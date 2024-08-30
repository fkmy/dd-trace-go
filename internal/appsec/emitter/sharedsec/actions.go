// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022 Datadog, Inc.

package sharedsec

import (
	_ "embed" // Blank import
	"net/http"
	"os"
	"path"
	"strings"

	"gopkg.in/DataDog/dd-trace-go.v1/appsec/events"
	"gopkg.in/DataDog/dd-trace-go.v1/internal/appsec/dyngo"
	"gopkg.in/DataDog/dd-trace-go.v1/internal/log"
	"gopkg.in/DataDog/dd-trace-go.v1/internal/stacktrace"
	urlpkg "net/url"

	"github.com/mitchellh/mapstructure"
)

// blockedTemplateJSON is the default JSON template used to write responses for blocked requests
//
//go:embed blocked-template.json
var blockedTemplateJSON []byte

// blockedTemplateHTML is the default HTML template used to write responses for blocked requests
//
//go:embed blocked-template.html
var blockedTemplateHTML []byte

const (
	envBlockedTemplateHTML = "DD_APPSEC_HTTP_BLOCKED_TEMPLATE_HTML"
	envBlockedTemplateJSON = "DD_APPSEC_HTTP_BLOCKED_TEMPLATE_JSON"
)

func init() {
	for env, template := range map[string]*[]byte{envBlockedTemplateJSON: &blockedTemplateJSON, envBlockedTemplateHTML: &blockedTemplateHTML} {
		if path, ok := os.LookupEnv(env); ok {
			if t, err := os.ReadFile(path); err != nil {
				log.Error("Could not read template at %s: %v", path, err)
			} else {
				*template = t
			}
		}

	}
}

type (
	// Action is a generic interface that represents any WAF action
	Action interface {
		Blocking() bool
		EmitData(op dyngo.Operation)
	}

	// HTTPAction are actions that interact with an HTTP request flow (block, redirect...)
	HTTPAction struct {
		http.Handler

		StatusCode       int
		RedirectLocation string
		// BlockingTemplate is a function that returns the headers to be added and body to be written to the response
		BlockingTemplate func(headers map[string][]string) (map[string][]string, []byte)
	}
	// GRPCAction are actions that interact with a GRPC request flow
	GRPCAction struct {
		GRPCWrapper
	}
	// StackTraceAction are actions that generate a stacktrace
	StackTraceAction struct {
		Event stacktrace.Event
	}

	// GRPCWrapper is an opaque prototype abstraction for a gRPC handler (to avoid importing grpc)
	// that returns a status code and an error
	// TODO: rely on strongly typed actions (with the actual grpc types) by introducing WAF constructors
	//     living in the contrib packages, along with their dependencies - something like `appsec.RegisterWAFConstructor(newGRPCWAF)`
	//    Such constructors would receive the full appsec config and rules, so that they would be able to build
	//    specific blocking actions.
	GRPCWrapper func() (uint32, error)

	// blockActionParams are the dynamic parameters to be provided to a "block_request"
	// action type upon invocation
	blockActionParams struct {
		// GRPCStatusCode is the gRPC status code to be returned. Since 0 is the OK status, the value is nullable to
		// be able to distinguish between unset and defaulting to Abort (10), or set to OK (0).
		GRPCStatusCode *int   `mapstructure:"grpc_status_code,omitempty"`
		StatusCode     int    `mapstructure:"status_code"`
		Type           string `mapstructure:"type,omitempty"`
	}
	// redirectActionParams are the dynamic parameters to be provided to a "redirect_request"
	// action type upon invocation
	redirectActionParams struct {
		Location   string `mapstructure:"location,omitempty"`
		StatusCode int    `mapstructure:"status_code"`
	}
)

func (a *HTTPAction) Blocking() bool              { return true }
func (a *HTTPAction) EmitData(op dyngo.Operation) { dyngo.EmitData(op, a) }

func (a *GRPCAction) Blocking() bool              { return true }
func (a *GRPCAction) EmitData(op dyngo.Operation) { dyngo.EmitData(op, a) }

func (a *StackTraceAction) Blocking() bool              { return false }
func (a *StackTraceAction) EmitData(op dyngo.Operation) { dyngo.EmitData(op, a) }

// NewStackTraceAction creates an action for the "stacktrace" action type
func NewStackTraceAction(params map[string]any) Action {
	id, ok := params["stack_id"]
	if !ok {
		log.Debug("appsec: could not read stack_id parameter for generate_stack action")
		return nil
	}

	strID, ok := id.(string)
	if !ok {
		log.Debug("appsec: could not cast stacktrace ID to string")
		return nil
	}

	event := stacktrace.NewEvent(stacktrace.ExploitEvent, stacktrace.WithID(strID))

	return &StackTraceAction{Event: *event}
}

// NewBlockAction creates an action for the "block_request" action type
func NewBlockAction(params map[string]any) []Action {
	p, err := blockParamsFromMap(params)
	if err != nil {
		log.Debug("appsec: couldn't decode redirect action parameters")
		return nil
	}
	return []Action{
		newHTTPBlockRequestAction(p.StatusCode, p.Type),
		newGRPCBlockRequestAction(*p.GRPCStatusCode),
	}
}

// NewRedirectAction creates an action for the "redirect_request" action type
func NewRedirectAction(params map[string]any) *HTTPAction {
	p, err := redirectParamsFromMap(params)
	if err != nil {
		log.Debug("appsec: couldn't decode redirect action parameters")
		return nil
	}
	return newRedirectRequestAction(p.StatusCode, p.Location)
}

func newHTTPBlockRequestAction(status int, template string) *HTTPAction {
	return &HTTPAction{
		Handler:          newBlockHandler(status, template),
		StatusCode:       status,
		BlockingTemplate: newManualBlockHandler(template),
	}
}

func newGRPCBlockRequestAction(status int) *GRPCAction {
	return &GRPCAction{GRPCWrapper: newGRPCBlockHandler(status)}
}

func newRedirectRequestAction(status int, loc string) *HTTPAction {
	// Default to 303 if status is out of redirection codes bounds
	if status < 300 || status >= 400 {
		status = 303
	}

	// If location is not set we fall back on a default block action
	if loc == "" {
		return &HTTPAction{
			Handler:          newBlockHandler(403, string(blockedTemplateJSON)),
			StatusCode:       403,
			BlockingTemplate: newManualBlockHandler("json"),
		}
	}
	return &HTTPAction{
		Handler:          http.RedirectHandler(loc, status),
		StatusCode:       status,
		RedirectLocation: loc,
	}
}

// newBlockHandler creates, initializes and returns a new BlockRequestAction
func newBlockHandler(status int, template string) http.Handler {
	htmlHandler := newBlockRequestHandler(status, "text/html", blockedTemplateHTML)
	jsonHandler := newBlockRequestHandler(status, "application/json", blockedTemplateJSON)
	switch template {
	case "json":
		return jsonHandler
	case "html":
		return htmlHandler
	default:
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := findCorrectTemplate(jsonHandler, htmlHandler, r.Header.Get("Accept"))
			h.(http.Handler).ServeHTTP(w, r)
		})
	}
}

func newManualBlockHandler(template string) func(headers map[string][]string) (map[string][]string, []byte) {
	htmlHandler := newManualBlockDataHandler("text/html", blockedTemplateHTML)
	jsonHandler := newManualBlockDataHandler("application/json", blockedTemplateJSON)
	switch template {
	case "json":
		return jsonHandler
	case "html":
		return htmlHandler
	default:
		return func(headers map[string][]string) (map[string][]string, []byte) {
			acceptHeader := ""
			if hdr, ok := headers["accept"]; ok && len(hdr) > 0 {
				acceptHeader = hdr[0]
			}
			h := findCorrectTemplate(jsonHandler, htmlHandler, acceptHeader)
			return h.(func(headers map[string][]string) (map[string][]string, []byte))(headers)
		}
	}
}

func findCorrectTemplate(jsonHandler interface{}, htmlHandler interface{}, acceptHeader string) interface{} {
	h := jsonHandler
	hdr := acceptHeader
	htmlIdx := strings.Index(hdr, "text/html")
	jsonIdx := strings.Index(hdr, "application/json")
	// Switch to html handler if text/html comes before application/json in the Accept header
	if htmlIdx != -1 && (jsonIdx == -1 || htmlIdx < jsonIdx) {
		h = htmlHandler
	}
	return h
}

func newManualBlockDataHandler(ct string, template []byte) func(headers map[string][]string) (map[string][]string, []byte) {
	return func(headers map[string][]string) (map[string][]string, []byte) {
		return map[string][]string{"Content-Type": {ct}}, template
	}
}

func newBlockRequestHandler(status int, ct string, payload []byte) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", ct)
		w.WriteHeader(status)
		w.Write(payload)
	})
}

func newGRPCBlockHandler(status int) GRPCWrapper {
	return func() (uint32, error) {
		return uint32(status), &events.BlockingSecurityEvent{}
	}
}

func blockParamsFromMap(params map[string]any) (blockActionParams, error) {
	grpcCode := 10
	p := blockActionParams{
		Type:           "auto",
		StatusCode:     403,
		GRPCStatusCode: &grpcCode,
	}

	if err := mapstructure.WeakDecode(params, &p); err != nil {
		return p, err
	}

	if p.GRPCStatusCode == nil {
		p.GRPCStatusCode = &grpcCode
	}
	return p, nil

}

func redirectParamsFromMap(params map[string]any) (redirectActionParams, error) {
	var p redirectActionParams
	err := mapstructure.WeakDecode(params, &p)
	return p, err
}

// HandleRedirectLocationString returns the headers and body to be written to the response when a redirect is needed
// Vendored from net/http/server.go
func HandleRedirectLocationString(oldpath string, url string, statusCode int, method string, h map[string][]string) (map[string][]string, []byte) {
	if u, err := urlpkg.Parse(url); err == nil {
		// If url was relative, make its path absolute by
		// combining with request path.
		// The client would probably do this for us,
		// but doing it ourselves is more reliable.
		// See RFC 7231, section 7.1.2
		if u.Scheme == "" && u.Host == "" {
			if oldpath == "" { // should not happen, but avoid a crash if it does
				oldpath = "/"
			}

			// no leading http://server
			if url == "" || url[0] != '/' {
				// make relative path absolute
				olddir, _ := path.Split(oldpath)
				url = olddir + url
			}

			var query string
			if i := strings.Index(url, "?"); i != -1 {
				url, query = url[:i], url[i:]
			}

			// clean up but preserve trailing slash
			trailing := strings.HasSuffix(url, "/")
			url = path.Clean(url)
			if trailing && !strings.HasSuffix(url, "/") {
				url += "/"
			}
			url += query
		}
	}

	// RFC 7231 notes that a short HTML body is usually included in
	// the response because older user agents may not understand 301/307.
	// Do it only if the request didn't already have a Content-Type header.
	_, hadCT := h["content-type"]
	newHeaders := make(map[string][]string, 2)

	newHeaders["location"] = []string{url}
	if !hadCT && (method == "GET" || method == "HEAD") {
		newHeaders["content-length"] = []string{"text/html; charset=utf-8"}
	}

	// Shouldn't send the body for POST or HEAD; that leaves GET.
	var body []byte
	if !hadCT && method == "GET" {
		body = []byte("<a href=\"" + htmlEscape(url) + "\">" + http.StatusText(statusCode) + "</a>.\n")
	}

	return newHeaders, body
}

// Vendored from net/http/server.go
var htmlReplacer = strings.NewReplacer(
	"&", "&amp;",
	"<", "&lt;",
	">", "&gt;",
	// "&#34;" is shorter than "&quot;".
	`"`, "&#34;",
	// "&#39;" is shorter than "&apos;" and apos was not in HTML until HTML5.
	"'", "&#39;",
)

// htmlEscape escapes special characters like "<" to become "&lt;".
func htmlEscape(s string) string {
	return htmlReplacer.Replace(s)
}
