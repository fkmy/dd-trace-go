// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016 Datadog, Inc.

package http

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/DataDog/dd-trace-go/v2/appsec/events"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/ext"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
	"github.com/DataDog/dd-trace-go/v2/instrumentation/testutils"
)

func TestWrapRoundTripperAllowNilTransport(t *testing.T) {
	assert := assert.New(t)

	httpClient := &http.Client{}
	httpClient.Transport = WrapRoundTripper(httpClient.Transport)

	wrapped, ok := httpClient.Transport.(*roundTripper)
	assert.True(ok)

	assert.Equal(http.DefaultTransport, wrapped.base)
}

func TestRoundTripper(t *testing.T) {
	mt := mocktracer.Start()
	defer mt.Stop()

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		spanctx, err := tracer.Extract(tracer.HTTPHeadersCarrier(r.Header))
		assert.NoError(t, err)

		span := tracer.StartSpan("test",
			tracer.ChildOf(spanctx))
		defer span.Finish()

		w.Write([]byte("Hello World"))
	}))
	defer s.Close()

	rt := WrapRoundTripper(http.DefaultTransport,
		WithBefore(func(req *http.Request, span *tracer.Span) {
			span.SetTag("CalledBefore", true)
		}),
		WithAfter(func(res *http.Response, span *tracer.Span) {
			span.SetTag("CalledAfter", true)
		}))

	client := &http.Client{
		Transport: rt,
	}

	resp, err := client.Get(s.URL + "/hello/world")
	assert.Nil(t, err)
	defer resp.Body.Close()

	spans := mt.FinishedSpans()
	assert.Len(t, spans, 2)
	assert.Equal(t, spans[0].TraceID(), spans[1].TraceID())

	s0 := spans[0]
	assert.Equal(t, "test", s0.OperationName())
	assert.Equal(t, "test", s0.Tag(ext.ResourceName))

	s1 := spans[1]
	assert.Equal(t, "http.request", s1.OperationName())
	assert.Equal(t, "http.request", s1.Tag(ext.ResourceName))
	assert.Equal(t, "200", s1.Tag(ext.HTTPCode))
	assert.Equal(t, "GET", s1.Tag(ext.HTTPMethod))
	assert.Equal(t, s.URL+"/hello/world", s1.Tag(ext.HTTPURL))
	assert.Equal(t, "true", s1.Tag("CalledBefore"))
	assert.Equal(t, "true", s1.Tag("CalledAfter"))
	assert.Equal(t, ext.SpanKindClient, s1.Tag(ext.SpanKind))
	assert.Equal(t, "net/http", s1.Tag(ext.Component))
	assert.Equal(t, "127.0.0.1", s1.Tag(ext.NetworkDestinationName))

	wantPort, err := strconv.Atoi(strings.TrimPrefix(s.URL, "http://127.0.0.1:"))
	require.NoError(t, err)
	require.NotEmpty(t, wantPort)
	assert.Equal(t, float64(wantPort), s1.Tag(ext.NetworkDestinationPort))
}

func TestRoundTripperServerError(t *testing.T) {
	mt := mocktracer.Start()
	defer mt.Stop()

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		spanctx, err := tracer.Extract(tracer.HTTPHeadersCarrier(r.Header))
		assert.NoError(t, err)

		span := tracer.StartSpan("test",
			tracer.ChildOf(spanctx))
		defer span.Finish()

		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Error"))
	}))
	defer s.Close()

	rt := WrapRoundTripper(http.DefaultTransport,
		WithBefore(func(req *http.Request, span *tracer.Span) {
			span.SetTag("CalledBefore", true)
		}),
		WithAfter(func(res *http.Response, span *tracer.Span) {
			span.SetTag("CalledAfter", true)
		}))

	client := &http.Client{
		Transport: rt,
	}

	resp, err := client.Get(s.URL + "/hello/world")
	assert.Nil(t, err)
	defer resp.Body.Close()

	spans := mt.FinishedSpans()
	assert.Len(t, spans, 2)
	assert.Equal(t, spans[0].TraceID(), spans[1].TraceID())

	s0 := spans[0]
	assert.Equal(t, "test", s0.OperationName())
	assert.Equal(t, "test", s0.Tag(ext.ResourceName))

	s1 := spans[1]
	assert.Equal(t, "http.request", s1.OperationName())
	assert.Equal(t, "http.request", s1.Tag(ext.ResourceName))
	assert.Equal(t, "500", s1.Tag(ext.HTTPCode))
	assert.Equal(t, "GET", s1.Tag(ext.HTTPMethod))
	assert.Equal(t, s.URL+"/hello/world", s1.Tag(ext.HTTPURL))
	assert.Equal(t, "500: Internal Server Error", s1.Tag(ext.ErrorMsg))
	assert.Equal(t, "true", s1.Tag("CalledBefore"))
	assert.Equal(t, "true", s1.Tag("CalledAfter"))
	assert.Equal(t, ext.SpanKindClient, s1.Tag(ext.SpanKind))
	assert.Equal(t, "net/http", s1.Tag(ext.Component))
}

func TestRoundTripperNetworkError(t *testing.T) {
	mt := mocktracer.Start()
	defer mt.Stop()

	done := make(chan struct{})
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := tracer.Extract(tracer.HTTPHeadersCarrier(r.Header))
		assert.NoError(t, err)
		<-done
	}))
	defer s.Close()
	defer close(done)

	rt := WrapRoundTripper(http.DefaultTransport,
		WithBefore(func(req *http.Request, span *tracer.Span) {
			span.SetTag("CalledBefore", true)
		}),
		WithAfter(func(res *http.Response, span *tracer.Span) {
			span.SetTag("CalledAfter", true)
		}))

	client := &http.Client{
		Transport: rt,
		Timeout:   1 * time.Millisecond,
	}

	_, err := client.Get(s.URL + "/hello/world") //nolint:bodyclose
	assert.NotNil(t, err)

	spans := mt.FinishedSpans()
	assert.Len(t, spans, 1)

	s0 := spans[0]
	assert.Equal(t, "http.request", s0.OperationName())
	assert.Equal(t, "http.request", s0.Tag(ext.ResourceName))
	assert.Equal(t, nil, s0.Tag(ext.HTTPCode))
	assert.Equal(t, "GET", s0.Tag(ext.HTTPMethod))
	assert.Equal(t, s.URL+"/hello/world", s0.Tag(ext.HTTPURL))
	assert.NotNil(t, s0.Tag(ext.ErrorMsg))
	assert.Equal(t, "true", s0.Tag("CalledBefore"))
	assert.Equal(t, "true", s0.Tag("CalledAfter"))
	assert.Equal(t, ext.SpanKindClient, s0.Tag(ext.SpanKind))
	assert.Equal(t, "net/http", s0.Tag(ext.Component))
}

func TestRoundTripperNetworkErrorWithErrorCheck(t *testing.T) {
	failedRequest := func(t *testing.T, mt mocktracer.Tracer, forwardErr bool, _ ...Option) *mocktracer.Span {
		done := make(chan struct{})
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := tracer.Extract(tracer.HTTPHeadersCarrier(r.Header))
			assert.NoError(t, err)
			<-done
		}))
		defer s.Close()
		defer close(done)

		rt := WrapRoundTripper(http.DefaultTransport,
			WithErrorCheck(func(err error) bool {
				return forwardErr
			}))

		client := &http.Client{
			Transport: rt,
			Timeout:   1 * time.Millisecond,
		}

		_, err := client.Get(s.URL + "/hello/world") //nolint:bodyclose
		assert.NotNil(t, err)

		spans := mt.FinishedSpans()
		assert.Len(t, spans, 1)

		s0 := spans[0]
		return s0
	}

	t.Run("error skipped", func(t *testing.T) {
		mt := mocktracer.Start()
		defer mt.Stop()

		span := failedRequest(t, mt, false)
		assert.Nil(t, span.Tag(ext.ErrorMsg))
	})

	t.Run("error forwarded", func(t *testing.T) {
		mt := mocktracer.Start()
		defer mt.Stop()

		span := failedRequest(t, mt, true)
		assert.NotNil(t, span.Tag(ext.ErrorMsg))
	})
}

func TestRoundTripperCredentials(t *testing.T) {
	mt := mocktracer.Start()
	defer mt.Stop()

	var auth string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if enc, ok := r.Header["Authorization"]; ok {
			encoded := strings.TrimPrefix(enc[0], "Basic ")
			if b64, err := base64.StdEncoding.DecodeString(encoded); err == nil {
				auth = string(b64)
			}
		}

	}))
	defer s.Close()

	rt := WrapRoundTripper(http.DefaultTransport,
		WithBefore(func(req *http.Request, span *tracer.Span) {
			span.SetTag("CalledBefore", true)
		}),
		WithAfter(func(res *http.Response, span *tracer.Span) {
			span.SetTag("CalledAfter", true)
		}))

	client := &http.Client{
		Transport: rt,
	}

	u, err := url.Parse(s.URL)
	require.NoError(t, err)
	u.User = url.UserPassword("myuser", "mypassword")

	resp, err := client.Get(u.String() + "/hello/world")
	assert.Nil(t, err)
	defer resp.Body.Close()

	spans := mt.FinishedSpans()
	require.Len(t, spans, 1)

	s1 := spans[0]

	assert.Equal(t, s.URL+"/hello/world", s1.Tag(ext.HTTPURL))
	assert.NotContains(t, s1.Tag(ext.HTTPURL), "mypassword")
	assert.NotContains(t, s1.Tag(ext.HTTPURL), "myuser")
	// Make sure we haven't modified the outgoing request, and the server still
	// receives the auth request.
	assert.Equal(t, auth, "myuser:mypassword")
}

func TestWrapClient(t *testing.T) {
	c := WrapClient(http.DefaultClient)
	assert.Equal(t, c, http.DefaultClient)
	_, ok := c.Transport.(*roundTripper)
	assert.True(t, ok)
}

func TestRoundTripperAnalyticsSettings(t *testing.T) {
	assertRate := func(t *testing.T, mt mocktracer.Tracer, rate interface{}, opts ...RoundTripperOption) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		rt := WrapRoundTripper(http.DefaultTransport, opts...)

		client := &http.Client{Transport: rt}
		resp, err := client.Get(srv.URL + "/hello/world")
		assert.Nil(t, err)
		defer resp.Body.Close()
		spans := mt.FinishedSpans()
		assert.Len(t, spans, 1)
		s := spans[0]
		assert.Equal(t, rate, s.Tag(ext.EventSampleRate))
	}

	t.Run("defaults", func(t *testing.T) {
		mt := mocktracer.Start()
		defer mt.Stop()

		assertRate(t, mt, nil)
	})

	t.Run("enabled", func(t *testing.T) {
		mt := mocktracer.Start()
		defer mt.Stop()

		assertRate(t, mt, 1.0, WithAnalytics(true))
	})

	t.Run("disabled", func(t *testing.T) {
		mt := mocktracer.Start()
		defer mt.Stop()

		assertRate(t, mt, nil, WithAnalytics(false))
	})

	t.Run("override", func(t *testing.T) {
		testutils.SetGlobalAnalyticsRate(t, 0.4)

		mt := mocktracer.Start()
		defer mt.Stop()

		assertRate(t, mt, 0.23, WithAnalyticsRate(0.23))
	})
}

// TestRoundTripperCopy is a regression test ensuring that RoundTrip
// does not modify the request per the RoundTripper contract. See:
// https://cs.opensource.google/go/go/+/refs/tags/go1.18.1:src/net/http/client.go;l=129-133
func TestRoundTripperCopy(t *testing.T) {
	mt := mocktracer.Start()
	defer mt.Stop()

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := tracer.Extract(tracer.HTTPHeadersCarrier(r.Header))
		assert.NoError(t, err)
		w.Write([]byte("Hello World"))
	}))
	defer s.Close()

	initialReq, err := http.NewRequest("GET", s.URL+"/hello/world", nil)
	assert.NoError(t, err)
	req, err := http.NewRequest("GET", s.URL+"/hello/world", nil)
	assert.NoError(t, err)
	rt := WrapRoundTripper(http.DefaultTransport).(*roundTripper)
	resp, err := rt.RoundTrip(req)
	assert.NoError(t, err)
	defer resp.Body.Close()
	assert.Len(t, req.Header, 0)
	assert.Equal(t, initialReq, req)
}

func TestRoundTripperIgnoreRequest(t *testing.T) {
	mt := mocktracer.Start()
	defer mt.Stop()

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello World"))
	}))
	defer s.Close()

	rt := WrapRoundTripper(http.DefaultTransport, WithIgnoreRequest(
		func(req *http.Request) bool {
			return req.URL.Path == "/ignore"
		},
	)).(*roundTripper)

	ignoreReq, err := http.NewRequest("GET", s.URL+"/ignore", nil)
	assert.NoError(t, err)
	resp1, err := rt.RoundTrip(ignoreReq)
	assert.NoError(t, err)
	defer resp1.Body.Close()

	req, err := http.NewRequest("GET", s.URL+"/hello", nil)
	assert.NoError(t, err)
	resp2, err := rt.RoundTrip(req)
	assert.NoError(t, err)
	defer resp2.Body.Close()

	spans := mt.FinishedSpans()
	assert.Len(t, spans, 1)
}

func TestRoundTripperURLWithoutPort(t *testing.T) {
	mt := mocktracer.Start()
	defer mt.Stop()

	client := &http.Client{
		Transport: WrapRoundTripper(http.DefaultTransport),
		Timeout:   1 * time.Millisecond,
	}
	_, err := client.Get("http://localhost/hello/world") //nolint:bodyclose
	require.Error(t, err)

	spans := mt.FinishedSpans()
	require.Len(t, spans, 1)

	s0 := spans[0]
	assert.Equal(t, "http.request", s0.OperationName())
	assert.Equal(t, "http.request", s0.Tag(ext.ResourceName))
	assert.Equal(t, nil, s0.Tag(ext.HTTPCode))
	assert.Equal(t, "GET", s0.Tag(ext.HTTPMethod))
	assert.Equal(t, "http://localhost/hello/world", s0.Tag(ext.HTTPURL))
	assert.NotNil(t, s0.Tag(ext.ErrorMsg))
	assert.Equal(t, ext.SpanKindClient, s0.Tag(ext.SpanKind))
	assert.Equal(t, "net/http", s0.Tag(ext.Component))
	assert.Equal(t, "localhost", s0.Tag(ext.NetworkDestinationName))
	assert.NotContains(t, s0.Tags(), ext.NetworkDestinationPort)
}

func TestServiceName(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello World"))
	}))
	defer s.Close()

	t.Run("option", func(t *testing.T) {
		mt := mocktracer.Start()
		defer mt.Stop()
		serviceName := "testServer"
		rt := WrapRoundTripper(http.DefaultTransport, WithService(serviceName))
		client := &http.Client{
			Transport: rt,
		}
		resp, err := client.Get(s.URL + "/hello/world")
		assert.Nil(t, err)
		defer resp.Body.Close()
		spans := mt.FinishedSpans()
		assert.Len(t, spans, 1)
		assert.Equal(t, serviceName, spans[0].Tag(ext.ServiceName))
	})

	t.Run("override", func(t *testing.T) {
		mt := mocktracer.Start()
		defer mt.Stop()
		serviceName := "testServer"
		rt := WrapRoundTripper(http.DefaultTransport,
			WithService("wrongServiceName"),
			WithBefore(func(_ *http.Request, span *tracer.Span) {
				span.SetTag(ext.ServiceName, serviceName)
			}),
		)
		client := &http.Client{
			Transport: rt,
		}
		resp, err := client.Get(s.URL + "/hello/world")
		assert.Nil(t, err)
		defer resp.Body.Close()
		spans := mt.FinishedSpans()
		assert.Len(t, spans, 1)
		assert.Equal(t, serviceName, spans[0].Tag(ext.ServiceName))
	})
}

func TestResourceNamer(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello World"))
	}))
	defer s.Close()

	t.Run("default", func(t *testing.T) {
		mt := mocktracer.Start()
		defer mt.Stop()
		rt := WrapRoundTripper(http.DefaultTransport)
		client := &http.Client{
			Transport: rt,
		}
		resp, err := client.Get(s.URL + "/hello/world")
		assert.Nil(t, err)
		defer resp.Body.Close()
		spans := mt.FinishedSpans()
		assert.Len(t, spans, 1)
		assert.Equal(t, "http.request", spans[0].Tag(ext.ResourceName))
	})

	t.Run("custom", func(t *testing.T) {
		mt := mocktracer.Start()
		defer mt.Stop()
		customNamer := func(req *http.Request) string {
			return fmt.Sprintf("%s %s", req.Method, req.URL.Path)
		}
		rt := WrapRoundTripper(http.DefaultTransport, WithResourceNamer(customNamer))
		client := &http.Client{
			Transport: rt,
		}
		resp, err := client.Get(s.URL + "/hello/world")
		assert.Nil(t, err)
		defer resp.Body.Close()
		spans := mt.FinishedSpans()
		assert.Len(t, spans, 1)
		assert.Equal(t, "GET /hello/world", spans[0].Tag(ext.ResourceName))
	})
}

func TestSpanOptions(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("")) }))
	defer s.Close()

	tagKey := "foo"
	tagValue := "bar"
	mt := mocktracer.Start()
	defer mt.Stop()
	rt := WrapRoundTripper(http.DefaultTransport, WithSpanOptions(tracer.Tag(tagKey, tagValue)))
	client := &http.Client{Transport: rt}

	resp, err := client.Get(s.URL)
	assert.Nil(t, err)
	defer resp.Body.Close()

	spans := mt.FinishedSpans()
	assert.Len(t, spans, 1)
	assert.Equal(t, tagValue, spans[0].Tag(tagKey))
}

func TestRoundTripperPropagation(t *testing.T) {
	mt := mocktracer.Start()
	defer mt.Stop()

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		spanctx, err := tracer.Extract(tracer.HTTPHeadersCarrier(r.Header))
		assert.ErrorIs(t, err, tracer.ErrSpanContextNotFound, "should not find headers injected in output")

		assert.Empty(t, r.Header.Get(tracer.DefaultTraceIDHeader), "should not find trace_id in output header")
		assert.Empty(t, r.Header.Get(tracer.DefaultParentIDHeader), "should not find parent_id in output header")

		span := tracer.StartSpan("test",
			tracer.ChildOf(spanctx))
		defer span.Finish()

		w.Write([]byte("Hello World"))
	}))
	defer s.Close()

	rt := WrapRoundTripper(http.DefaultTransport,
		WithPropagation(false))
	client := &http.Client{
		Transport: rt,
	}

	resp, err := client.Get(s.URL + "/hello/world")
	assert.Nil(t, err)
	defer resp.Body.Close()
}

type emptyRoundTripper struct{}

func (rt *emptyRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	recorder := httptest.NewRecorder()
	recorder.WriteHeader(200)
	return recorder.Result(), nil
}

func TestAppsec(t *testing.T) {
	t.Setenv("DD_APPSEC_RULES", "../../../internal/appsec/testdata/rasp.json")

	client := WrapRoundTripper(&emptyRoundTripper{})

	for _, enabled := range []bool{true, false} {

		t.Run(strconv.FormatBool(enabled), func(t *testing.T) {
			t.Setenv("DD_APPSEC_RASP_ENABLED", strconv.FormatBool(enabled))

			mt := mocktracer.Start()
			defer mt.Stop()

			testutils.StartAppSec(t)
			if !instr.AppSecEnabled() {
				t.Skip("appsec not enabled")
			}

			w := httptest.NewRecorder()
			r, err := http.NewRequest("GET", "?value=169.254.169.254", nil)
			require.NoError(t, err)

			TraceAndServe(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				req, err := http.NewRequest("GET", "http://169.254.169.254", nil)
				require.NoError(t, err)

				resp, err := client.RoundTrip(req.WithContext(r.Context()))

				if enabled {
					require.True(t, events.IsSecurityError(err))
				} else {
					require.NoError(t, err)
				}

				if resp != nil {
					defer resp.Body.Close()
				}
			}), w, r, &ServeConfig{
				Service:  "service",
				Resource: "resource",
			})

			spans := mt.FinishedSpans()
			require.Len(t, spans, 2) // service entry serviceSpan & http request serviceSpan
			serviceSpan := spans[1]

			if !enabled {
				require.NotContains(t, serviceSpan.Tags(), "_dd.appsec.json")
				require.NotContains(t, serviceSpan.Tags(), "_dd.stack")
				return
			}

			require.Contains(t, serviceSpan.Tags(), "_dd.appsec.json")
			appsecJSON := serviceSpan.Tag("_dd.appsec.json")
			require.Contains(t, appsecJSON, "server.io.net.url")

			require.Contains(t, serviceSpan.Tags(), "_dd.stack")
			require.NotContains(t, serviceSpan.Tags(), "error.message")

			// This is a nested event so it should contain the child span id in the service entry span
			// TODO(eliott.bouhana): uncomment this once we have the child span id in the service entry span
			// require.Contains(t, appsecJSON, `"span_id":`+strconv.FormatUint(requestSpan.SpanID(), 10))
		})
	}
}
