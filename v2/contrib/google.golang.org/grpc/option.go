// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016 Datadog, Inc.

package grpc

import (
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
	"github.com/DataDog/dd-trace-go/v2/internal"
	"github.com/DataDog/dd-trace-go/v2/internal/globalconfig"
	"github.com/DataDog/dd-trace-go/v2/internal/log"
	"github.com/DataDog/dd-trace-go/v2/internal/namingschema"

	"google.golang.org/grpc/codes"
)

const (
	defaultClientServiceName = "grpc.client"
	defaultServerServiceName = "grpc.server"
)

// Option describes options for the gRPC integration.
type Option interface {
	apply(*config)
}

// OptionFn represents options applicable to StreamClientInterceptor, UnaryClientInterceptor, StreamServerInterceptor,
// UnaryServerInterceptor, NewClientStatsHandler and NewServerStatsHandler.
type OptionFn func(*config)

func (fn OptionFn) apply(cfg *config) {
	fn(cfg)
}

func (fn OptionFn) applyStream(cfg *config) {
	fn(cfg)
}

type config struct {
	serviceName         func() string
	spanName            string
	nonErrorCodes       map[codes.Code]bool
	traceStreamCalls    bool
	traceStreamMessages bool
	noDebugStack        bool
	untracedMethods     map[string]struct{}
	withMetadataTags    bool
	ignoredMetadata     map[string]struct{}
	withRequestTags     bool
	withErrorDetailTags bool
	spanOpts            []tracer.StartSpanOption
	tags                map[string]interface{}
}

func defaults(cfg *config) {
	cfg.traceStreamCalls = true
	cfg.traceStreamMessages = true
	cfg.nonErrorCodes = map[codes.Code]bool{codes.Canceled: true}
	// cfg.spanOpts = append(cfg.spanOpts, tracer.AnalyticsRate(globalconfig.AnalyticsRate()))
	if internal.BoolEnv("DD_TRACE_GRPC_ANALYTICS_ENABLED", false) {
		cfg.spanOpts = append(cfg.spanOpts, tracer.AnalyticsRate(1.0))
	}
	cfg.ignoredMetadata = map[string]struct{}{
		"x-datadog-trace-id":          {},
		"x-datadog-parent-id":         {},
		"x-datadog-sampling-priority": {},
	}
}

func clientDefaults(cfg *config) {
	sn := namingschema.ServiceNameOverrideV0(defaultClientServiceName, defaultClientServiceName)
	cfg.serviceName = func() string { return sn }
	cfg.spanName = namingschema.OpName(namingschema.GRPCClient)
	defaults(cfg)
}

func serverDefaults(cfg *config) {
	// We check for a configured service name, so we don't break users who are incorrectly creating their server
	// before the call `tracer.Start()`
	if globalconfig.ServiceName() != "" {
		sn := namingschema.ServiceName(defaultServerServiceName)
		cfg.serviceName = func() string { return sn }
	} else {
		log.Warn("No global service name was detected. GRPC Server may have been created before calling tracer.Start(). Will dynamically fetch service name for every span. " +
			"Note this may have a slight performance cost, it is always recommended to start the tracer before initializing any traced packages.\n")
		cfg.serviceName = func() string { return namingschema.ServiceName(defaultServerServiceName) }
	}
	cfg.spanName = namingschema.OpName(namingschema.GRPCServer)
	defaults(cfg)
}

// WithService sets the given service name for the intercepted client.
func WithService(name string) OptionFn {
	return func(cfg *config) {
		cfg.serviceName = func() string { return name }
	}
}

// WithStreamCalls enables or disables tracing of streaming calls. This option does not apply to the
// stats handler.
func WithStreamCalls(enabled bool) OptionFn {
	return func(cfg *config) {
		cfg.traceStreamCalls = enabled
	}
}

// WithStreamMessages enables or disables tracing of streaming messages. This option does not apply
// to the stats handler.
func WithStreamMessages(enabled bool) OptionFn {
	return func(cfg *config) {
		cfg.traceStreamMessages = enabled
	}
}

// NoDebugStack disables debug stacks for traces with errors. This is useful in situations
// where errors are frequent, and the overhead of calling debug.Stack may affect performance.
func NoDebugStack() OptionFn {
	return func(cfg *config) {
		cfg.noDebugStack = true
	}
}

// NonErrorCodes determines the list of codes that will not be considered errors in instrumentation.
// This call overrides the default handling of codes.Canceled as a non-error.
func NonErrorCodes(cs ...codes.Code) OptionFn {
	return func(cfg *config) {
		cfg.nonErrorCodes = make(map[codes.Code]bool, len(cs))
		for _, c := range cs {
			cfg.nonErrorCodes[c] = true
		}
	}
}

// WithAnalytics enables Trace Analytics for all started spans.
func WithAnalytics(on bool) OptionFn {
	return func(cfg *config) {
		if on {
			WithSpanOptions(tracer.AnalyticsRate(1.0))(cfg)
		}
	}
}

// WithAnalyticsRate sets the sampling rate for Trace Analytics events
// correlated to started spans.
func WithAnalyticsRate(rate float64) OptionFn {
	return func(cfg *config) {
		if rate >= 0.0 && rate <= 1.0 {
			WithSpanOptions(tracer.AnalyticsRate(rate))(cfg)
		}
	}
}

// WithUntracedMethods specifies full methods to be ignored by the server side and client
// side interceptors. When a request's full method is in ms, no spans will be created.
func WithUntracedMethods(ms ...string) OptionFn {
	ums := make(map[string]struct{}, len(ms))
	for _, e := range ms {
		ums[e] = struct{}{}
	}
	return func(cfg *config) {
		cfg.untracedMethods = ums
	}
}

// WithMetadataTags specifies whether gRPC metadata should be added to spans as tags.
func WithMetadataTags() OptionFn {
	return func(cfg *config) {
		cfg.withMetadataTags = true
	}
}

// WithIgnoredMetadata specifies keys to be ignored while tracing the metadata. Must be used
// in conjunction with WithMetadataTags.
func WithIgnoredMetadata(ms ...string) OptionFn {
	return func(cfg *config) {
		for _, e := range ms {
			cfg.ignoredMetadata[e] = struct{}{}
		}
	}
}

// WithRequestTags specifies whether gRPC requests should be added to spans as tags.
func WithRequestTags() OptionFn {
	return func(cfg *config) {
		cfg.withRequestTags = true
	}
}

// WithErrorDetailTags specifies whether gRPC responses details contain should be added to spans as tags.
func WithErrorDetailTags() OptionFn {
	return func(cfg *config) {
		cfg.withErrorDetailTags = true
	}
}

// WithCustomTag will attach the value to the span tagged by the key.
func WithCustomTag(key string, value interface{}) OptionFn {
	return func(cfg *config) {
		if cfg.tags == nil {
			cfg.tags = make(map[string]interface{})
		}
		cfg.tags[key] = value
	}
}

// WithSpanOptions defines a set of additional tracer.StartSpanOption to be added
// to spans started by the integration.
func WithSpanOptions(opts ...tracer.StartSpanOption) OptionFn {
	return func(cfg *config) {
		cfg.spanOpts = append(cfg.spanOpts, opts...)
	}
}