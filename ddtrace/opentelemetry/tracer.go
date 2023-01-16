package opentelemetry

import (
	"context"
	oteltrace "go.opentelemetry.io/otel/trace"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/tracer"
)

var _ oteltrace.Tracer = (*oteltracer)(nil)

type oteltracer struct {
	name     string
	cfg      oteltrace.TracerConfig
	provider *tracerProvider
	ddtrace.Tracer
}

//todo:can we use config.SpanKind in some way
func (t *oteltracer) Start(ctx context.Context, spanName string, opts ...oteltrace.SpanStartOption) (context.Context, oteltrace.Span) {
	var ssConfig = oteltrace.NewSpanStartConfig(opts...)
	var optsLocal []ddtrace.StartSpanOption
	if !ssConfig.NewRoot() {
		if s, ok := tracer.SpanFromContext(ctx); ok {
			optsLocal = append(optsLocal, tracer.ChildOf(s.Context()))
		}
	}
	if t := ssConfig.Timestamp(); !t.IsZero() {
		optsLocal = append(optsLocal, tracer.StartTime(ssConfig.Timestamp()))
	}
	for _, attr := range ssConfig.Attributes() {
		optsLocal = append(optsLocal, tracer.Tag(string(attr.Key), attr.Value.AsInterface()))
	}
	s := t.Tracer.StartSpan(spanName, optsLocal...)
	return tracer.ContextWithSpan(ctx, s), oteltrace.Span(&span{
		Span:       s,
		oteltracer: t,
	})
}