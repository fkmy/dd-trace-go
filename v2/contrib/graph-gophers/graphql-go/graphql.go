// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016 Datadog, Inc.

// Package graphql provides functions to trace the graph-gophers/graphql-go package (https://github.com/graph-gophers/graphql-go).
//
// We use the tracing mechanism available in the
// https://godoc.org/github.com/graph-gophers/graphql-go/trace subpackage.
// Create a new Tracer with `NewTracer` and pass it as an additional option to
// `MustParseSchema`.
package graphql // import "github.com/DataDog/dd-trace-go/v2/contrib/graph-gophers/graphql-go"

import (
	"context"
	"fmt"
	"math"

	"github.com/DataDog/dd-trace-go/v2/ddtrace"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/ext"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
	"github.com/DataDog/dd-trace-go/v2/internal/log"
	"github.com/DataDog/dd-trace-go/v2/internal/telemetry"

	"github.com/graph-gophers/graphql-go/errors"
	"github.com/graph-gophers/graphql-go/introspection"
	"github.com/graph-gophers/graphql-go/trace"
)

const componentName = "graph-gophers/graphql-go"

func init() {
	telemetry.LoadIntegration(componentName)
	tracer.MarkIntegrationImported("github.com/graph-gophers/graphql-go")
}

const (
	tagGraphqlField         = "graphql.field"
	tagGraphqlQuery         = "graphql.query"
	tagGraphqlType          = "graphql.type"
	tagGraphqlOperationName = "graphql.operation.name"
)

// A Tracer implements the graphql-go/trace.Tracer interface by sending traces
// to the Datadog tracer.
type Tracer struct {
	cfg *config
}

var _ trace.Tracer = (*Tracer)(nil)

// TraceQuery traces a GraphQL query.
func (t *Tracer) TraceQuery(ctx context.Context, queryString string, operationName string, _ map[string]interface{}, _ map[string]*introspection.Type) (context.Context, trace.TraceQueryFinishFunc) {
	opts := []ddtrace.StartSpanOption{
		tracer.ServiceName(t.cfg.serviceName),
		tracer.Tag(tagGraphqlQuery, queryString),
		tracer.Tag(tagGraphqlOperationName, operationName),
		tracer.Tag(ext.Component, componentName),
		tracer.Measured(),
	}
	if !math.IsNaN(t.cfg.analyticsRate) {
		opts = append(opts, tracer.Tag(ext.EventSampleRate, t.cfg.analyticsRate))
	}
	span, ctx := tracer.StartSpanFromContext(ctx, t.cfg.querySpanName, opts...)

	return ctx, func(errs []*errors.QueryError) {
		var err error
		switch n := len(errs); n {
		case 0:
			// err = nil
		case 1:
			err = errs[0]
		default:
			err = fmt.Errorf("%s (and %d more errors)", errs[0], n-1)
		}
		span.Finish(tracer.WithError(err))
	}
}

// TraceField traces a GraphQL field access.
func (t *Tracer) TraceField(ctx context.Context, _ string, typeName string, fieldName string, trivial bool, _ map[string]interface{}) (context.Context, trace.TraceFieldFinishFunc) {
	if t.cfg.omitTrivial && trivial {
		return ctx, func(queryError *errors.QueryError) {}
	}
	opts := []ddtrace.StartSpanOption{
		tracer.ServiceName(t.cfg.serviceName),
		tracer.Tag(tagGraphqlField, fieldName),
		tracer.Tag(tagGraphqlType, typeName),
		tracer.Tag(ext.Component, componentName),
		tracer.Measured(),
	}
	if !math.IsNaN(t.cfg.analyticsRate) {
		opts = append(opts, tracer.Tag(ext.EventSampleRate, t.cfg.analyticsRate))
	}
	span, ctx := tracer.StartSpanFromContext(ctx, "graphql.field", opts...)

	return ctx, func(err *errors.QueryError) {
		// must explicitly check for nil, see issue golang/go#22729
		if err != nil {
			span.Finish(tracer.WithError(err))
		} else {
			span.Finish()
		}
	}
}

// NewTracer creates a new Tracer.
func NewTracer(opts ...Option) trace.Tracer {
	cfg := new(config)
	defaults(cfg)
	for _, opt := range opts {
		opt(cfg)
	}
	log.Debug("contrib/graph-gophers/graphql-go: Configuring Graphql Tracer: %#v", cfg)
	return &Tracer{
		cfg: cfg,
	}
}