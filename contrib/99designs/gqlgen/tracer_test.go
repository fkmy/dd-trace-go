// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022 Datadog, Inc.

package gqlgen

import (
	"testing"

	"github.com/99designs/gqlgen/client"
	"github.com/99designs/gqlgen/graphql"
	"github.com/99designs/gqlgen/graphql/handler/testserver"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	"github.com/stretchr/testify/assert"

	"github.com/DataDog/dd-trace-go/v2/ddtrace/ext"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
)

type testServerResponse struct {
	Name string
}

func TestOptions(t *testing.T) {
	query := `{ name }`
	for name, tt := range map[string]struct {
		tracerOpts []Option
		test       func(*assert.Assertions, *mocktracer.Span, []*mocktracer.Span)
	}{
		"default": {
			test: func(assert *assert.Assertions, root *mocktracer.Span, _ []*mocktracer.Span) {
				assert.Equal("graphql.query", root.OperationName())
				assert.Equal(query, root.Tag(ext.ResourceName))
				assert.Equal("graphql", root.Tag(ext.ServiceName))
				assert.Equal(ext.SpanTypeGraphQL, root.Tag(ext.SpanType))
				assert.Equal("99designs/gqlgen", root.Tag(ext.Component))
				assert.Nil(root.Tag(ext.EventSampleRate))
			},
		},
		"WithService": {
			tracerOpts: []Option{WithService("TestServer")},
			test: func(assert *assert.Assertions, root *mocktracer.Span, _ []*mocktracer.Span) {
				assert.Equal("TestServer", root.Tag(ext.ServiceName))
			},
		},
		"WithAnalytics/true": {
			tracerOpts: []Option{WithAnalytics(true)},
			test: func(assert *assert.Assertions, root *mocktracer.Span, _ []*mocktracer.Span) {
				assert.Equal(1.0, root.Tag(ext.EventSampleRate))
			},
		},
		"WithAnalytics/false": {
			tracerOpts: []Option{WithAnalytics(false)},
			test: func(assert *assert.Assertions, root *mocktracer.Span, _ []*mocktracer.Span) {
				assert.Nil(root.Tag(ext.EventSampleRate))
			},
		},
		"WithAnalyticsRate": {
			tracerOpts: []Option{WithAnalyticsRate(0.5)},
			test: func(assert *assert.Assertions, root *mocktracer.Span, _ []*mocktracer.Span) {
				assert.Equal(0.5, root.Tag(ext.EventSampleRate))
			},
		},
		"WithoutTraceTrivialResolvedFields": {
			tracerOpts: []Option{WithoutTraceTrivialResolvedFields()},
			test: func(assert *assert.Assertions, _ *mocktracer.Span, spans []*mocktracer.Span) {
				var hasFieldOperation bool
				for _, span := range spans {
					if span.OperationName() == fieldOp {
						hasFieldOperation = true
						break
					}
				}
				assert.Equal(false, hasFieldOperation)
			},
		},
		"WithCustomTag": {
			tracerOpts: []Option{
				WithCustomTag("customTag1", "customValue1"),
				WithCustomTag("customTag2", "customValue2"),
			},
			test: func(assert *assert.Assertions, root *mocktracer.Span, _ []*mocktracer.Span) {
				assert.Equal("customValue1", root.Tag("customTag1"))
				assert.Equal("customValue2", root.Tag("customTag2"))
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			mt := mocktracer.Start()
			defer mt.Stop()
			c := newTestClient(t, testserver.New(), NewTracer(tt.tracerOpts...))
			c.MustPost(query, &testServerResponse{})
			spans := mt.FinishedSpans()
			var root *mocktracer.Span
			for _, span := range spans {
				if span.ParentID() == 0 {
					root = span
				}
			}
			assert.NotNil(root)
			tt.test(assert, root, spans)
			assert.Nil(root.Tag(ext.ErrorMsg))
		})
	}

	// WithoutTraceIntrospectionQuery tested here since we are specifically checking against an IntrosepctionQuery operation.
	query = `query IntrospectionQuery { __schema { queryType { name } } }`
	for name, tt := range map[string]struct {
		tracerOpts []Option
		test       func(assert *assert.Assertions, spans []*mocktracer.Span)
	}{
		"WithoutTraceIntrospectionQuery": {
			tracerOpts: []Option{WithoutTraceIntrospectionQuery()},
			test: func(assert *assert.Assertions, spans []*mocktracer.Span) {
				var hasFieldSpan bool
				for _, span := range spans {
					if span.OperationName() == fieldOp {
						hasFieldSpan = true
						break
					}
				}
				assert.Equal(false, hasFieldSpan)
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			mt := mocktracer.Start()
			defer mt.Stop()
			c := newTestClient(t, testserver.New(), NewTracer(tt.tracerOpts...))
			c.MustPost(query, &testServerResponse{}, client.Operation("IntrospectionQuery"))
			tt.test(assert, mt.FinishedSpans())
		})
	}
}

func TestError(t *testing.T) {
	assert := assert.New(t)
	mt := mocktracer.Start()
	defer mt.Stop()
	c := newTestClient(t, testserver.NewError(), NewTracer())
	err := c.Post(`{ name }`, &testServerResponse{})
	assert.NotNil(err)
	var root *mocktracer.Span
	for _, span := range mt.FinishedSpans() {
		if span.ParentID() == 0 {
			root = span
		}
	}
	assert.NotNil(root)
	assert.NotNil(root.Tag(ext.ErrorMsg))
}

func TestObfuscation(t *testing.T) {
	assert := assert.New(t)
	mt := mocktracer.Start()
	defer mt.Stop()
	c := newTestClient(t, testserver.New(), NewTracer())
	var resp struct {
		Name string
	}
	query := `query($id: Int!) {
	name
	find(id: $id)
}
`
	err := c.Post(query, &resp, client.Var("id", 12345))
	assert.Nil(err)

	// No spans should contain the sensitive ID.
	for _, span := range mt.FinishedSpans() {
		assert.NotContains(span.Tag(ext.ResourceName), "12345")
	}
}

func TestChildSpans(t *testing.T) {
	assert := assert.New(t)
	mt := mocktracer.Start()
	defer mt.Stop()
	c := newTestClient(t, testserver.New(), NewTracer())
	err := c.Post(`{ name }`, &testServerResponse{})
	assert.Nil(err)
	var root *mocktracer.Span
	allSpans := mt.FinishedSpans()
	var resNames []string
	var opNames []string
	for _, span := range allSpans {
		if span.ParentID() == 0 {
			root = span
		}
		resNames = append(resNames, span.Tag(ext.ResourceName).(string))
		opNames = append(opNames, span.OperationName())
		assert.Equal("99designs/gqlgen", span.Tag(ext.Component))
	}
	assert.ElementsMatch(resNames, []string{readOp, parsingOp, validationOp, "Query.name", `{ name }`})
	assert.ElementsMatch(opNames, []string{readOp, parsingOp, validationOp, fieldOp, "graphql.query"})
	assert.NotNil(root)
	assert.Zero(root.Tag(ext.ErrorMsg))
}

func newTestClient(t *testing.T, h *testserver.TestServer, tracer graphql.HandlerExtension) *client.Client {
	t.Helper()
	h.AddTransport(transport.POST{})
	h.Use(tracer)
	return client.New(h)
}
