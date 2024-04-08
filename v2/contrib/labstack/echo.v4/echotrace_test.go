// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016 Datadog, Inc.

package echo

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DataDog/dd-trace-go/v2/ddtrace/ext"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
	"github.com/DataDog/dd-trace-go/v2/internal/globalconfig"
	"github.com/DataDog/dd-trace-go/v2/internal/log"
	"github.com/DataDog/dd-trace-go/v2/internal/normalizer"
	"github.com/DataDog/dd-trace-go/v2/v1internal/namingschematest"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestChildSpan(t *testing.T) {
	assert := assert.New(t)
	mt := mocktracer.Start()
	defer mt.Stop()
	var called, traced bool

	router := echo.New()
	router.Use(Middleware(WithService("foobar")))
	router.GET("/user/:id", func(c echo.Context) error {
		called = true
		_, traced = tracer.SpanFromContext(c.Request().Context())
		return c.NoContent(200)
	})

	r := httptest.NewRequest("GET", "/user/123", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)

	// verify traces look good
	assert.True(called)
	assert.True(traced)
}

func TestTrace200(t *testing.T) {
	assert := assert.New(t)
	mt := mocktracer.Start()
	defer mt.Stop()
	var called, traced bool

	router := echo.New()
	router.Use(Middleware(WithService("foobar"), WithAnalytics(false)))
	router.GET("/user/:id", func(c echo.Context) error {
		called = true
		var span *tracer.Span
		span, traced = tracer.SpanFromContext(c.Request().Context())

		// we patch the span on the request context.
		span.SetTag("test.echo", "echony")
		assert.Equal(mocktracer.MockSpan(span).Tag(ext.ServiceName), "foobar")
		return c.NoContent(200)
	})

	root := tracer.StartSpan("root")
	r := httptest.NewRequest("GET", "/user/123", nil)
	err := tracer.Inject(root.Context(), tracer.HTTPHeadersCarrier(r.Header))
	assert.Nil(err)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)

	// verify traces look good
	assert.True(called)
	assert.True(traced)

	spans := mt.FinishedSpans()
	require.Len(t, spans, 1)

	span := spans[0]
	assert.Equal("http.request", span.OperationName())
	assert.Equal(ext.SpanTypeWeb, span.Tag(ext.SpanType))
	assert.Equal("foobar", span.Tag(ext.ServiceName))
	assert.Equal("echony", span.Tag("test.echo"))
	assert.Contains(span.Tag(ext.ResourceName), "/user/:id")
	assert.Equal("200", span.Tag(ext.HTTPCode))
	assert.Equal("GET", span.Tag(ext.HTTPMethod))
	assert.Equal(root.Context().SpanID(), span.ParentID())
	assert.Equal("labstack/echo.v4", span.Tag(ext.Component))
	assert.Equal(ext.SpanKindServer, span.Tag(ext.SpanKind))
	assert.Equal("/user/:id", span.Tag(ext.HTTPRoute))

	assert.Equal("http://example.com/user/123", span.Tag(ext.HTTPURL))
}

func TestTraceAnalytics(t *testing.T) {
	assert := assert.New(t)
	mt := mocktracer.Start()
	defer mt.Stop()
	var called, traced bool

	router := echo.New()
	router.Use(Middleware(WithService("foobar"), WithAnalytics(true)))
	router.GET("/user/:id", func(c echo.Context) error {
		called = true
		var span *tracer.Span
		span, traced = tracer.SpanFromContext(c.Request().Context())

		// we patch the span on the request context.
		span.SetTag("test.echo", "echony")
		assert.Equal(mocktracer.MockSpan(span).Tag(ext.ServiceName), "foobar")
		return c.NoContent(200)
	})

	root := tracer.StartSpan("root")
	r := httptest.NewRequest("GET", "/user/123", nil)
	err := tracer.Inject(root.Context(), tracer.HTTPHeadersCarrier(r.Header))
	assert.Nil(err)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)

	// verify traces look good
	assert.True(called)
	assert.True(traced)

	spans := mt.FinishedSpans()
	require.Len(t, spans, 1)

	span := spans[0]
	assert.Equal("http.request", span.OperationName())
	assert.Equal(ext.SpanTypeWeb, span.Tag(ext.SpanType))
	assert.Equal("foobar", span.Tag(ext.ServiceName))
	assert.Equal("echony", span.Tag("test.echo"))
	assert.Contains(span.Tag(ext.ResourceName), "/user/:id")
	assert.Equal("200", span.Tag(ext.HTTPCode))
	assert.Equal("GET", span.Tag(ext.HTTPMethod))
	assert.Equal(1.0, span.Tag(ext.EventSampleRate))
	assert.Equal(root.Context().SpanID(), span.ParentID())
	assert.Equal("labstack/echo.v4", span.Tag(ext.Component))
	assert.Equal(ext.SpanKindServer, span.Tag(ext.SpanKind))

	assert.Equal("http://example.com/user/123", span.Tag(ext.HTTPURL))
}

func TestError(t *testing.T) {
	assert := assert.New(t)
	mt := mocktracer.Start()
	defer mt.Stop()
	var called, traced bool

	// setup
	router := echo.New()
	router.Use(Middleware(WithService("foobar")))
	wantErr := errors.New("oh no")

	// a handler with an error and make the requests
	router.GET("/err", func(c echo.Context) error {
		_, traced = tracer.SpanFromContext(c.Request().Context())
		called = true

		err := wantErr
		c.Error(err)
		return err
	})
	r := httptest.NewRequest("GET", "/err", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)

	// verify the errors and status are correct
	assert.True(called)
	assert.True(traced)

	spans := mt.FinishedSpans()
	require.Len(t, spans, 1)

	span := spans[0]
	assert.Equal("http.request", span.OperationName())
	assert.Equal("foobar", span.Tag(ext.ServiceName))
	assert.Equal("500", span.Tag(ext.HTTPCode))
	assert.Equal(wantErr.Error(), span.Tag(ext.ErrorMsg))
	assert.Equal("labstack/echo.v4", span.Tag(ext.Component))
	assert.Equal(ext.SpanKindServer, span.Tag(ext.SpanKind))
}

func TestErrorHandling(t *testing.T) {
	assert := assert.New(t)
	mt := mocktracer.Start()
	defer mt.Stop()
	var called, traced bool

	// setup
	router := echo.New()
	router.HTTPErrorHandler = func(err error, ctx echo.Context) {
		ctx.Response().WriteHeader(http.StatusInternalServerError)
	}
	router.Use(Middleware(WithService("foobar")))
	wantErr := errors.New("oh no")

	// a handler with an error and make the requests
	router.GET("/err", func(c echo.Context) error {
		_, traced = tracer.SpanFromContext(c.Request().Context())
		called = true
		return wantErr
	})
	r := httptest.NewRequest("GET", "/err", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)

	// verify the errors and status are correct
	assert.True(called)
	assert.True(traced)

	spans := mt.FinishedSpans()
	require.Len(t, spans, 1)

	span := spans[0]
	assert.Equal("http.request", span.OperationName())
	assert.Equal("foobar", span.Tag(ext.ServiceName))
	assert.Equal("500", span.Tag(ext.HTTPCode))
	assert.Equal(wantErr.Error(), span.Tag(ext.ErrorMsg))
	assert.Equal("labstack/echo.v4", span.Tag(ext.Component))
	assert.Equal(ext.SpanKindServer, span.Tag(ext.SpanKind))
}

func TestStatusError(t *testing.T) {
	for _, tt := range []struct {
		isStatusError func(statusCode int) bool
		err           error
		code          string
		handler       func(c echo.Context) error
	}{
		{
			err:  errors.New("oh no"),
			code: "500",
			handler: func(c echo.Context) error {
				return errors.New("oh no")
			},
		},
		{
			err:  echo.NewHTTPError(http.StatusInternalServerError, "my error message"),
			code: "500",
			handler: func(c echo.Context) error {
				return echo.NewHTTPError(http.StatusInternalServerError, "my error message")
			},
		},
		{
			err:  nil,
			code: "400",
			handler: func(c echo.Context) error {
				return echo.NewHTTPError(http.StatusBadRequest, "my error message")
			},
		},
		{
			isStatusError: func(statusCode int) bool { return statusCode >= 400 && statusCode < 500 },
			err:           nil,
			code:          "500",
			handler: func(c echo.Context) error {
				return errors.New("oh no")
			},
		},
		{
			isStatusError: func(statusCode int) bool { return statusCode >= 400 && statusCode < 500 },
			err:           nil,
			code:          "500",
			handler: func(c echo.Context) error {
				return echo.NewHTTPError(http.StatusInternalServerError, "my error message")
			},
		},
		{
			isStatusError: func(statusCode int) bool { return statusCode >= 400 },
			err:           echo.NewHTTPError(http.StatusBadRequest, "my error message"),
			code:          "400",
			handler: func(c echo.Context) error {
				return echo.NewHTTPError(http.StatusBadRequest, "my error message")
			},
		},
		{
			isStatusError: func(statusCode int) bool { return statusCode >= 200 },
			err:           fmt.Errorf("201: Created"),
			code:          "201",
			handler: func(c echo.Context) error {
				c.JSON(201, map[string]string{"status": "ok", "type": "test"})
				return nil
			},
		},
		{
			isStatusError: func(statusCode int) bool { return statusCode >= 200 },
			err:           fmt.Errorf("200: OK"),
			code:          "200",
			handler: func(c echo.Context) error {
				// It's not clear if unset (0) status is possible naturally, but we can simulate that situation.
				c.Response().Status = 0
				return nil
			},
		},
	} {
		t.Run("", func(t *testing.T) {
			assert := assert.New(t)
			mt := mocktracer.Start()
			defer mt.Stop()

			router := echo.New()
			opts := []Option{WithService("foobar")}
			if tt.isStatusError != nil {
				opts = append(opts, WithStatusCheck(tt.isStatusError))
			}
			router.Use(Middleware(opts...))
			router.GET("/err", tt.handler)
			r := httptest.NewRequest("GET", "/err", nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, r)

			spans := mt.FinishedSpans()
			require.Len(t, spans, 1)
			span := spans[0]
			assert.Equal("http.request", span.OperationName())
			assert.Equal(ext.SpanTypeWeb, span.Tag(ext.SpanType))
			assert.Equal("foobar", span.Tag(ext.ServiceName))
			assert.Contains(span.Tag(ext.ResourceName), "/err")
			assert.Equal(tt.code, span.Tag(ext.HTTPCode))
			assert.Equal("GET", span.Tag(ext.HTTPMethod))
			err := span.Tag(ext.ErrorMsg)
			if tt.err != nil {
				if !assert.NotNil(err) {
					return
				}
				assert.Equal(tt.err.Error(), err)
			} else {
				assert.Nil(err)
			}
		})
	}
}

func TestGetSpanNotInstrumented(t *testing.T) {
	assert := assert.New(t)
	router := echo.New()
	var called, traced bool

	router.GET("/ping", func(c echo.Context) error {
		// Assert we don't have a span on the context.
		called = true
		_, traced = tracer.SpanFromContext(c.Request().Context())
		return c.NoContent(200)
	})

	r := httptest.NewRequest("GET", "/ping", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, r)
	assert.True(called)
	assert.False(traced)
}

func TestNoDebugStack(t *testing.T) {
	assert := assert.New(t)
	mt := mocktracer.Start()
	defer mt.Stop()
	var called, traced bool

	// setup
	router := echo.New()
	router.Use(Middleware(NoDebugStack()))
	wantErr := errors.New("oh no")

	// a handler with an error and make the requests
	router.GET("/err", func(c echo.Context) error {
		_, traced = tracer.SpanFromContext(c.Request().Context())
		called = true

		err := wantErr
		c.Error(err)
		return err
	})
	r := httptest.NewRequest("GET", "/err", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)

	// verify the error is correct and the stacktrace is disabled
	assert.True(called)
	assert.True(traced)

	spans := mt.FinishedSpans()
	require.Len(t, spans, 1)

	span := spans[0]
	assert.Equal(wantErr.Error(), span.Tag(ext.ErrorMsg))
	assert.Equal(nil, span.Tag(ext.ErrorStack))
	assert.Equal("labstack/echo.v4", span.Tag(ext.Component))
	assert.Equal(ext.SpanKindServer, span.Tag(ext.SpanKind))
}

func TestIgnoreRequestFunc(t *testing.T) {
	assert := assert.New(t)
	mt := mocktracer.Start()
	defer mt.Stop()
	var called, traced bool

	// setup
	ignoreRequestFunc := func(c echo.Context) bool {
		return true
	}
	router := echo.New()
	router.Use(Middleware(WithIgnoreRequest(ignoreRequestFunc)))

	// a handler with an error and make the requests
	router.GET("/err", func(c echo.Context) error {
		_, traced = tracer.SpanFromContext(c.Request().Context())
		called = true
		return nil
	})
	r := httptest.NewRequest("GET", "/err", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)

	// verify the error is correct and the stacktrace is disabled
	assert.True(called)
	assert.False(traced)

	spans := mt.FinishedSpans()
	assert.Len(spans, 0)
}

type testCustomError struct {
	TestCode int
}

// Error satisfies the apierror interface
func (e *testCustomError) Error() string {
	return "test"
}

func TestWithErrorTranslator(t *testing.T) {
	assert := assert.New(t)
	mt := mocktracer.Start()
	defer mt.Stop()
	var called, traced bool

	// setup
	translateError := func(e error) (*echo.HTTPError, bool) {
		return &echo.HTTPError{
			Message: e.(*testCustomError).Error(),
			Code:    e.(*testCustomError).TestCode,
		}, true
	}
	router := echo.New()
	router.Use(Middleware(WithErrorTranslator(translateError)))

	// a handler with an error and make the requests
	router.GET("/err", func(c echo.Context) error {
		_, traced = tracer.SpanFromContext(c.Request().Context())
		called = true
		return &testCustomError{
			TestCode: 401,
		}
	})
	r := httptest.NewRequest("GET", "/err", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)

	// verify the error is correct and the stacktrace is disabled
	assert.True(called)
	assert.True(traced)

	spans := mt.FinishedSpans()
	require.Len(t, spans, 1)
	span := spans[0]
	assert.Equal("http.request", span.OperationName())
	assert.Equal(ext.SpanTypeWeb, span.Tag(ext.SpanType))
	assert.Contains(span.Tag(ext.ResourceName), "/err")
	assert.Equal("401", span.Tag(ext.HTTPCode))
	assert.Equal("GET", span.Tag(ext.HTTPMethod))
}

func TestNamingSchema(t *testing.T) {
	genSpans := namingschematest.GenSpansFn(func(t *testing.T, serviceOverride string) []*mocktracer.Span {
		var opts []Option
		if serviceOverride != "" {
			opts = append(opts, WithService(serviceOverride))
		}
		mt := mocktracer.Start()
		defer mt.Stop()

		mux := echo.New()
		mux.Use(Middleware(opts...))
		mux.GET("/200", func(c echo.Context) error {
			return c.NoContent(200)
		})
		r := httptest.NewRequest("GET", "/200", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)

		return mt.FinishedSpans()
	})
	namingschematest.NewHTTPServerTest(genSpans, "echo")(t)
}

func TestWithHeaderTags(t *testing.T) {
	setupReq := func(opts ...Option) *http.Request {
		router := echo.New()
		router.Use(Middleware(opts...))

		router.GET("/test", func(c echo.Context) error {
			return c.String(http.StatusOK, "test")
		})
		r := httptest.NewRequest("GET", "/test", nil)
		r.Header.Set("h!e@a-d.e*r", "val")
		r.Header.Add("h!e@a-d.e*r", "val2")
		r.Header.Set("2header", "2val")
		r.Header.Set("3header", "3val")
		r.Header.Set("x-datadog-header", "value")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		return r
	}
	t.Run("default-off", func(t *testing.T) {
		mt := mocktracer.Start()
		defer mt.Stop()
		htArgs := []string{"h!e@a-d.e*r", "2header", "3header", "x-datadog-header"}
		setupReq()
		spans := mt.FinishedSpans()
		assert := assert.New(t)
		assert.Equal(len(spans), 1)
		s := spans[0]
		for _, arg := range htArgs {
			_, tag := normalizer.HeaderTag(arg)
			assert.NotContains(s.Tags(), tag)
		}
	})
	t.Run("integration", func(t *testing.T) {
		mt := mocktracer.Start()
		defer mt.Stop()

		htArgs := []string{"h!e@a-d.e*r", "2header:tag"}
		r := setupReq(WithHeaderTags(htArgs))
		spans := mt.FinishedSpans()
		assert := assert.New(t)
		assert.Equal(len(spans), 1)
		s := spans[0]

		for _, arg := range htArgs {
			header, tag := normalizer.HeaderTag(arg)
			assert.Equal(strings.Join(r.Header.Values(header), ","), s.Tags()[tag])
		}
		assert.NotContains(s.Tags(), "http.headers.x-datadog-header")
	})

	t.Run("global", func(t *testing.T) {
		mt := mocktracer.Start()
		defer mt.Stop()

		header, tag := normalizer.HeaderTag("3header")
		globalconfig.SetHeaderTag(header, tag)

		r := setupReq()
		spans := mt.FinishedSpans()
		assert := assert.New(t)
		assert.Equal(len(spans), 1)
		s := spans[0]

		assert.Equal(strings.Join(r.Header.Values(header), ","), s.Tags()[tag])
		assert.NotContains(s.Tags(), "http.headers.x-datadog-header")
	})

	t.Run("override", func(t *testing.T) {
		mt := mocktracer.Start()
		defer mt.Stop()

		globalH, globalT := normalizer.HeaderTag("3header")
		globalconfig.SetHeaderTag(globalH, globalT)

		htArgs := []string{"h!e@a-d.e*r", "2header:tag"}
		r := setupReq(WithHeaderTags(htArgs))
		spans := mt.FinishedSpans()
		assert := assert.New(t)
		assert.Equal(len(spans), 1)
		s := spans[0]

		for _, arg := range htArgs {
			header, tag := normalizer.HeaderTag(arg)
			assert.Equal(strings.Join(r.Header.Values(header), ","), s.Tags()[tag])
		}
		assert.NotContains(s.Tags(), "http.headers.x-datadog-header")
		assert.NotContains(s.Tags(), globalT)
	})
}

func TestWithErrorCheck(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		opts    []Option
		wantErr error
	}{
		{
			name: "ignore-4xx-404-error",
			err: &echo.HTTPError{
				Code:     http.StatusNotFound,
				Message:  "not found",
				Internal: errors.New("not found"),
			},
			opts: []Option{
				WithErrorCheck(func(err error) bool {
					var he *echo.HTTPError
					if errors.As(err, &he) {
						// do not tag 4xx errors
						return !(he.Code < 500 && he.Code >= 400)
					}
					return true
				}),
			},
			wantErr: nil, // 404 is returned, hence not tagged
		},
		{
			name: "ignore-4xx-500-error",
			err: &echo.HTTPError{
				Code:     http.StatusInternalServerError,
				Message:  "internal error",
				Internal: errors.New("internal error"),
			},
			opts: []Option{
				WithErrorCheck(func(err error) bool {
					var he *echo.HTTPError
					if errors.As(err, &he) {
						// do not tag 4xx errors
						return !(he.Code < 500 && he.Code >= 400)
					}
					return true
				}),
			},
			wantErr: &echo.HTTPError{
				Code:     http.StatusInternalServerError,
				Message:  "internal error",
				Internal: errors.New("internal error"),
			}, // this is 500, tagged
		},
		{
			name: "ignore-none",
			err:  errors.New("any error"),
			opts: []Option{
				WithErrorCheck(func(err error) bool {
					return true
				}),
			},
			wantErr: errors.New("any error"),
		},
		{
			name: "ignore-all",
			err:  errors.New("any error"),
			opts: []Option{
				WithErrorCheck(func(err error) bool {
					return false
				}),
			},
			wantErr: nil,
		},
		{
			// withErrorCheck also runs for the errors created from the WithStatusCheck option.
			name: "ignore-errors-from-status-check",
			err: &echo.HTTPError{
				Code:     http.StatusNotFound,
				Message:  "internal error",
				Internal: errors.New("internal error"),
			},
			opts: []Option{
				WithStatusCheck(func(statusCode int) bool {
					return statusCode == http.StatusNotFound
				}),
				WithErrorCheck(func(err error) bool {
					return false
				}),
			},
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mt := mocktracer.Start()
			defer mt.Stop()

			router := echo.New()
			router.Use(Middleware(tt.opts...))
			var called, traced bool

			// always return the specified error
			router.GET("/err", func(c echo.Context) error {
				_, traced = tracer.SpanFromContext(c.Request().Context())
				called = true
				return tt.err
			})
			r := httptest.NewRequest(http.MethodGet, "/err", nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, r)

			assert.True(t, called)
			assert.True(t, traced)
			spans := mt.FinishedSpans()
			require.Len(t, spans, 1) // fail at once if there is no span

			span := spans[0]
			if tt.wantErr == nil {
				assert.NotContains(t, span.Tags(), ext.ErrorMsg)
				return
			}
			assert.Equal(t, tt.wantErr.Error(), span.Tag(ext.ErrorMsg))
		})
	}
}

func TestWithCustomTags(t *testing.T) {
	assert := assert.New(t)
	mt := mocktracer.Start()
	defer mt.Stop()
	var called, traced bool

	// setup
	router := echo.New()
	router.Use(Middleware(
		WithService("foobar"),
		WithCustomTag("customTag1", "customValue1"),
		WithCustomTag("customTag2", "customValue2"),
		WithCustomTag(ext.SpanKind, "replace me"),
	))

	// a handler with an error and make the requests
	router.GET("/test", func(c echo.Context) error {
		_, traced = tracer.SpanFromContext(c.Request().Context())
		called = true
		return nil
	})
	r := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)

	// verify the errors and status are correct
	assert.True(called)
	assert.True(traced)

	spans := mt.FinishedSpans()
	require.Len(t, spans, 1)

	span := spans[0]
	assert.Equal("customValue1", span.Tag("customTag1"))
	assert.Equal("customValue2", span.Tag("customTag2"))
	assert.Equal("server", span.Tag(ext.SpanKind))
}

func BenchmarkEchoNoTracing(b *testing.B) {
	mux := echo.New()
	mux.GET("/200", func(c echo.Context) error {
		return c.NoContent(200)
	})
	r := httptest.NewRequest("GET", "/200", nil)
	w := httptest.NewRecorder()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mux.ServeHTTP(w, r)
	}
}

func BenchmarkEchoWithTracing(b *testing.B) {
	tracer.Start(tracer.WithLogger(log.DiscardLogger{}))
	defer tracer.Stop()

	mux := echo.New()
	mux.Use(Middleware())
	mux.GET("/200", func(c echo.Context) error {
		return c.NoContent(200)
	})
	r := httptest.NewRequest("GET", "/200", nil)
	w := httptest.NewRecorder()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mux.ServeHTTP(w, r)
	}
}
