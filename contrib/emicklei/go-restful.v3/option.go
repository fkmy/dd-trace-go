// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016 Datadog, Inc.

package restful

import (
	"math"

	"github.com/DataDog/dd-trace-go/v2/instrumentation"
)

type config struct {
	serviceName   string
	analyticsRate float64
	headerTags    instrumentation.HeaderTags
}

func newConfig() *config {
	return &config{
		serviceName:   instr.ServiceName(instrumentation.ComponentServer, nil),
		analyticsRate: instr.AnalyticsRate(true),
		headerTags:    instr.HTTPHeadersAsTags(),
	}
}

// Option describes options for the go-restful integration.
type Option interface {
	apply(*config)
}

// OptionFn represents options applicable to FilterFunc.
type OptionFn func(*config)

func (fn OptionFn) apply(cfg *config) {
	fn(cfg)
}

// WithService sets the service name to by used by the filter.
func WithService(name string) OptionFn {
	return func(cfg *config) {
		cfg.serviceName = name
	}
}

// WithAnalytics enables Trace Analytics for all started spans.
func WithAnalytics(on bool) OptionFn {
	return func(cfg *config) {
		if on {
			cfg.analyticsRate = 1.0
		} else {
			cfg.analyticsRate = math.NaN()
		}
	}
}

// WithAnalyticsRate sets the sampling rate for Trace Analytics events
// correlated to started spans.
func WithAnalyticsRate(rate float64) OptionFn {
	return func(cfg *config) {
		if rate >= 0.0 && rate <= 1.0 {
			cfg.analyticsRate = rate
		} else {
			cfg.analyticsRate = math.NaN()
		}
	}
}

// WithHeaderTags enables the integration to attach HTTP request headers as span tags.
// Warning:
// Using this feature can risk exposing sensitive data such as authorization tokens to Datadog.
// Special headers can not be sub-selected. E.g., an entire Cookie header would be transmitted, without the ability to choose specific Cookies.
func WithHeaderTags(headers []string) OptionFn {
	return func(cfg *config) {
		cfg.headerTags = instrumentation.NewHeaderTags(headers)
	}
}
