// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016 Datadog, Inc.

package kafka

import (
	"math"

	"github.com/DataDog/dd-trace-go/v2/instrumentation"
)

type config struct {
	consumerServiceName string
	producerServiceName string
	consumerSpanName    string
	producerSpanName    string
	analyticsRate       float64
	dataStreamsEnabled  bool
}

// Option describes options for the Kafka integration.
type Option interface {
	apply(*config)
}

// OptionFn represents options applicable to NewReader, NewWriter, WrapReader and WrapWriter.
type OptionFn func(*config)

func (fn OptionFn) apply(cfg *config) {
	fn(cfg)
}

func newConfig(opts ...Option) *config {
	cfg := &config{
		analyticsRate: instr.AnalyticsRate(false),
	}

	cfg.dataStreamsEnabled = instr.DataStreamsEnabled()

	cfg.consumerServiceName = instr.ServiceName(instrumentation.ComponentConsumer, nil)
	cfg.producerServiceName = instr.ServiceName(instrumentation.ComponentProducer, nil)
	cfg.consumerSpanName = instr.OperationName(instrumentation.ComponentConsumer, nil)
	cfg.producerSpanName = instr.OperationName(instrumentation.ComponentProducer, nil)

	for _, opt := range opts {
		opt.apply(cfg)
	}
	return cfg
}

// WithService sets the config service name to serviceName.
func WithService(serviceName string) OptionFn {
	return func(cfg *config) {
		cfg.consumerServiceName = serviceName
		cfg.producerServiceName = serviceName
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

// WithDataStreams enables the Data Streams monitoring product features: https://www.datadoghq.com/product/data-streams-monitoring/
func WithDataStreams() OptionFn {
	return func(cfg *config) {
		cfg.dataStreamsEnabled = true
	}
}
