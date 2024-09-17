// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016 Datadog, Inc.

package vault

import (
	v2 "github.com/DataDog/dd-trace-go/contrib/hashicorp/vault/v2"
)

const defaultServiceName = "vault"

// Option can be passed to NewHTTPClient and WrapHTTPClient to configure the integration.
type Option = v2.Option

// WithAnalytics enables or disables Trace Analytics for all started spans.
func WithAnalytics(on bool) Option {
	return v2.WithAnalytics(on)
}

// WithAnalyticsRate sets the sampling rate for Trace Analytics events correlated to started spans.
func WithAnalyticsRate(rate float64) Option {
	return v2.WithAnalyticsRate(rate)
}

// WithServiceName sets the given service name for the http.Client.
func WithServiceName(name string) Option {
	return v2.WithService(name)
}
