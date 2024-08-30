// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016 Datadog, Inc.

package httpsec

import (
	"gopkg.in/DataDog/dd-trace-go.v1/internal/appsec/trace"
	"gopkg.in/DataDog/dd-trace-go.v1/internal/appsec/trace/httptrace"
)

// SetRequestHeadersTags sets the AppSec-specific request headers span tags.
func SetRequestHeadersTags(span trace.TagSetter, headers map[string][]string) {
	setHeadersTags(span, "http.request.headers.", headers)
}

// SetResponseHeadersTags sets the AppSec-specific response headers span tags.
func SetResponseHeadersTags(span trace.TagSetter, headers map[string][]string) {
	setHeadersTags(span, "http.response.headers.", headers)
}

// setHeadersTags sets the AppSec-specific headers span tags.
func setHeadersTags(span trace.TagSetter, tagPrefix string, headers map[string][]string) {
	for h, v := range httptrace.NormalizeHTTPHeaders(headers) {
		span.SetTag(tagPrefix+h, v)
	}
}
