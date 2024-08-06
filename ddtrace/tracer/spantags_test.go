// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024 Datadog, Inc.

package tracer

import (
	"math/rand"
	"strconv"
	"testing"

	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/ext"
)

func BenchmarkSpanLifecycle(b *testing.B) {
	r := rand.New(rand.NewSource(0))
	distribution := newDistributionRand(
		b,
		// The probabilities represent the distribution of the number of tags
		// that are set on a span as observed in our production intake at the time
		// of writing this benchmark.
		[]float64{0.01, 0.09, 0.4, 0.25, 0.15, 0.05, 0.04, 0.01},
		[]float64{8.75, 14.59, 22.8, 31.2, 39.1, 43.5, 54.3, 70.0},
	)
	b.Run("baseline", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			span := StartSpan("benchmark")
			span.Finish()
		}
	})
	b.Run("with unknown tags", func(b *testing.B) {
		// precompute the tags
		tags := make([]string, 70)
		for i := 0; i < len(tags); i++ {
			tags[i] = strconv.Itoa(i)
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			span := StartSpan("benchmark")
			nTags := int(distribution.generate(r))
			for j := 0; j < nTags; j++ {
				span.SetTag(tags[j], "tag")
			}
			span.Finish()
		}
	})
	b.Run("with known tags", func(b *testing.B) {
		// precompute the tags
		tags := make([]string, 70)
		for i := 0; i < len(tags); i++ {
			tags[i] = strconv.Itoa(i)
		}
		tags[0] = ext.Environment
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			span := StartSpan("benchmark")
			nTags := int(distribution.generate(r))
			for j := 0; j < nTags; j++ {
				span.SetTag(tags[j], "tag")
			}
			span.Finish()
		}
	})
}

// distributionRand is a helper for generating random numbers following
// a given probability distribution. It implements the inverse transform
// sampling method.
type distributionRand struct {
	b      *testing.B
	cdf    []float64
	values []float64
}

func newDistributionRand(b *testing.B, probabilities []float64, values []float64) *distributionRand {
	b.Helper()
	cdf := make([]float64, len(probabilities))
	sum := 0.0
	for i, p := range probabilities {
		sum += p
		cdf[i] = sum
	}
	return &distributionRand{
		b:      b,
		cdf:    cdf,
		values: values,
	}
}

func (d *distributionRand) generate(r *rand.Rand) float64 {
	d.b.Helper()
	u := r.Float64()
	for i, c := range d.cdf {
		if u <= c {
			return d.values[i]
		}
	}
	return d.values[len(d.values)-1]
}
