// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2023 Datadog, Inc.

package validationtest

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	memcachetest "gopkg.in/DataDog/dd-trace-go.v1/contrib/internal/validationtest/contrib/bradfitz/gomemcache/memcache"
	sqltest "gopkg.in/DataDog/dd-trace-go.v1/contrib/internal/validationtest/contrib/database/sql"

	//redigotest "gopkg.in/DataDog/dd-trace-go.v1/contrib/internal/validationtest/contrib/garyburd/redigo"
	mgotest "gopkg.in/DataDog/dd-trace-go.v1/contrib/internal/validationtest/contrib/globalsign/mgo"
	pgtest "gopkg.in/DataDog/dd-trace-go.v1/contrib/internal/validationtest/contrib/go-pg/pg.v10"
	redistest "gopkg.in/DataDog/dd-trace-go.v1/contrib/internal/validationtest/contrib/go-redis/redis"
	redisV7test "gopkg.in/DataDog/dd-trace-go.v1/contrib/internal/validationtest/contrib/go-redis/redis.v7"
	redisV8test "gopkg.in/DataDog/dd-trace-go.v1/contrib/internal/validationtest/contrib/go-redis/redis.v8"
	mongotest "gopkg.in/DataDog/dd-trace-go.v1/contrib/internal/validationtest/contrib/go.mongodb.org/mongo-driver/mongo"
	gocqltrace "gopkg.in/DataDog/dd-trace-go.v1/contrib/internal/validationtest/contrib/gocql/gocql"
	gomodule_redigotest "gopkg.in/DataDog/dd-trace-go.v1/contrib/internal/validationtest/contrib/gomodule/redigo"
	gopkgJinzhuGormv1test "gopkg.in/DataDog/dd-trace-go.v1/contrib/internal/validationtest/contrib/gopkg.in/jinzhu/gorm.v1"
	gormv1test "gopkg.in/DataDog/dd-trace-go.v1/contrib/internal/validationtest/contrib/gorm.io/gorm.v1"
	jinzhuGormv1test "gopkg.in/DataDog/dd-trace-go.v1/contrib/internal/validationtest/contrib/jinzhu/gorm"

	elasticsearchV6test "gopkg.in/DataDog/dd-trace-go.v1/contrib/internal/validationtest/contrib/elastic/go-elasticsearch.v6"
	elasticsearchV7test "gopkg.in/DataDog/dd-trace-go.v1/contrib/internal/validationtest/contrib/elastic/go-elasticsearch.v7"

	//elasticsearchV8test "gopkg.in/DataDog/dd-trace-go.v1/contrib/internal/validationtest/contrib/elastic/go-elasticsearch.v8"

	gorestfultest "gopkg.in/DataDog/dd-trace-go.v1/contrib/internal/validationtest/contrib/emicklei/go-restful"
	ginGonicTest "gopkg.in/DataDog/dd-trace-go.v1/contrib/internal/validationtest/contrib/gin-gonic/gin"

	gochitest "gopkg.in/DataDog/dd-trace-go.v1/contrib/internal/validationtest/contrib/go-chi/chi"
	gochiv5test "gopkg.in/DataDog/dd-trace-go.v1/contrib/internal/validationtest/contrib/go-chi/chi.v5"

	sqlxtest "gopkg.in/DataDog/dd-trace-go.v1/contrib/internal/validationtest/contrib/jmoiron/sqlx"
	dnstest "gopkg.in/DataDog/dd-trace-go.v1/contrib/internal/validationtest/contrib/miekg/dns"
	redisV9test "gopkg.in/DataDog/dd-trace-go.v1/contrib/internal/validationtest/contrib/redis/go-redis.v9"
	leveldbtest "gopkg.in/DataDog/dd-trace-go.v1/contrib/internal/validationtest/contrib/syndtr/goleveldb/leveldb"
	buntdbtest "gopkg.in/DataDog/dd-trace-go.v1/contrib/internal/validationtest/contrib/tidwall/buntdb"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/tracer"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Integration is an interface that should be implemented by integrations (packages under the contrib/ folder) in
// order to be tested.
type Integration interface {
	// Name returns name of the integration (usually the import path starting from /contrib).
	Name() string

	// Init initializes the integration (start a server in the background, initialize the client, etc.).
	// It should also call t.Helper() before making any assertions.
	Init(t *testing.T)

	// GenSpans performs any operation(s) from the integration that generate spans.
	// It should call t.Helper() before making any assertions.
	GenSpans(t *testing.T)

	// NumSpans returns the number of spans that should have been generated during the test.
	NumSpans() int

	// WithServiceName configures the integration to use the given service name.
	WithServiceName(name string)
}

// tracerEnv gets the current tracer configuration variables needed for Test Agent testing and places
// these env variables in a comma separated string of key=value pairs.
func tracerEnv() string {
	var ddEnvVars []string
	for _, keyValue := range os.Environ() {
		if !strings.HasPrefix(keyValue, "DD_") {
			continue
		}
		ddEnvVars = append(ddEnvVars, keyValue)
	}
	return strings.Join(ddEnvVars, ",")
}

type testAgentRoundTripper struct {
	base http.RoundTripper
}

// RoundTrip adds the DD Tracer configuration environment and test session token to the trace request headers
func (rt *testAgentRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	sessionTokenEnv, ok := os.LookupEnv("CI_TEST_AGENT_SESSION_TOKEN")
	if !ok {
		sessionTokenEnv = "default"
	}
	req.Header.Add("X-Datadog-Trace-Env-Variables", tracerEnv())
	req.Header.Add("X-Datadog-Test-Session-Token", sessionTokenEnv)
	return rt.base.RoundTrip(req)
}

func testAgentDetails() string {
	testAgentHost, exists := os.LookupEnv("DD_TEST_AGENT_HOST")
	if !exists {
		testAgentHost = "localhost"
	}

	testAgentPort, exists := os.LookupEnv("DD_TEST_AGENT_PORT")
	if !exists {
		testAgentPort = "9126"
	}
	return fmt.Sprintf("%s:%s", testAgentHost, testAgentPort)
}

var (
	testAgentConnection = testAgentDetails()
	sessionToken        = "default"
)

func TestIntegrations(t *testing.T) {
	// if _, ok := os.LookupEnv("INTEGRATION"); !ok {
	// 	t.Skip("to enable integration test, set the INTEGRATION environment variable")
	// }
	integrations := []Integration{
		gochiv5test.New(),
		gochitest.New(),
		ginGonicTest.New(),
		gorestfultest.New(),
		elasticsearchV6test.New(),
		elasticsearchV7test.New(),
		// elasticsearchV8test.New(),
		sqltest.New(),
		gopkgJinzhuGormv1test.New(),
		jinzhuGormv1test.New(),
		gormv1test.New(),
		mgotest.New(),
		sqlxtest.New(),
		memcachetest.New(),
		dnstest.New(),
		//redigotest.New(),
		pgtest.New(),
		redistest.New(),
		redisV7test.New(),
		redisV8test.New(),
		mongotest.New(),
		gocqltrace.New(),
		gomodule_redigotest.New(),
		redisV9test.New(),
		leveldbtest.New(),
		buntdbtest.New(),
	}

	testCases := []struct {
		name                   string
		env                    map[string]string
		integrationServiceName string
	}{
		{
			"GlobalServiceConfigured",
			map[string]string{
				"DD_SERVICE": "Datadog-Test-Agent-Trace-Checks",
			},
			"",
		},
		{
			"SpanAttributeSchemaV0",
			map[string]string{
				"DD_TRACE_SPAN_ATTRIBUTE_SCHEMA": "v0",
				"DD_SERVICE":                     "Datadog-Test-Agent-Trace-Checks",
			},
			"",
		},
		{
			"SpanAttributeSchemaV1",
			map[string]string{
				"DD_TRACE_SPAN_ATTRIBUTE_SCHEMA": "v1",
				"DD_SERVICE":                     "Datadog-Test-Agent-Trace-Checks",
			},
			"",
		},
		{
			"SpanAttributeSchemaV1WithIntegrationServiceName",
			map[string]string{
				"DD_TRACE_SPAN_ATTRIBUTE_SCHEMA": "v1",
				"DD_SERVICE":                     "Datadog-Test-Agent-Trace-Checks",
			},
			"Datadog-Test-Agent-Trace-Checks-Override",
		},
	}

	for _, ig := range integrations {
		for _, tc := range testCases {
			testName := fmt.Sprintf("contrib/%s/%s", ig.Name(), tc.name)

			t.Run(testName, func(t *testing.T) {
				sessionToken = fmt.Sprintf("%s-%d", testName, time.Now().Unix())
				t.Setenv("CI_TEST_AGENT_SESSION_TOKEN", sessionToken)
				// t.Setenv("DD_SERVICE", "Datadog-Test-Agent-Trace-Checks")
				// loop through all our environment for the testCase and set each variable
				for k, v := range tc.env {
					t.Setenv(k, v)
				}

				// also include the testCase start options within the tracer config
				tracer.Start(
					tracer.WithAgentAddr(testAgentConnection),
					tracer.WithHTTPClient(tracerHTTPClient()),
				)
				defer tracer.Stop()

				if tc.integrationServiceName != "" {
					componentName := ig.Name()
					if componentName == "jmoiron/sqlx" {
						componentName = "database/sql"
					}
					t.Setenv(fmt.Sprintf("DD_%s_SERVICE", strings.ToUpper(componentName)), tc.integrationServiceName)
					ig.WithServiceName(tc.integrationServiceName)
				}

				ig.Init(t)
				ig.GenSpans(t)
				tracer.Flush()

				assertNumSpans(t, sessionToken, ig.NumSpans())
				checkFailures(t, sessionToken)
			})

		}
	}
}

// assertNumSpans makes an http request to the Test Agent for all traces produced with the included
// sessionToken and asserts that the correct number of spans was returned
func assertNumSpans(t *testing.T, sessionToken string, wantSpans int) {
	t.Helper()
	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/test/session/traces", testAgentConnection), nil)
	require.NoError(t, err)
	req.Header.Set("X-Datadog-Test-Session-Token", sessionToken)
	var lastReceived int
	run := func() bool {
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)

		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		var traces [][]map[string]interface{}
		require.NoError(t, json.Unmarshal(body, &traces))

		receivedSpans := 0
		for _, traceSpans := range traces {
			receivedSpans += len(traceSpans)
		}
		lastReceived = receivedSpans
		if receivedSpans > wantSpans {
			t.Fatalf("received more spans than expected (wantSpans: %d, receivedSpans: %d)", wantSpans, receivedSpans)
		}
		if receivedSpans < wantSpans {
			t.Logf("received less spans than expected (wantSpans: %d, receivedSpans: %d)", wantSpans, receivedSpans)
		}
		return receivedSpans == wantSpans
	}

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	timeoutChan := time.After(5 * time.Second)

	for {
		if done := run(); done {
			return
		}
		select {
		case <-ticker.C:
			continue

		case <-timeoutChan:
			t.Fatalf("timeout waiting for spans (wantSpans: %d, receivedSpans: %d)", wantSpans, lastReceived)
		}
	}
}

// checkFailures makes an HTTP request to the Test Agent for any Trace Check failures and passes or fails the test
// depending on if failures exist.
func checkFailures(t *testing.T, sessionToken string) {
	t.Helper()
	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/test/trace_check/failures", testAgentConnection), nil)
	require.NoError(t, err)
	req.Header.Set("X-Datadog-Test-Session-Token", sessionToken)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)

	defer resp.Body.Close()

	// the Test Agent returns a 200 if no trace-failures occurred and 400 otherwise
	if resp.StatusCode == http.StatusOK {
		return
	}
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Fail(t, "APM Test Agent detected failures: \n", string(body))
}

func tracerHTTPClient() *http.Client {
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	return &http.Client{
		// We copy the transport to avoid using the default one, as it might be
		// augmented with tracing and we don't want these calls to be recorded.
		// See https://golang.org/pkg/net/http/#DefaultTransport .
		Transport: &testAgentRoundTripper{
			base: &http.Transport{
				Proxy:                 http.ProxyFromEnvironment,
				DialContext:           dialer.DialContext,
				MaxIdleConns:          100,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
			},
		},
		Timeout: 2 * time.Second,
	}
}
