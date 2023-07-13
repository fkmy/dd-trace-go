// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016 Datadog, Inc.

package redigo_test

import (
	"log"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	pgtrace "gopkg.in/DataDog/dd-trace-go.v1/contrib/go-pg/pg.v10"

	"github.com/go-pg/pg/v10"
)

type Integration struct {
	conn     *pg.DB
	numSpans int
}

func New() *Integration {
	return &Integration{}
}

func (i *Integration) Name() string {
	return "contrib/go-pg/pg.v10"
}

func (i *Integration) Init(t *testing.T) func() {
	t.Helper()
	i.conn = pg.Connect(&pg.Options{
		User:     "postgres",
		Password: "postgres",
		Database: "postgres",
	})

	// Wrap the connection with the APM hook.
	pgtrace.Wrap(i.conn)
	var n int
	_, err := i.conn.QueryOne(pg.Scan(&n), "SELECT 1")
	if err != nil {
		log.Fatal(err)
	}
	i.numSpans++

	return func() {
		i.conn.Close()
	}
}

func (i *Integration) GenSpans(t *testing.T) {
	t.Helper()

	var n int
	res, err := i.conn.QueryOne(pg.Scan(&n), "SELECT 1")
	require.NoError(t, err)
	assert.Equal(t, 1, res.RowsAffected())
	i.numSpans++

	var x int
	_, err = i.conn.QueryOne(pg.Scan(&x), "SELECT 2")
	require.NoError(t, err)
	assert.Equal(t, 1, res.RowsAffected())
	i.numSpans++
}

func (i *Integration) NumSpans() int {
	return i.numSpans
}