// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016 Datadog, Inc.

package kafka

import (
	"context"
	"errors"
	"log"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/segmentio/kafka-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gopkg.in/DataDog/dd-trace-go.v1/contrib/internal/namingschematest"
	"gopkg.in/DataDog/dd-trace-go.v1/contrib/segmentio/kafka.go.v0/internal/tracing"
	"gopkg.in/DataDog/dd-trace-go.v1/datastreams"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/ext"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/mocktracer"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/tracer"
)

const (
	testGroupID       = "gosegtest"
	testTopic         = "gosegtest"
	testReaderMaxWait = 10 * time.Millisecond
)

func TestMain(m *testing.M) {
	_, ok := os.LookupEnv("INTEGRATION")
	if !ok {
		log.Println("🚧 Skipping integration test (INTEGRATION environment variable is not set)")
		os.Exit(0)
	}
	cleanup := createTopic()
	exitCode := m.Run()
	cleanup()
	os.Exit(exitCode)
}

func createTopic() func() {
	conn, err := kafka.Dial("tcp", "localhost:9092")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	controller, err := conn.Controller()
	if err != nil {
		log.Fatal(err)
	}

	controllerConn, err := kafka.Dial("tcp", net.JoinHostPort(controller.Host, strconv.Itoa(controller.Port)))
	if err != nil {
		log.Fatal(err)
	}

	err = controllerConn.DeleteTopics(testTopic)
	if err != nil && !errors.Is(err, kafka.UnknownTopicOrPartition) {
		log.Fatalf("failed to delete topic: %v", err)
	}
	topicConfigs := []kafka.TopicConfig{
		{
			Topic:             testTopic,
			NumPartitions:     1,
			ReplicationFactor: 1,
		},
	}
	err = controllerConn.CreateTopics(topicConfigs...)
	if err != nil {
		log.Fatal(err)
	}
	return func() {
		if err := controllerConn.DeleteTopics(testTopic); err != nil {
			log.Printf("failed to delete topic: %v", err)
		}
		if err := controllerConn.Close(); err != nil {
			log.Printf("failed to close controller connection: %v", err)
		}
	}
}

type readerOpFn func(t *testing.T, r *Reader)

func genIntegrationTestSpans(t *testing.T, mt mocktracer.Tracer, writerOp func(t *testing.T, w *Writer), readerOp readerOpFn, writerOpts []Option, readerOpts []Option) ([]mocktracer.Span, []kafka.Message) {
	writtenMessages := []kafka.Message{}

	// add some dummy values to broker/addr to test bootstrap servers.
	kw := &kafka.Writer{
		Addr:         kafka.TCP("localhost:9092", "localhost:9093", "localhost:9094"),
		Topic:        testTopic,
		RequiredAcks: kafka.RequireOne,
		Completion: func(messages []kafka.Message, err error) {
			writtenMessages = append(writtenMessages, messages...)
		},
	}
	w := WrapWriter(kw, writerOpts...)
	writerOp(t, w)
	err := w.Close()
	require.NoError(t, err)

	r := NewReader(kafka.ReaderConfig{
		Brokers: []string{"localhost:9092", "localhost:9093", "localhost:9094"},
		GroupID: testGroupID,
		Topic:   testTopic,
		MaxWait: testReaderMaxWait,
	}, readerOpts...)
	readerOp(t, r)
	err = r.Close()
	require.NoError(t, err)

	spans := mt.FinishedSpans()
	require.Len(t, spans, 2)
	// they should be linked via headers
	assert.Equal(t, spans[0].TraceID(), spans[1].TraceID(), "Trace IDs should match")
	return spans, writtenMessages
}

func TestReadMessageFunctional(t *testing.T) {
	mt := mocktracer.Start()
	defer mt.Stop()

	var (
		messagesToWrite = []kafka.Message{
			{
				Key:   []byte("key1"),
				Value: []byte("value1"),
			},
		}
		readMessages []kafka.Message
	)

	spans, writtenMessages := genIntegrationTestSpans(
		t,
		mt,
		func(t *testing.T, w *Writer) {
			err := w.WriteMessages(context.Background(), messagesToWrite...)
			require.NoError(t, err, "Expected to write message to topic")
		},
		func(t *testing.T, r *Reader) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			readMsg, err := r.ReadMessage(ctx)
			require.NoError(t, err, "Expected to consume message")
			assert.Equal(t, messagesToWrite[0].Value, readMsg.Value, "Values should be equal")

			readMessages = append(readMessages, readMsg)
			err = r.CommitMessages(context.Background(), readMsg)
			assert.NoError(t, err, "Expected CommitMessages to not return an error")
		},
		[]Option{WithAnalyticsRate(0.1), WithDataStreams()},
		[]Option{WithDataStreams()},
	)

	assert.Len(t, writtenMessages, len(messagesToWrite))
	assert.Len(t, readMessages, len(messagesToWrite))

	// producer span
	s0 := spans[0]
	assert.Equal(t, "kafka.produce", s0.OperationName())
	assert.Equal(t, "kafka", s0.Tag(ext.ServiceName))
	assert.Equal(t, "Produce Topic "+testTopic, s0.Tag(ext.ResourceName))
	assert.Equal(t, 0.1, s0.Tag(ext.EventSampleRate))
	assert.Equal(t, "queue", s0.Tag(ext.SpanType))
	assert.Equal(t, 0, s0.Tag(ext.MessagingKafkaPartition))
	assert.Equal(t, "segmentio/kafka.go.v0", s0.Tag(ext.Component))
	assert.Equal(t, ext.SpanKindProducer, s0.Tag(ext.SpanKind))
	assert.Equal(t, "kafka", s0.Tag(ext.MessagingSystem))
	assert.Equal(t, "localhost:9092,localhost:9093,localhost:9094", s0.Tag(ext.KafkaBootstrapServers))

	p, ok := datastreams.PathwayFromContext(datastreams.ExtractFromBase64Carrier(context.Background(), tracing.MessageCarrier{Message: tracingMessage(&writtenMessages[0])}))
	assert.True(t, ok)
	expectedCtx, _ := tracer.SetDataStreamsCheckpoint(context.Background(), "direction:out", "topic:"+testTopic, "type:kafka")
	expected, _ := datastreams.PathwayFromContext(expectedCtx)
	assert.NotEqual(t, expected.GetHash(), 0)
	assert.Equal(t, expected.GetHash(), p.GetHash())

	// consumer span
	s1 := spans[1]
	assert.Equal(t, "kafka.consume", s1.OperationName())
	assert.Equal(t, "kafka", s1.Tag(ext.ServiceName))
	assert.Equal(t, "Consume Topic "+testTopic, s1.Tag(ext.ResourceName))
	assert.Equal(t, nil, s1.Tag(ext.EventSampleRate))
	assert.Equal(t, "queue", s1.Tag(ext.SpanType))
	assert.Equal(t, 0, s1.Tag(ext.MessagingKafkaPartition))
	assert.Equal(t, "segmentio/kafka.go.v0", s1.Tag(ext.Component))
	assert.Equal(t, ext.SpanKindConsumer, s1.Tag(ext.SpanKind))
	assert.Equal(t, "kafka", s1.Tag(ext.MessagingSystem))
	assert.Equal(t, "localhost:9092,localhost:9093,localhost:9094", s1.Tag(ext.KafkaBootstrapServers))

	p, ok = datastreams.PathwayFromContext(datastreams.ExtractFromBase64Carrier(context.Background(), tracing.MessageCarrier{Message: tracingMessage(&readMessages[0])}))
	assert.True(t, ok)
	expectedCtx, _ = tracer.SetDataStreamsCheckpoint(
		datastreams.ExtractFromBase64Carrier(context.Background(), tracing.MessageCarrier{Message: tracingMessage(&writtenMessages[0])}),
		"direction:in", "topic:"+testTopic, "type:kafka", "group:"+testGroupID,
	)
	expected, _ = datastreams.PathwayFromContext(expectedCtx)
	assert.NotEqual(t, expected.GetHash(), 0)
	assert.Equal(t, expected.GetHash(), p.GetHash())
}

func TestFetchMessageFunctional(t *testing.T) {
	mt := mocktracer.Start()
	defer mt.Stop()

	var (
		messagesToWrite = []kafka.Message{
			{
				Key:   []byte("key1"),
				Value: []byte("value1"),
			},
		}
		readMessages []kafka.Message
	)

	spans, writtenMessages := genIntegrationTestSpans(
		t,
		mt,
		func(t *testing.T, w *Writer) {
			err := w.WriteMessages(context.Background(), messagesToWrite...)
			require.NoError(t, err, "Expected to write message to topic")
		},
		func(t *testing.T, r *Reader) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			readMsg, err := r.FetchMessage(ctx)
			require.NoError(t, err, "Expected to consume message")
			assert.Equal(t, messagesToWrite[0].Value, readMsg.Value, "Values should be equal")

			readMessages = append(readMessages, readMsg)
			err = r.CommitMessages(context.Background(), readMsg)
			assert.NoError(t, err, "Expected CommitMessages to not return an error")
		},
		[]Option{WithAnalyticsRate(0.1), WithDataStreams()},
		[]Option{WithDataStreams()},
	)

	// producer span
	s0 := spans[0]
	assert.Equal(t, "kafka.produce", s0.OperationName())
	assert.Equal(t, "kafka", s0.Tag(ext.ServiceName))
	assert.Equal(t, "Produce Topic "+testTopic, s0.Tag(ext.ResourceName))
	assert.Equal(t, 0.1, s0.Tag(ext.EventSampleRate))
	assert.Equal(t, "queue", s0.Tag(ext.SpanType))
	assert.Equal(t, 0, s0.Tag(ext.MessagingKafkaPartition))
	assert.Equal(t, "segmentio/kafka.go.v0", s0.Tag(ext.Component))
	assert.Equal(t, ext.SpanKindProducer, s0.Tag(ext.SpanKind))
	assert.Equal(t, "kafka", s0.Tag(ext.MessagingSystem))
	assert.Equal(t, "localhost:9092,localhost:9093,localhost:9094", s0.Tag(ext.KafkaBootstrapServers))

	p, ok := datastreams.PathwayFromContext(datastreams.ExtractFromBase64Carrier(context.Background(), tracing.MessageCarrier{Message: tracingMessage(&writtenMessages[0])}))
	assert.True(t, ok)
	expectedCtx, _ := tracer.SetDataStreamsCheckpoint(context.Background(), "direction:out", "topic:"+testTopic, "type:kafka")
	expected, _ := datastreams.PathwayFromContext(expectedCtx)
	assert.NotEqual(t, expected.GetHash(), 0)
	assert.Equal(t, expected.GetHash(), p.GetHash())

	// consumer span
	s1 := spans[1]
	assert.Equal(t, "kafka.consume", s1.OperationName())
	assert.Equal(t, "kafka", s1.Tag(ext.ServiceName))
	assert.Equal(t, "Consume Topic "+testTopic, s1.Tag(ext.ResourceName))
	assert.Equal(t, nil, s1.Tag(ext.EventSampleRate))
	assert.Equal(t, "queue", s1.Tag(ext.SpanType))
	assert.Equal(t, 0, s1.Tag(ext.MessagingKafkaPartition))
	assert.Equal(t, "segmentio/kafka.go.v0", s1.Tag(ext.Component))
	assert.Equal(t, ext.SpanKindConsumer, s1.Tag(ext.SpanKind))
	assert.Equal(t, "kafka", s1.Tag(ext.MessagingSystem))
	assert.Equal(t, "localhost:9092,localhost:9093,localhost:9094", s1.Tag(ext.KafkaBootstrapServers))

	p, ok = datastreams.PathwayFromContext(datastreams.ExtractFromBase64Carrier(context.Background(), tracing.MessageCarrier{Message: tracingMessage(&readMessages[0])}))
	assert.True(t, ok)
	expectedCtx, _ = tracer.SetDataStreamsCheckpoint(
		datastreams.ExtractFromBase64Carrier(context.Background(), tracing.MessageCarrier{Message: tracingMessage(&writtenMessages[0])}),
		"direction:in", "topic:"+testTopic, "type:kafka", "group:"+testGroupID,
	)
	expected, _ = datastreams.PathwayFromContext(expectedCtx)
	assert.NotEqual(t, expected.GetHash(), 0)
	assert.Equal(t, expected.GetHash(), p.GetHash())
}

func TestNamingSchema(t *testing.T) {
	genSpans := func(t *testing.T, serviceOverride string) []mocktracer.Span {
		var opts []Option
		if serviceOverride != "" {
			opts = append(opts, WithServiceName(serviceOverride))
		}

		mt := mocktracer.Start()
		defer mt.Stop()

		messagesToWrite := []kafka.Message{
			{
				Key:   []byte("key1"),
				Value: []byte("value1"),
			},
		}

		spans, _ := genIntegrationTestSpans(
			t,
			mt,
			func(t *testing.T, w *Writer) {
				err := w.WriteMessages(context.Background(), messagesToWrite...)
				require.NoError(t, err, "Expected to write message to topic")
			},
			func(t *testing.T, r *Reader) {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				readMsg, err := r.FetchMessage(ctx)
				require.NoError(t, err, "Expected to consume message")
				assert.Equal(t, messagesToWrite[0].Value, readMsg.Value, "Values should be equal")

				err = r.CommitMessages(context.Background(), readMsg)
				assert.NoError(t, err, "Expected CommitMessages to not return an error")
			},
			opts,
			opts,
		)
		return spans
	}
	namingschematest.NewKafkaTest(genSpans)(t)
}

func BenchmarkReaderStartSpan(b *testing.B) {
	ctx := context.Background()
	cfg := tracing.NewConfig()
	kafkaCfg := &tracing.KafkaConfig{
		BootstrapServers: "localhost:9092,localhost:9093,localhost:9094",
		ConsumerGroupID:  testGroupID,
	}
	msg := kafka.Message{
		Key:   []byte("key1"),
		Value: []byte("value1"),
	}

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		tracing.StartConsumeSpan(ctx, cfg, kafkaCfg, tracingMessage(&msg))
	}
}

func BenchmarkWriterStartSpan(b *testing.B) {
	ctx := context.Background()
	cfg := tracing.NewConfig()
	kafkaCfg := &tracing.KafkaConfig{
		BootstrapServers: "localhost:9092,localhost:9093,localhost:9094",
		ConsumerGroupID:  testGroupID,
	}
	kw := &kafka.Writer{
		Addr:         kafka.TCP("localhost:9092", "localhost:9093", "localhost:9094"),
		Topic:        testTopic,
		RequiredAcks: kafka.RequireOne,
	}
	msg := kafka.Message{
		Key:   []byte("key1"),
		Value: []byte("value1"),
	}

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		tracing.StartProduceSpan(ctx, cfg, kafkaCfg, tracingWriter(kw), tracingMessage(&msg))
	}
}
