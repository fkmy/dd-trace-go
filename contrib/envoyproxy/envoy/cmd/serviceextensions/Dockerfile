# Build stage
FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -tags appsec -o ./contrib/envoyproxy/envoy/cmd/serviceextensions/serviceextensions ./contrib/envoyproxy/envoy/cmd/serviceextensions

# Runtime stage
FROM alpine:3.20.3
WORKDIR /app
COPY --from=builder /app/contrib/envoyproxy/envoy/cmd/serviceextensions/serviceextensions /app/serviceextensions
COPY ./contrib/envoyproxy/envoy/cmd/serviceextensions/localhost.crt /app/localhost.crt
COPY ./contrib/envoyproxy/envoy/cmd/serviceextensions/localhost.key /app/localhost.key

EXPOSE 80
EXPOSE 443

CMD ["./serviceextensions"]
