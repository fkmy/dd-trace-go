module gopkg.in/DataDog/dd-trace-go.v1/internal/exectracetest

go 1.22.0

require (
	github.com/google/pprof v0.0.0-20230817174616-7a8ec2ada47b
	github.com/mattn/go-sqlite3 v1.14.18
	golang.org/x/exp v0.0.0-20240506185415-9bf2ced13842
	gopkg.in/DataDog/dd-trace-go.v1 v1.64.0
)

require (
	github.com/DataDog/appsec-internal-go v1.7.0 // indirect
	github.com/DataDog/datadog-agent/pkg/obfuscate v0.52.1 // indirect
	github.com/DataDog/datadog-agent/pkg/remoteconfig/state v0.52.1 // indirect
	github.com/DataDog/datadog-go/v5 v5.5.0 // indirect
	github.com/DataDog/dd-trace-go/contrib/database/sql/v2 v2.0.0-20240913143645-b075389b5aaf // indirect
	github.com/DataDog/dd-trace-go/v2 v2.0.0-20240918102525-7d4b68cbd85f // indirect
	github.com/DataDog/go-libddwaf/v3 v3.3.0 // indirect
	github.com/DataDog/go-sqllexer v0.0.11 // indirect
	github.com/DataDog/go-tuf v1.1.0-0.5.2 // indirect
	github.com/DataDog/sketches-go v1.4.6 // indirect
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/ebitengine/purego v0.7.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/outcaste-io/ristretto v0.2.3 // indirect
	github.com/philhofer/fwd v1.1.3-0.20240612014219-fbbf4953d986 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/secure-systems-lab/go-securesystemslib v0.8.0 // indirect
	github.com/tinylib/msgp v1.2.1 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	golang.org/x/mod v0.18.0 // indirect
	golang.org/x/sys v0.23.0 // indirect
	golang.org/x/time v0.5.0 // indirect
	golang.org/x/xerrors v0.0.0-20240716161551-93cc26a95ae9 // indirect
	google.golang.org/protobuf v1.34.2 // indirect
)

// use local version of dd-trace-go
replace gopkg.in/DataDog/dd-trace-go.v1 => ../..
