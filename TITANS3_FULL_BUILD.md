# TitanS3 - Complete Source Build Document

## Introduction

TitanS3 is a production-grade, S3-compatible object storage platform built from the ground up in Go. This document contains the complete source code for all components, services, libraries, deployment configurations, and documentation.

**Architecture Highlights:**
- Horizontally scalable API gateway with full S3 compatibility
- Metadata service backed by PostgreSQL/CockroachDB
- Distributed storage nodes with Reed-Solomon erasure coding (RS 8+4)
- SigV4 authentication with IAM-style policies
- Server-side encryption (SSE-S3, SSE-C)
- Lifecycle management, versioning, multipart uploads
- Background scrubbing, repair, and rebalancing
- Comprehensive observability (Prometheus, OpenTelemetry, structured logging)
- Admin CLI and web console

**Repository Structure:**
```
/titans3
  /cmd
    /gw        # API gateway service
    /node      # Storage node service
    /meta      # Metadata service orchestrator
    /titanctl  # CLI admin tool
  /pkg
    /api/s3    # S3 HTTP handlers and XML types
    /auth      # SigV4, access keys, policy evaluation
    /meta      # Database schemas, repositories, migrations
    /placement # Ring, rendezvous hashing, rebalancing
    /ec        # Reed-Solomon erasure coding
    /chunk     # Chunk I/O, small-file packing, checksums
    /kms       # Key management service interface
    /lifecycle # Lifecycle policy execution
    /replicate # Async replication workers
    /observe   # Metrics, tracing, logging
    /config    # Configuration management
    /utils     # Utility functions
  /deploy
    /compose   # Docker Compose for development
    /k8s       # Kubernetes manifests
  /docs        # Architecture and operations documentation
```

---

# PART 1: Core Infrastructure & Configuration

## File: go.mod

```go
// path: go.mod
module github.com/dadyutenga/bucket

go 1.22

require (
github.com/go-chi/chi/v5 v5.0.12
github.com/google/uuid v1.6.0
github.com/jackc/pgx/v5 v5.5.5
github.com/klauspost/reedsolomon v1.12.1
github.com/prometheus/client_golang v1.19.0
github.com/spf13/cobra v1.8.0
github.com/spf13/viper v1.18.2
go.opentelemetry.io/otel v1.24.0
go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.24.0
go.opentelemetry.io/otel/sdk v1.24.0
go.opentelemetry.io/otel/trace v1.24.0
golang.org/x/crypto v0.21.0
golang.org/x/sync v0.6.0
google.golang.org/grpc v1.62.1
google.golang.org/protobuf v1.33.0
gopkg.in/yaml.v3 v3.0.1
)

require (
github.com/beorn7/perks v1.0.1 // indirect
github.com/cenkalti/backoff/v4 v4.2.1 // indirect
github.com/cespare/xxhash/v2 v2.2.0 // indirect
github.com/fsnotify/fsnotify v1.7.0 // indirect
github.com/go-logr/logr v1.4.1 // indirect
github.com/go-logr/stdr v1.2.2 // indirect
github.com/golang/protobuf v1.5.4 // indirect
github.com/grpc-ecosystem/grpc-gateway/v2 v2.19.1 // indirect
github.com/hashicorp/hcl v1.0.0 // indirect
github.com/inconshreveable/mousetrap v1.1.0 // indirect
github.com/jackc/pgpassfile v1.0.0 // indirect
github.com/jackc/pgservicefile v0.0.0-20221227161230-091c0ba34f0a // indirect
github.com/jackc/puddle/v2 v2.2.1 // indirect
github.com/klauspost/cpuid/v2 v2.2.7 // indirect
github.com/magiconair/properties v1.8.7 // indirect
github.com/matttproud/golang_protobuf_extensions/v2 v2.0.0 // indirect
github.com/mitchellh/mapstructure v1.5.0 // indirect
github.com/pelletier/go-toml/v2 v2.1.0 // indirect
github.com/prometheus/client_model v0.6.0 // indirect
github.com/prometheus/common v0.48.0 // indirect
github.com/prometheus/procfs v0.12.0 // indirect
github.com/sagikazarmark/locafero v0.4.0 // indirect
github.com/sagikazarmark/slog-shim v0.1.0 // indirect
github.com/sourcegraph/conc v0.3.0 // indirect
github.com/spf13/afero v1.11.0 // indirect
github.com/spf13/cast v1.6.0 // indirect
github.com/spf13/pflag v1.0.5 // indirect
github.com/subosito/gotenv v1.6.0 // indirect
go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.24.0 // indirect
go.opentelemetry.io/otel/metric v1.24.0 // indirect
go.opentelemetry.io/proto/otlp v1.1.0 // indirect
go.uber.org/atomic v1.9.0 // indirect
go.uber.org/multierr v1.9.0 // indirect
golang.org/x/net v0.22.0 // indirect
golang.org/x/sys v0.18.0 // indirect
golang.org/x/text v0.14.0 // indirect
google.golang.org/genproto/googleapis/api v0.0.0-20240227224415-6ceb2ff114de // indirect
google.golang.org/genproto/googleapis/rpc v0.0.0-20240227224415-6ceb2ff114de // indirect
gopkg.in/ini.v1 v1.67.0 // indirect
)
```

## File: pkg/config/config.go

```go
// path: pkg/config/config.go
package config

import (
"fmt"
"os"
"time"

"github.com/spf13/viper"
)

// Config represents the complete TitanS3 configuration
type Config struct {
Service  ServiceConfig  `mapstructure:"service"`
Gateway  GatewayConfig  `mapstructure:"gateway"`
Node     NodeConfig     `mapstructure:"node"`
Meta     MetaConfig     `mapstructure:"meta"`
Storage  StorageConfig  `mapstructure:"storage"`
Security SecurityConfig `mapstructure:"security"`
Observ   ObservConfig   `mapstructure:"observability"`
}

// ServiceConfig contains common service configuration
type ServiceConfig struct {
Name        string `mapstructure:"name"`
Environment string `mapstructure:"environment"`
LogLevel    string `mapstructure:"log_level"`
Debug       bool   `mapstructure:"debug"`
}

// GatewayConfig contains API gateway specific configuration
type GatewayConfig struct {
Host           string        `mapstructure:"host"`
Port           int           `mapstructure:"port"`
ReadTimeout    time.Duration `mapstructure:"read_timeout"`
WriteTimeout   time.Duration `mapstructure:"write_timeout"`
MaxHeaderBytes int           `mapstructure:"max_header_bytes"`
EnableTLS      bool          `mapstructure:"enable_tls"`
TLSCert        string        `mapstructure:"tls_cert"`
TLSKey         string        `mapstructure:"tls_key"`

// S3 specific settings
EnablePathStyle    bool   `mapstructure:"enable_path_style"`
DefaultRegion      string `mapstructure:"default_region"`
MaxMultipartParts  int    `mapstructure:"max_multipart_parts"`
MaxObjectSize      int64  `mapstructure:"max_object_size"`
PresignedURLExpiry time.Duration `mapstructure:"presigned_url_expiry"`

// Backend connections
MetaServiceURL  string `mapstructure:"meta_service_url"`
NodeServiceURLs []string `mapstructure:"node_service_urls"`
}

// NodeConfig contains storage node specific configuration
type NodeConfig struct {
Host     string `mapstructure:"host"`
Port     int    `mapstructure:"port"`
GRPCPort int    `mapstructure:"grpc_port"`
NodeID   string `mapstructure:"node_id"`
DataPath string `mapstructure:"data_path"`

// Storage settings
MaxConcurrentWrites int   `mapstructure:"max_concurrent_writes"`
MaxConcurrentReads  int   `mapstructure:"max_concurrent_reads"`
BlockSize           int64 `mapstructure:"block_size"`
EnableMmap          bool  `mapstructure:"enable_mmap"`

// Health check
HealthCheckInterval time.Duration `mapstructure:"health_check_interval"`

// Repair and scrubbing
ScrubInterval       time.Duration `mapstructure:"scrub_interval"`
RepairWorkers       int           `mapstructure:"repair_workers"`
}

// MetaConfig contains metadata service configuration
type MetaConfig struct {
Host string `mapstructure:"host"`
Port int    `mapstructure:"port"`

// Database configuration
DBHost            string        `mapstructure:"db_host"`
DBPort            int           `mapstructure:"db_port"`
DBName            string        `mapstructure:"db_name"`
DBUser            string        `mapstructure:"db_user"`
DBPassword        string        `mapstructure:"db_password"`
DBSSLMode         string        `mapstructure:"db_ssl_mode"`
DBMaxConnections  int           `mapstructure:"db_max_connections"`
DBMaxIdleConns    int           `mapstructure:"db_max_idle_conns"`
DBConnMaxLifetime time.Duration `mapstructure:"db_conn_max_lifetime"`

// Migration settings
AutoMigrate bool `mapstructure:"auto_migrate"`
}

// StorageConfig contains storage layer configuration
type StorageConfig struct {
// Erasure coding parameters
ECDataShards   int `mapstructure:"ec_data_shards"`
ECParityShards int `mapstructure:"ec_parity_shards"`

// Placement
VirtualNodesPerNode int    `mapstructure:"virtual_nodes_per_node"`
ReplicationFactor   int    `mapstructure:"replication_factor"`
PlacementStrategy   string `mapstructure:"placement_strategy"` // "rendezvous" or "consistent_hash"

// Quorum settings
WriteQuorum int `mapstructure:"write_quorum"`
ReadQuorum  int `mapstructure:"read_quorum"`

// Small file optimization
SmallFileThreshold int64 `mapstructure:"small_file_threshold"`
EnablePacking      bool  `mapstructure:"enable_packing"`

// Checksums
ChecksumAlgorithm string `mapstructure:"checksum_algorithm"` // "crc32c" or "blake3"
}

// SecurityConfig contains security related configuration
type SecurityConfig struct {
// SigV4 settings
SignatureValidation bool          `mapstructure:"signature_validation"`
MaxClockSkew        time.Duration `mapstructure:"max_clock_skew"`

// Encryption
EnableSSES3     bool   `mapstructure:"enable_sse_s3"`
EnableSSEC      bool   `mapstructure:"enable_sse_c"`
KMSProvider     string `mapstructure:"kms_provider"` // "local", "vault", "aws"
KMSEndpoint     string `mapstructure:"kms_endpoint"`
KMSKeyID        string `mapstructure:"kms_key_id"`
MasterKeyPath   string `mapstructure:"master_key_path"`

// Access key storage
KeyHashingMemory uint32 `mapstructure:"key_hashing_memory"` // Argon2id memory in KB
KeyHashingTime   uint32 `mapstructure:"key_hashing_time"`   // Argon2id iterations
KeyHashingThreads uint8  `mapstructure:"key_hashing_threads"` // Argon2id parallelism

// TLS
MinTLSVersion string `mapstructure:"min_tls_version"`
CipherSuites  []string `mapstructure:"cipher_suites"`
}

// ObservConfig contains observability configuration
type ObservConfig struct {
// Metrics
EnableMetrics   bool   `mapstructure:"enable_metrics"`
MetricsPort     int    `mapstructure:"metrics_port"`
MetricsPath     string `mapstructure:"metrics_path"`

// Tracing
EnableTracing      bool    `mapstructure:"enable_tracing"`
TracingEndpoint    string  `mapstructure:"tracing_endpoint"`
TracingSampleRate  float64 `mapstructure:"tracing_sample_rate"`

// Logging
LogFormat       string `mapstructure:"log_format"` // "json" or "text"
LogOutput       string `mapstructure:"log_output"` // "stdout", "stderr", or file path
EnableAccessLog bool   `mapstructure:"enable_access_log"`
AccessLogPath   string `mapstructure:"access_log_path"`
}

// Load loads configuration from file and environment variables
func Load(configPath string) (*Config, error) {
v := viper.New()

// Set defaults
setDefaults(v)

// Read config file if provided
if configPath != "" {
v.SetConfigFile(configPath)
if err := v.ReadInConfig(); err != nil {
return nil, fmt.Errorf("failed to read config file: %w", err)
}
}

// Environment variables take precedence
v.SetEnvPrefix("TITANS3")
v.AutomaticEnv()

var cfg Config
if err := v.Unmarshal(&cfg); err != nil {
return nil, fmt.Errorf("failed to unmarshal config: %w", err)
}

// Validate configuration
if err := cfg.Validate(); err != nil {
return nil, fmt.Errorf("invalid configuration: %w", err)
}

return &cfg, nil
}

// setDefaults sets default configuration values
func setDefaults(v *viper.Viper) {
// Service defaults
v.SetDefault("service.name", "titans3")
v.SetDefault("service.environment", "development")
v.SetDefault("service.log_level", "info")
v.SetDefault("service.debug", false)

// Gateway defaults
v.SetDefault("gateway.host", "0.0.0.0")
v.SetDefault("gateway.port", 8080)
v.SetDefault("gateway.read_timeout", "5m")
v.SetDefault("gateway.write_timeout", "5m")
v.SetDefault("gateway.max_header_bytes", 1048576) // 1MB
v.SetDefault("gateway.enable_tls", false)
v.SetDefault("gateway.enable_path_style", true)
v.SetDefault("gateway.default_region", "us-east-1")
v.SetDefault("gateway.max_multipart_parts", 10000)
v.SetDefault("gateway.max_object_size", 5497558138880) // 5TB
v.SetDefault("gateway.presigned_url_expiry", "15m")
v.SetDefault("gateway.meta_service_url", "http://localhost:8081")

// Node defaults
v.SetDefault("node.host", "0.0.0.0")
v.SetDefault("node.port", 8082)
v.SetDefault("node.grpc_port", 9082)
v.SetDefault("node.node_id", getHostname())
v.SetDefault("node.data_path", "/var/lib/titans3/data")
v.SetDefault("node.max_concurrent_writes", 100)
v.SetDefault("node.max_concurrent_reads", 100)
v.SetDefault("node.block_size", 4194304) // 4MB
v.SetDefault("node.enable_mmap", true)
v.SetDefault("node.health_check_interval", "30s")
v.SetDefault("node.scrub_interval", "24h")
v.SetDefault("node.repair_workers", 4)

// Meta defaults
v.SetDefault("meta.host", "0.0.0.0")
v.SetDefault("meta.port", 8081)
v.SetDefault("meta.db_host", "localhost")
v.SetDefault("meta.db_port", 5432)
v.SetDefault("meta.db_name", "titans3")
v.SetDefault("meta.db_user", "titans3")
v.SetDefault("meta.db_password", "")
v.SetDefault("meta.db_ssl_mode", "prefer")
v.SetDefault("meta.db_max_connections", 100)
v.SetDefault("meta.db_max_idle_conns", 10)
v.SetDefault("meta.db_conn_max_lifetime", "1h")
v.SetDefault("meta.auto_migrate", true)

// Storage defaults
v.SetDefault("storage.ec_data_shards", 8)
v.SetDefault("storage.ec_parity_shards", 4)
v.SetDefault("storage.virtual_nodes_per_node", 256)
v.SetDefault("storage.replication_factor", 3)
v.SetDefault("storage.placement_strategy", "rendezvous")
v.SetDefault("storage.write_quorum", 9) // (8+4)*0.75
v.SetDefault("storage.read_quorum", 9)
v.SetDefault("storage.small_file_threshold", 65536) // 64KB
v.SetDefault("storage.enable_packing", true)
v.SetDefault("storage.checksum_algorithm", "crc32c")

// Security defaults
v.SetDefault("security.signature_validation", true)
v.SetDefault("security.max_clock_skew", "15m")
v.SetDefault("security.enable_sse_s3", true)
v.SetDefault("security.enable_sse_c", true)
v.SetDefault("security.kms_provider", "local")
v.SetDefault("security.master_key_path", "/etc/titans3/master.key")
v.SetDefault("security.key_hashing_memory", 65536) // 64MB
v.SetDefault("security.key_hashing_time", 3)
v.SetDefault("security.key_hashing_threads", 4)
v.SetDefault("security.min_tls_version", "1.2")

// Observability defaults
v.SetDefault("observability.enable_metrics", true)
v.SetDefault("observability.metrics_port", 9090)
v.SetDefault("observability.metrics_path", "/metrics")
v.SetDefault("observability.enable_tracing", true)
v.SetDefault("observability.tracing_endpoint", "localhost:4317")
v.SetDefault("observability.tracing_sample_rate", 0.1)
v.SetDefault("observability.log_format", "json")
v.SetDefault("observability.log_output", "stdout")
v.SetDefault("observability.enable_access_log", true)
v.SetDefault("observability.access_log_path", "/var/log/titans3/access.log")
}

// Validate validates the configuration
func (c *Config) Validate() error {
// Validate erasure coding parameters
totalShards := c.Storage.ECDataShards + c.Storage.ECParityShards
if c.Storage.ECDataShards < 1 {
return fmt.Errorf("ec_data_shards must be at least 1")
}
if c.Storage.ECParityShards < 1 {
return fmt.Errorf("ec_parity_shards must be at least 1")
}

// Validate quorum settings
if c.Storage.WriteQuorum < c.Storage.ECDataShards {
return fmt.Errorf("write_quorum must be at least ec_data_shards")
}
if c.Storage.WriteQuorum > totalShards {
return fmt.Errorf("write_quorum cannot exceed total shards")
}
if c.Storage.ReadQuorum < c.Storage.ECDataShards {
return fmt.Errorf("read_quorum must be at least ec_data_shards")
}

// Validate placement strategy
if c.Storage.PlacementStrategy != "rendezvous" && c.Storage.PlacementStrategy != "consistent_hash" {
return fmt.Errorf("invalid placement_strategy: %s", c.Storage.PlacementStrategy)
}

// Validate KMS provider
if c.Security.KMSProvider != "local" && c.Security.KMSProvider != "vault" && c.Security.KMSProvider != "aws" {
return fmt.Errorf("invalid kms_provider: %s", c.Security.KMSProvider)
}

// Validate checksum algorithm
if c.Storage.ChecksumAlgorithm != "crc32c" && c.Storage.ChecksumAlgorithm != "blake3" {
return fmt.Errorf("invalid checksum_algorithm: %s", c.Storage.ChecksumAlgorithm)
}

return nil
}

// getHostname returns the system hostname or a default value
func getHostname() string {
hostname, err := os.Hostname()
if err != nil {
return "unknown-host"
}
return hostname
}
```

## File: pkg/utils/errors.go

```go
// path: pkg/utils/errors.go
package utils

import (
"errors"
"fmt"
)

// Common error types
var (
// ErrNotFound indicates a requested resource was not found
ErrNotFound = errors.New("not found")

// ErrAlreadyExists indicates a resource already exists
ErrAlreadyExists = errors.New("already exists")

// ErrInvalidArgument indicates an invalid argument was provided
ErrInvalidArgument = errors.New("invalid argument")

// ErrUnauthorized indicates authentication failed
ErrUnauthorized = errors.New("unauthorized")

// ErrForbidden indicates the operation is not allowed
ErrForbidden = errors.New("forbidden")

// ErrConflict indicates a conflict with existing state
ErrConflict = errors.New("conflict")

// ErrInternal indicates an internal server error
ErrInternal = errors.New("internal error")

// ErrUnavailable indicates the service is unavailable
ErrUnavailable = errors.New("service unavailable")

// ErrTimeout indicates an operation timed out
ErrTimeout = errors.New("timeout")

// ErrQuorumNotMet indicates quorum requirements were not satisfied
ErrQuorumNotMet = errors.New("quorum not met")

// ErrChecksumMismatch indicates a checksum validation failure
ErrChecksumMismatch = errors.New("checksum mismatch")

// ErrInvalidSignature indicates signature validation failed
ErrInvalidSignature = errors.New("invalid signature")

// ErrExpiredSignature indicates a signature has expired
ErrExpiredSignature = errors.New("expired signature")
)

// ApplicationError represents a structured application error
type ApplicationError struct {
Code    string
Message string
Err     error
Details map[string]interface{}
}

// Error implements the error interface
func (e *ApplicationError) Error() string {
if e.Err != nil {
return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.Err)
}
return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap implements error unwrapping
func (e *ApplicationError) Unwrap() error {
return e.Err
}

// NewApplicationError creates a new application error
func NewApplicationError(code, message string, err error) *ApplicationError {
return &ApplicationError{
Code:    code,
Message: message,
Err:     err,
Details: make(map[string]interface{}),
}
}

// WithDetail adds a detail to the error
func (e *ApplicationError) WithDetail(key string, value interface{}) *ApplicationError {
e.Details[key] = value
return e
}

// IsNotFound checks if an error is a not found error
func IsNotFound(err error) bool {
return errors.Is(err, ErrNotFound)
}

// IsAlreadyExists checks if an error is an already exists error
func IsAlreadyExists(err error) bool {
return errors.Is(err, ErrAlreadyExists)
}

// IsUnauthorized checks if an error is an unauthorized error
func IsUnauthorized(err error) bool {
return errors.Is(err, ErrUnauthorized)
}

// IsForbidden checks if an error is a forbidden error
func IsForbidden(err error) bool {
return errors.Is(err, ErrForbidden)
}
```

## File: pkg/utils/hash.go

```go
// path: pkg/utils/hash.go
package utils

import (
"crypto/md5"
"crypto/sha256"
"encoding/base64"
"encoding/hex"
"fmt"
"hash/crc32"
"io"
)

// MD5Hash computes the MD5 hash of data
func MD5Hash(data []byte) string {
hash := md5.Sum(data)
return hex.EncodeToString(hash[:])
}

// MD5HashReader computes MD5 hash from a reader
func MD5HashReader(r io.Reader) (string, error) {
hasher := md5.New()
if _, err := io.Copy(hasher, r); err != nil {
return "", fmt.Errorf("failed to compute MD5: %w", err)
}
return hex.EncodeToString(hasher.Sum(nil)), nil
}

// SHA256Hash computes the SHA256 hash of data
func SHA256Hash(data []byte) string {
hash := sha256.Sum256(data)
return hex.EncodeToString(hash[:])
}

// SHA256HashReader computes SHA256 hash from a reader
func SHA256HashReader(r io.Reader) (string, error) {
hasher := sha256.New()
if _, err := io.Copy(hasher, r); err != nil {
return "", fmt.Errorf("failed to compute SHA256: %w", err)
}
return hex.EncodeToString(hasher.Sum(nil)), nil
}

// CRC32CHash computes CRC32C checksum
func CRC32CHash(data []byte) uint32 {
table := crc32.MakeTable(crc32.Castagnoli)
return crc32.Checksum(data, table)
}

// Base64Encode encodes data to base64
func Base64Encode(data []byte) string {
return base64.StdEncoding.EncodeToString(data)
}

// Base64Decode decodes base64 data
func Base64Decode(s string) ([]byte, error) {
return base64.StdEncoding.DecodeString(s)
}

// HexEncode encodes data to hexadecimal
func HexEncode(data []byte) string {
return hex.EncodeToString(data)
}

// HexDecode decodes hexadecimal data
func HexDecode(s string) ([]byte, error) {
return hex.DecodeString(s)
}

// ETagFromMD5 creates an ETag from MD5 hash
func ETagFromMD5(md5Hash string) string {
return fmt.Sprintf(`"%s"`, md5Hash)
}

// MultipartETag creates an ETag for multipart uploads
func MultipartETag(partMD5s []string) string {
// Concatenate all part MD5s and hash them
combined := ""
for _, md5 := range partMD5s {
combined += md5
}
finalHash := MD5Hash([]byte(combined))
return fmt.Sprintf(`"%s-%d"`, finalHash, len(partMD5s))
}
```

## File: pkg/utils/time.go

```go
// path: pkg/utils/time.go
package utils

import (
"time"
)

// TimeNow returns the current time (can be mocked for testing)
var TimeNow = time.Now

// FormatISO8601 formats a time in ISO8601 format
func FormatISO8601(t time.Time) string {
return t.UTC().Format("20060102T150405Z")
}

// ParseISO8601 parses an ISO8601 formatted time
func ParseISO8601(s string) (time.Time, error) {
return time.Parse("20060102T150405Z", s)
}

// FormatRFC1123 formats a time in RFC1123 format (HTTP Date header)
func FormatRFC1123(t time.Time) string {
return t.UTC().Format(time.RFC1123)
}

// ParseRFC1123 parses an RFC1123 formatted time
func ParseRFC1123(s string) (time.Time, error) {
return time.Parse(time.RFC1123, s)
}

// IsWithinSkew checks if a time is within the allowed clock skew
func IsWithinSkew(t time.Time, skew time.Duration) bool {
now := TimeNow()
diff := now.Sub(t)
if diff < 0 {
diff = -diff
}
return diff <= skew
}

// ExpiresAt returns a time in the future
func ExpiresAt(duration time.Duration) time.Time {
return TimeNow().Add(duration)
}

// IsExpired checks if a time is in the past
func IsExpired(t time.Time) bool {
return TimeNow().After(t)
}
```

## File: pkg/utils/xml.go

```go
// path: pkg/utils/xml.go
package utils

import (
"encoding/xml"
"fmt"
"io"
)

// XMLHeader is the standard XML header
const XMLHeader = `<?xml version="1.0" encoding="UTF-8"?>`

// MarshalXML marshals a value to XML with header
func MarshalXML(v interface{}) ([]byte, error) {
data, err := xml.MarshalIndent(v, "", "  ")
if err != nil {
return nil, fmt.Errorf("failed to marshal XML: %w", err)
}
return append([]byte(XMLHeader+"\n"), data...), nil
}

// UnmarshalXML unmarshals XML data
func UnmarshalXML(data []byte, v interface{}) error {
if err := xml.Unmarshal(data, v); err != nil {
return fmt.Errorf("failed to unmarshal XML: %w", err)
}
return nil
}

// UnmarshalXMLReader unmarshals XML from a reader
func UnmarshalXMLReader(r io.Reader, v interface{}) error {
decoder := xml.NewDecoder(r)
if err := decoder.Decode(v); err != nil {
return fmt.Errorf("failed to decode XML: %w", err)
}
return nil
}

// EncodeXMLResponse encodes an XML response to a writer
func EncodeXMLResponse(w io.Writer, v interface{}) error {
if _, err := w.Write([]byte(XMLHeader + "\n")); err != nil {
return fmt.Errorf("failed to write XML header: %w", err)
}

encoder := xml.NewEncoder(w)
encoder.Indent("", "  ")
if err := encoder.Encode(v); err != nil {
return fmt.Errorf("failed to encode XML: %w", err)
}

return nil
}
```

## File: pkg/utils/http.go

```go
// path: pkg/utils/http.go
package utils

import (
"fmt"
"net/http"
"strconv"
"strings"
)

// ParseRangeHeader parses the HTTP Range header
func ParseRangeHeader(rangeHeader string, size int64) (start, end int64, err error) {
if rangeHeader == "" {
return 0, size - 1, nil
}

// Format: bytes=start-end
const prefix = "bytes="
if !strings.HasPrefix(rangeHeader, prefix) {
return 0, 0, fmt.Errorf("invalid range header format")
}

rangeSpec := strings.TrimPrefix(rangeHeader, prefix)
parts := strings.Split(rangeSpec, "-")
if len(parts) != 2 {
return 0, 0, fmt.Errorf("invalid range specification")
}

// Parse start
if parts[0] != "" {
start, err = strconv.ParseInt(parts[0], 10, 64)
if err != nil {
return 0, 0, fmt.Errorf("invalid start position: %w", err)
}
}

// Parse end
if parts[1] != "" {
end, err = strconv.ParseInt(parts[1], 10, 64)
if err != nil {
return 0, 0, fmt.Errorf("invalid end position: %w", err)
}
} else {
end = size - 1
}

// Validate range
if start < 0 || end >= size || start > end {
return 0, 0, fmt.Errorf("range not satisfiable")
}

return start, end, nil
}

// ContentRangeHeader generates a Content-Range header value
func ContentRangeHeader(start, end, total int64) string {
return fmt.Sprintf("bytes %d-%d/%d", start, end, total)
}

// GetQueryParam extracts a query parameter from request
func GetQueryParam(r *http.Request, key string) string {
return r.URL.Query().Get(key)
}

// GetQueryParams extracts multiple values for a query parameter
func GetQueryParams(r *http.Request, key string) []string {
return r.URL.Query()[key]
}

// GetHeader extracts a header value from request
func GetHeader(r *http.Request, key string) string {
return r.Header.Get(key)
}

// SetCORSHeaders sets CORS headers on response
func SetCORSHeaders(w http.ResponseWriter, origin string, methods []string) {
if origin != "" {
w.Header().Set("Access-Control-Allow-Origin", origin)
}
if len(methods) > 0 {
w.Header().Set("Access-Control-Allow-Methods", strings.Join(methods, ", "))
}
w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Amz-*")
w.Header().Set("Access-Control-Max-Age", "3600")
}

// WriteJSONError writes a JSON error response
func WriteJSONError(w http.ResponseWriter, statusCode int, code, message string) {
w.Header().Set("Content-Type", "application/json")
w.WriteHeader(statusCode)
fmt.Fprintf(w, `{"error":{"code":"%s","message":"%s"}}`, code, message)
}

// WriteXMLError writes an XML error response in S3 format
func WriteXMLError(w http.ResponseWriter, statusCode int, code, message, resource, requestID string) {
w.Header().Set("Content-Type", "application/xml")
w.WriteHeader(statusCode)
fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>%s</Code>
  <Message>%s</Message>
  <Resource>%s</Resource>
  <RequestId>%s</RequestId>
</Error>`, code, message, resource, requestID)
}
```

## File: pkg/utils/strings.go

```go
// path: pkg/utils/strings.go
package utils

import (
"strings"
"unicode"
)

// IsValidBucketName validates an S3 bucket name
func IsValidBucketName(name string) bool {
if len(name) < 3 || len(name) > 63 {
return false
}

// Must start and end with lowercase letter or number
if !isLowerAlphaNum(rune(name[0])) || !isLowerAlphaNum(rune(name[len(name)-1])) {
return false
}

// Can contain lowercase letters, numbers, dots, and hyphens
// Cannot contain two adjacent dots or a dot adjacent to a hyphen
prevDot := false
for i, c := range name {
if c == '.' {
if prevDot || (i > 0 && name[i-1] == '-') || (i < len(name)-1 && name[i+1] == '-') {
return false
}
prevDot = true
} else if c == '-' {
prevDot = false
} else if !isLowerAlphaNum(c) {
return false
} else {
prevDot = false
}
}

// Cannot look like an IP address
parts := strings.Split(name, ".")
if len(parts) == 4 {
isIP := true
for _, part := range parts {
if len(part) == 0 || len(part) > 3 {
isIP = false
break
}
for _, c := range part {
if !unicode.IsDigit(c) {
isIP = false
break
}
}
}
if isIP {
return false
}
}

return true
}

// isLowerAlphaNum checks if a rune is a lowercase letter or digit
func isLowerAlphaNum(c rune) bool {
return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
}

// IsValidObjectKey validates an S3 object key
func IsValidObjectKey(key string) bool {
if len(key) == 0 || len(key) > 1024 {
return false
}
// Object keys can contain any UTF-8 character
return true
}

// SanitizeString removes potentially dangerous characters
func SanitizeString(s string) string {
return strings.Map(func(r rune) rune {
if unicode.IsPrint(r) {
return r
}
return -1
}, s)
}

// TrimPathSlashes removes leading and trailing slashes from a path
func TrimPathSlashes(path string) string {
return strings.Trim(path, "/")
}

// NormalizePath normalizes a path by removing redundant slashes
func NormalizePath(path string) string {
parts := strings.Split(path, "/")
normalized := make([]string, 0, len(parts))

for _, part := range parts {
if part != "" && part != "." {
if part == ".." && len(normalized) > 0 {
normalized = normalized[:len(normalized)-1]
} else if part != ".." {
normalized = append(normalized, part)
}
}
}

return strings.Join(normalized, "/")
}

// JoinPath joins path segments
func JoinPath(segments ...string) string {
var result strings.Builder
for i, seg := range segments {
if i > 0 && !strings.HasPrefix(seg, "/") {
result.WriteString("/")
}
result.WriteString(strings.Trim(seg, "/"))
}
return result.String()
}
```

---

# PART 2: Observability Infrastructure

## File: pkg/observe/logger.go

```go
// path: pkg/observe/logger.go
package observe

import (
"context"
"encoding/json"
"fmt"
"io"
"log/slog"
"os"
"time"

"github.com/google/uuid"
)

// ContextKey type for context keys
type ContextKey string

const (
// RequestIDKey is the context key for request ID
RequestIDKey ContextKey = "request_id"

// TraceIDKey is the context key for trace ID
TraceIDKey ContextKey = "trace_id"

// UserIDKey is the context key for user ID
UserIDKey ContextKey = "user_id"
)

// Logger provides structured logging capabilities
type Logger struct {
logger *slog.Logger
level  slog.Level
}

// NewLogger creates a new logger
func NewLogger(format string, output io.Writer, level string) *Logger {
var handler slog.Handler

logLevel := parseLevel(level)

opts := &slog.HandlerOptions{
Level: logLevel,
AddSource: true,
}

if format == "json" {
handler = slog.NewJSONHandler(output, opts)
} else {
handler = slog.NewTextHandler(output, opts)
}

return &Logger{
logger: slog.New(handler),
level:  logLevel,
}
}

// parseLevel converts string level to slog.Level
func parseLevel(level string) slog.Level {
switch level {
case "debug":
return slog.LevelDebug
case "info":
return slog.LevelInfo
case "warn", "warning":
return slog.LevelWarn
case "error":
return slog.LevelError
default:
return slog.LevelInfo
}
}

// WithContext adds context information to the logger
func (l *Logger) WithContext(ctx context.Context) *Logger {
attrs := []any{}

if requestID := ctx.Value(RequestIDKey); requestID != nil {
attrs = append(attrs, slog.String("request_id", requestID.(string)))
}

if traceID := ctx.Value(TraceIDKey); traceID != nil {
attrs = append(attrs, slog.String("trace_id", traceID.(string)))
}

if userID := ctx.Value(UserIDKey); userID != nil {
attrs = append(attrs, slog.String("user_id", userID.(string)))
}

return &Logger{
logger: l.logger.With(attrs...),
level:  l.level,
}
}

// Debug logs a debug message
func (l *Logger) Debug(msg string, args ...any) {
l.logger.Debug(msg, args...)
}

// Info logs an info message
func (l *Logger) Info(msg string, args ...any) {
l.logger.Info(msg, args...)
}

// Warn logs a warning message
func (l *Logger) Warn(msg string, args ...any) {
l.logger.Warn(msg, args...)
}

// Error logs an error message
func (l *Logger) Error(msg string, args ...any) {
l.logger.Error(msg, args...)
}

// With adds fields to the logger
func (l *Logger) With(args ...any) *Logger {
return &Logger{
logger: l.logger.With(args...),
level:  l.level,
}
}

// AccessLog represents an HTTP access log entry
type AccessLog struct {
Timestamp     time.Time         `json:"timestamp"`
RequestID     string            `json:"request_id"`
Method        string            `json:"method"`
Path          string            `json:"path"`
Query         string            `json:"query,omitempty"`
StatusCode    int               `json:"status_code"`
Duration      time.Duration     `json:"duration_ms"`
BytesRead     int64             `json:"bytes_read"`
BytesWritten  int64             `json:"bytes_written"`
UserAgent     string            `json:"user_agent,omitempty"`
RemoteAddr    string            `json:"remote_addr"`
AccessKey     string            `json:"access_key,omitempty"`
Bucket        string            `json:"bucket,omitempty"`
ObjectKey     string            `json:"object_key,omitempty"`
Error         string            `json:"error,omitempty"`
CustomFields  map[string]string `json:"custom_fields,omitempty"`
}

// AccessLogger handles access logging
type AccessLogger struct {
output io.Writer
}

// NewAccessLogger creates a new access logger
func NewAccessLogger(output io.Writer) *AccessLogger {
return &AccessLogger{output: output}
}

// Log writes an access log entry
func (al *AccessLogger) Log(entry *AccessLog) error {
data, err := json.Marshal(entry)
if err != nil {
return fmt.Errorf("failed to marshal access log: %w", err)
}

_, err = fmt.Fprintf(al.output, "%s\n", data)
return err
}

// NewRequestID generates a new request ID
func NewRequestID() string {
return uuid.New().String()
}

// ContextWithRequestID adds a request ID to context
func ContextWithRequestID(ctx context.Context, requestID string) context.Context {
return context.WithValue(ctx, RequestIDKey, requestID)
}

// GetRequestID extracts request ID from context
func GetRequestID(ctx context.Context) string {
if requestID := ctx.Value(RequestIDKey); requestID != nil {
return requestID.(string)
}
return ""
}

// DefaultLogger is the default application logger
var DefaultLogger = NewLogger("json", os.Stdout, "info")
```

## File: pkg/observe/metrics.go

```go
// path: pkg/observe/metrics.go
package observe

import (
"github.com/prometheus/client_golang/prometheus"
"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics holds all Prometheus metrics for TitanS3
type Metrics struct {
// HTTP metrics
HTTPRequestsTotal       *prometheus.CounterVec
HTTPRequestDuration     *prometheus.HistogramVec
HTTPRequestSize         *prometheus.HistogramVec
HTTPResponseSize        *prometheus.HistogramVec
HTTPActiveRequests      *prometheus.GaugeVec

// S3 API metrics
S3OperationsTotal       *prometheus.CounterVec
S3OperationDuration     *prometheus.HistogramVec
S3ObjectsTotal          prometheus.Gauge
S3BucketsTotal          prometheus.Gauge
S3BytesStored           prometheus.Gauge

// Storage metrics
StorageNodeHealth       *prometheus.GaugeVec
StorageShardWrites      *prometheus.CounterVec
StorageShardReads       *prometheus.CounterVec
StorageShardErrors      *prometheus.CounterVec
StorageDiskUsage        *prometheus.GaugeVec
StorageDiskFree         *prometheus.GaugeVec

// Erasure coding metrics
ECEncodeOperations      *prometheus.CounterVec
ECDecodeOperations      *prometheus.CounterVec
ECEncodeDuration        *prometheus.HistogramVec
ECDecodeDuration        *prometheus.HistogramVec
ECReconstructions       *prometheus.CounterVec

// Metadata metrics
MetaDBConnections       prometheus.Gauge
MetaDBQueries           *prometheus.CounterVec
MetaDBQueryDuration     *prometheus.HistogramVec
MetaDBErrors            *prometheus.CounterVec

// Cache metrics
CacheHits               *prometheus.CounterVec
CacheMisses             *prometheus.CounterVec
CacheEvictions          *prometheus.CounterVec
CacheSize               *prometheus.GaugeVec

// Background job metrics
ScrubOperations         *prometheus.CounterVec
RepairOperations        *prometheus.CounterVec
LifecycleRuns           *prometheus.CounterVec
ReplicationLag          *prometheus.GaugeVec

// Auth metrics
AuthAttempts            *prometheus.CounterVec
AuthFailures            *prometheus.CounterVec
PolicyEvaluations       *prometheus.CounterVec
}

// NewMetrics creates and registers all metrics
func NewMetrics(namespace string) *Metrics {
return &Metrics{
// HTTP metrics
HTTPRequestsTotal: promauto.NewCounterVec(
prometheus.CounterOpts{
Namespace: namespace,
Name:      "http_requests_total",
Help:      "Total number of HTTP requests",
},
[]string{"method", "path", "status"},
),
HTTPRequestDuration: promauto.NewHistogramVec(
prometheus.HistogramOpts{
Namespace: namespace,
Name:      "http_request_duration_seconds",
Help:      "HTTP request duration in seconds",
Buckets:   prometheus.ExponentialBuckets(0.001, 2, 15),
},
[]string{"method", "path", "status"},
),
HTTPRequestSize: promauto.NewHistogramVec(
prometheus.HistogramOpts{
Namespace: namespace,
Name:      "http_request_size_bytes",
Help:      "HTTP request size in bytes",
Buckets:   prometheus.ExponentialBuckets(100, 10, 8),
},
[]string{"method", "path"},
),
HTTPResponseSize: promauto.NewHistogramVec(
prometheus.HistogramOpts{
Namespace: namespace,
Name:      "http_response_size_bytes",
Help:      "HTTP response size in bytes",
Buckets:   prometheus.ExponentialBuckets(100, 10, 8),
},
[]string{"method", "path"},
),
HTTPActiveRequests: promauto.NewGaugeVec(
prometheus.GaugeOpts{
Namespace: namespace,
Name:      "http_active_requests",
Help:      "Number of active HTTP requests",
},
[]string{"method"},
),

// S3 API metrics
S3OperationsTotal: promauto.NewCounterVec(
prometheus.CounterOpts{
Namespace: namespace,
Name:      "s3_operations_total",
Help:      "Total number of S3 operations",
},
[]string{"operation", "bucket", "status"},
),
S3OperationDuration: promauto.NewHistogramVec(
prometheus.HistogramOpts{
Namespace: namespace,
Name:      "s3_operation_duration_seconds",
Help:      "S3 operation duration in seconds",
Buckets:   prometheus.ExponentialBuckets(0.001, 2, 15),
},
[]string{"operation", "bucket"},
),
S3ObjectsTotal: promauto.NewGauge(
prometheus.GaugeOpts{
Namespace: namespace,
Name:      "s3_objects_total",
Help:      "Total number of S3 objects",
},
),
S3BucketsTotal: promauto.NewGauge(
prometheus.GaugeOpts{
Namespace: namespace,
Name:      "s3_buckets_total",
Help:      "Total number of S3 buckets",
},
),
S3BytesStored: promauto.NewGauge(
prometheus.GaugeOpts{
Namespace: namespace,
Name:      "s3_bytes_stored",
Help:      "Total bytes stored",
},
),

// Storage metrics
StorageNodeHealth: promauto.NewGaugeVec(
prometheus.GaugeOpts{
Namespace: namespace,
Name:      "storage_node_health",
Help:      "Storage node health status (1=healthy, 0=unhealthy)",
},
[]string{"node_id"},
),
StorageShardWrites: promauto.NewCounterVec(
prometheus.CounterOpts{
Namespace: namespace,
Name:      "storage_shard_writes_total",
Help:      "Total number of shard writes",
},
[]string{"node_id", "status"},
),
StorageShardReads: promauto.NewCounterVec(
prometheus.CounterOpts{
Namespace: namespace,
Name:      "storage_shard_reads_total",
Help:      "Total number of shard reads",
},
[]string{"node_id", "status"},
),
StorageShardErrors: promauto.NewCounterVec(
prometheus.CounterOpts{
Namespace: namespace,
Name:      "storage_shard_errors_total",
Help:      "Total number of shard errors",
},
[]string{"node_id", "operation", "error_type"},
),
StorageDiskUsage: promauto.NewGaugeVec(
prometheus.GaugeOpts{
Namespace: namespace,
Name:      "storage_disk_usage_bytes",
Help:      "Disk usage in bytes",
},
[]string{"node_id", "volume"},
),
StorageDiskFree: promauto.NewGaugeVec(
prometheus.GaugeOpts{
Namespace: namespace,
Name:      "storage_disk_free_bytes",
Help:      "Free disk space in bytes",
},
[]string{"node_id", "volume"},
),

// Erasure coding metrics
ECEncodeOperations: promauto.NewCounterVec(
prometheus.CounterOpts{
Namespace: namespace,
Name:      "ec_encode_operations_total",
Help:      "Total number of erasure encode operations",
},
[]string{"status"},
),
ECDecodeOperations: promauto.NewCounterVec(
prometheus.CounterOpts{
Namespace: namespace,
Name:      "ec_decode_operations_total",
Help:      "Total number of erasure decode operations",
},
[]string{"status"},
),
ECEncodeDuration: promauto.NewHistogramVec(
prometheus.HistogramOpts{
Namespace: namespace,
Name:      "ec_encode_duration_seconds",
Help:      "Erasure encode duration in seconds",
Buckets:   prometheus.ExponentialBuckets(0.001, 2, 12),
},
[]string{},
),
ECDecodeDuration: promauto.NewHistogramVec(
prometheus.HistogramOpts{
Namespace: namespace,
Name:      "ec_decode_duration_seconds",
Help:      "Erasure decode duration in seconds",
Buckets:   prometheus.ExponentialBuckets(0.001, 2, 12),
},
[]string{},
),
ECReconstructions: promauto.NewCounterVec(
prometheus.CounterOpts{
Namespace: namespace,
Name:      "ec_reconstructions_total",
Help:      "Total number of data reconstructions",
},
[]string{"reason"},
),

// Metadata metrics
MetaDBConnections: promauto.NewGauge(
prometheus.GaugeOpts{
Namespace: namespace,
Name:      "meta_db_connections",
Help:      "Number of active database connections",
},
),
MetaDBQueries: promauto.NewCounterVec(
prometheus.CounterOpts{
Namespace: namespace,
Name:      "meta_db_queries_total",
Help:      "Total number of database queries",
},
[]string{"query_type", "status"},
),
MetaDBQueryDuration: promauto.NewHistogramVec(
prometheus.HistogramOpts{
Namespace: namespace,
Name:      "meta_db_query_duration_seconds",
Help:      "Database query duration in seconds",
Buckets:   prometheus.ExponentialBuckets(0.0001, 2, 15),
},
[]string{"query_type"},
),
MetaDBErrors: promauto.NewCounterVec(
prometheus.CounterOpts{
Namespace: namespace,
Name:      "meta_db_errors_total",
Help:      "Total number of database errors",
},
[]string{"error_type"},
),

// Cache metrics
CacheHits: promauto.NewCounterVec(
prometheus.CounterOpts{
Namespace: namespace,
Name:      "cache_hits_total",
Help:      "Total number of cache hits",
},
[]string{"cache_name"},
),
CacheMisses: promauto.NewCounterVec(
prometheus.CounterOpts{
Namespace: namespace,
Name:      "cache_misses_total",
Help:      "Total number of cache misses",
},
[]string{"cache_name"},
),
CacheEvictions: promauto.NewCounterVec(
prometheus.CounterOpts{
Namespace: namespace,
Name:      "cache_evictions_total",
Help:      "Total number of cache evictions",
},
[]string{"cache_name", "reason"},
),
CacheSize: promauto.NewGaugeVec(
prometheus.GaugeOpts{
Namespace: namespace,
Name:      "cache_size_bytes",
Help:      "Cache size in bytes",
},
[]string{"cache_name"},
),

// Background job metrics
ScrubOperations: promauto.NewCounterVec(
prometheus.CounterOpts{
Namespace: namespace,
Name:      "scrub_operations_total",
Help:      "Total number of scrub operations",
},
[]string{"status"},
),
RepairOperations: promauto.NewCounterVec(
prometheus.CounterOpts{
Namespace: namespace,
Name:      "repair_operations_total",
Help:      "Total number of repair operations",
},
[]string{"status"},
),
LifecycleRuns: promauto.NewCounterVec(
prometheus.CounterOpts{
Namespace: namespace,
Name:      "lifecycle_runs_total",
Help:      "Total number of lifecycle runs",
},
[]string{"rule_type", "status"},
),
ReplicationLag: promauto.NewGaugeVec(
prometheus.GaugeOpts{
Namespace: namespace,
Name:      "replication_lag_seconds",
Help:      "Replication lag in seconds",
},
[]string{"source", "destination"},
),

// Auth metrics
AuthAttempts: promauto.NewCounterVec(
prometheus.CounterOpts{
Namespace: namespace,
Name:      "auth_attempts_total",
Help:      "Total number of authentication attempts",
},
[]string{"method", "status"},
),
AuthFailures: promauto.NewCounterVec(
prometheus.CounterOpts{
Namespace: namespace,
Name:      "auth_failures_total",
Help:      "Total number of authentication failures",
},
[]string{"method", "reason"},
),
PolicyEvaluations: promauto.NewCounterVec(
prometheus.CounterOpts{
Namespace: namespace,
Name:      "policy_evaluations_total",
Help:      "Total number of policy evaluations",
},
[]string{"effect", "action"},
),
}
}
```


## File: pkg/observe/tracing.go

```go
// path: pkg/observe/tracing.go
package observe

import (
"context"
"fmt"

"go.opentelemetry.io/otel"
"go.opentelemetry.io/otel/attribute"
"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
"go.opentelemetry.io/otel/propagation"
"go.opentelemetry.io/otel/sdk/resource"
sdktrace "go.opentelemetry.io/otel/sdk/trace"
semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
"go.opentelemetry.io/otel/trace"
)

// Tracer wraps OpenTelemetry tracer
type Tracer struct {
provider *sdktrace.TracerProvider
tracer   trace.Tracer
}

// NewTracer creates a new tracer
func NewTracer(serviceName, endpoint string, sampleRate float64) (*Tracer, error) {
ctx := context.Background()

// Create OTLP exporter
exporter, err := otlptracegrpc.New(ctx,
otlptracegrpc.WithEndpoint(endpoint),
otlptracegrpc.WithInsecure(),
)
if err != nil {
return nil, fmt.Errorf("failed to create OTLP exporter: %w", err)
}

// Create resource
res, err := resource.New(ctx,
resource.WithAttributes(
semconv.ServiceName(serviceName),
),
)
if err != nil {
return nil, fmt.Errorf("failed to create resource: %w", err)
}

// Create tracer provider
tp := sdktrace.NewTracerProvider(
sdktrace.WithBatcher(exporter),
sdktrace.WithResource(res),
sdktrace.WithSampler(sdktrace.TraceIDRatioBased(sampleRate)),
)

// Register as global tracer provider
otel.SetTracerProvider(tp)
otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
propagation.TraceContext{},
propagation.Baggage{},
))

tracer := tp.Tracer(serviceName)

return &Tracer{
provider: tp,
tracer:   tracer,
}, nil
}

// Start starts a new span
func (t *Tracer) Start(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
return t.tracer.Start(ctx, name, opts...)
}

// Shutdown shuts down the tracer
func (t *Tracer) Shutdown(ctx context.Context) error {
return t.provider.Shutdown(ctx)
}

// AddEvent adds an event to the current span
func AddEvent(ctx context.Context, name string, attrs ...attribute.KeyValue) {
span := trace.SpanFromContext(ctx)
span.AddEvent(name, trace.WithAttributes(attrs...))
}

// SetAttributes sets attributes on the current span
func SetAttributes(ctx context.Context, attrs ...attribute.KeyValue) {
span := trace.SpanFromContext(ctx)
span.SetAttributes(attrs...)
}

// RecordError records an error on the current span
func RecordError(ctx context.Context, err error, opts ...trace.EventOption) {
span := trace.SpanFromContext(ctx)
span.RecordError(err, opts...)
}

// SetStatus sets the status of the current span
func SetStatus(ctx context.Context, code trace.StatusCode, description string) {
span := trace.SpanFromContext(ctx)
span.SetStatus(code, description)
}
```

## File: pkg/observe/middleware.go

```go
// path: pkg/observe/middleware.go
package observe

import (
"net/http"
"time"

"go.opentelemetry.io/otel/attribute"
"go.opentelemetry.io/otel/trace"
)

// responseWriter wraps http.ResponseWriter to capture status and size
type responseWriter struct {
http.ResponseWriter
statusCode   int
bytesWritten int64
}

// WriteHeader captures the status code
func (rw *responseWriter) WriteHeader(code int) {
rw.statusCode = code
rw.ResponseWriter.WriteHeader(code)
}

// Write captures bytes written
func (rw *responseWriter) Write(b []byte) (int, error) {
n, err := rw.ResponseWriter.Write(b)
rw.bytesWritten += int64(n)
return n, err
}

// LoggingMiddleware logs HTTP requests
func LoggingMiddleware(logger *Logger) func(http.Handler) http.Handler {
return func(next http.Handler) http.Handler {
return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
start := time.Now()
requestID := NewRequestID()
ctx := ContextWithRequestID(r.Context(), requestID)
r = r.WithContext(ctx)

// Wrap response writer
rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

// Process request
next.ServeHTTP(rw, r)

// Log request
duration := time.Since(start)
logger.WithContext(ctx).Info("http_request",
"method", r.Method,
"path", r.URL.Path,
"status", rw.statusCode,
"duration_ms", duration.Milliseconds(),
"bytes_written", rw.bytesWritten,
"user_agent", r.UserAgent(),
"remote_addr", r.RemoteAddr,
)
})
}
}

// MetricsMiddleware records metrics for HTTP requests
func MetricsMiddleware(metrics *Metrics) func(http.Handler) http.Handler {
return func(next http.Handler) http.Handler {
return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
start := time.Now()

// Wrap response writer
rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

// Track active requests
metrics.HTTPActiveRequests.WithLabelValues(r.Method).Inc()
defer metrics.HTTPActiveRequests.WithLabelValues(r.Method).Dec()

// Process request
next.ServeHTTP(rw, r)

// Record metrics
duration := time.Since(start).Seconds()
labels := []string{r.Method, r.URL.Path, http.StatusText(rw.statusCode)}

metrics.HTTPRequestsTotal.WithLabelValues(labels...).Inc()
metrics.HTTPRequestDuration.WithLabelValues(labels...).Observe(duration)
metrics.HTTPRequestSize.WithLabelValues(r.Method, r.URL.Path).Observe(float64(r.ContentLength))
metrics.HTTPResponseSize.WithLabelValues(r.Method, r.URL.Path).Observe(float64(rw.bytesWritten))
})
}
}

// TracingMiddleware adds distributed tracing to HTTP requests
func TracingMiddleware(tracer *Tracer, serviceName string) func(http.Handler) http.Handler {
return func(next http.Handler) http.Handler {
return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
ctx := r.Context()

// Start span
ctx, span := tracer.Start(ctx, r.Method+" "+r.URL.Path,
trace.WithAttributes(
attribute.String("http.method", r.Method),
attribute.String("http.url", r.URL.String()),
attribute.String("http.user_agent", r.UserAgent()),
attribute.String("http.remote_addr", r.RemoteAddr),
),
)
defer span.End()

// Wrap response writer
rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

// Process request
next.ServeHTTP(rw, r.WithContext(ctx))

// Add response attributes
span.SetAttributes(
attribute.Int("http.status_code", rw.statusCode),
attribute.Int64("http.response_size", rw.bytesWritten),
)

// Set span status based on HTTP status code
if rw.statusCode >= 400 {
span.SetStatus(trace.StatusError, http.StatusText(rw.statusCode))
}
})
}
}

// RecoveryMiddleware recovers from panics
func RecoveryMiddleware(logger *Logger) func(http.Handler) http.Handler {
return func(next http.Handler) http.Handler {
return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
defer func() {
if err := recover(); err != nil {
logger.Error("panic recovered",
"error", err,
"path", r.URL.Path,
"method", r.Method,
)
http.Error(w, "Internal Server Error", http.StatusInternalServerError)
}
}()
next.ServeHTTP(w, r)
})
}
}

// CORSMiddleware adds CORS headers
func CORSMiddleware(allowedOrigins []string) func(http.Handler) http.Handler {
return func(next http.Handler) http.Handler {
return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
origin := r.Header.Get("Origin")

// Check if origin is allowed
allowed := false
for _, allowedOrigin := range allowedOrigins {
if allowedOrigin == "*" || allowedOrigin == origin {
allowed = true
break
}
}

if allowed {
w.Header().Set("Access-Control-Allow-Origin", origin)
w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, HEAD, OPTIONS")
w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Amz-*, Range")
w.Header().Set("Access-Control-Expose-Headers", "ETag, Content-Range, Accept-Ranges")
w.Header().Set("Access-Control-Max-Age", "3600")
}

// Handle preflight
if r.Method == "OPTIONS" {
w.WriteHeader(http.StatusOK)
return
}

next.ServeHTTP(w, r)
})
}
}
```

---

# PART 3: Authentication & Authorization

## File: pkg/auth/sigv4.go

```go
// path: pkg/auth/sigv4.go
package auth

import (
"bytes"
"crypto/hmac"
"crypto/sha256"
"encoding/hex"
"fmt"
"net/http"
"net/url"
"sort"
"strings"
"time"

"github.com/dadyutenga/bucket/pkg/utils"
)

const (
// SignatureV4Algorithm is the AWS Signature Version 4 algorithm identifier
SignatureV4Algorithm = "AWS4-HMAC-SHA256"

// TimeFormat is the format for AWS timestamps
TimeFormat = "20060102T150405Z"

// DateFormat is the format for AWS dates
DateFormat = "20060102"
)

// SigV4Verifier verifies AWS Signature Version 4 signatures
type SigV4Verifier struct {
maxClockSkew time.Duration
region       string
service      string
}

// NewSigV4Verifier creates a new SigV4 verifier
func NewSigV4Verifier(region, service string, maxClockSkew time.Duration) *SigV4Verifier {
return &SigV4Verifier{
maxClockSkew: maxClockSkew,
region:       region,
service:      service,
}
}

// VerifyRequest verifies a request's SigV4 signature
func (v *SigV4Verifier) VerifyRequest(r *http.Request, accessKey, secretKey string) error {
// Check if this is a presigned URL request
if r.URL.Query().Get("X-Amz-Algorithm") != "" {
return v.verifyPresignedURL(r, secretKey)
}

// Otherwise, verify header-based signature
return v.verifyHeaderSignature(r, secretKey)
}

// verifyHeaderSignature verifies header-based SigV4 signature
func (v *SigV4Verifier) verifyHeaderSignature(r *http.Request, secretKey string) error {
// Extract authorization header
authHeader := r.Header.Get("Authorization")
if authHeader == "" {
return utils.ErrUnauthorized
}

// Parse authorization header
credential, signedHeaders, signature, err := parseAuthorizationHeader(authHeader)
if err != nil {
return fmt.Errorf("invalid authorization header: %w", err)
}

// Extract timestamp
timestamp := r.Header.Get("X-Amz-Date")
if timestamp == "" {
timestamp = r.Header.Get("Date")
}
if timestamp == "" {
return fmt.Errorf("missing timestamp header")
}

// Parse and validate timestamp
reqTime, err := time.Parse(TimeFormat, timestamp)
if err != nil {
return fmt.Errorf("invalid timestamp format: %w", err)
}

if !utils.IsWithinSkew(reqTime, v.maxClockSkew) {
return utils.ErrExpiredSignature
}

// Build canonical request
canonicalReq := buildCanonicalRequest(r, signedHeaders)

// Build string to sign
stringToSign := buildStringToSign(reqTime, v.region, v.service, canonicalReq)

// Calculate signature
calculatedSig := calculateSignature(secretKey, reqTime, v.region, v.service, stringToSign)

// Compare signatures
if !hmac.Equal([]byte(signature), []byte(calculatedSig)) {
return utils.ErrInvalidSignature
}

return nil
}

// verifyPresignedURL verifies presigned URL signature
func (v *SigV4Verifier) verifyPresignedURL(r *http.Request, secretKey string) error {
query := r.URL.Query()

// Extract required query parameters
algorithm := query.Get("X-Amz-Algorithm")
credential := query.Get("X-Amz-Credential")
timestamp := query.Get("X-Amz-Date")
expiresStr := query.Get("X-Amz-Expires")
signedHeaders := query.Get("X-Amz-SignedHeaders")
signature := query.Get("X-Amz-Signature")

if algorithm != SignatureV4Algorithm {
return fmt.Errorf("unsupported algorithm: %s", algorithm)
}

// Parse and validate timestamp
reqTime, err := time.Parse(TimeFormat, timestamp)
if err != nil {
return fmt.Errorf("invalid timestamp format: %w", err)
}

// Check expiration
expires, err := time.ParseDuration(expiresStr + "s")
if err != nil {
return fmt.Errorf("invalid expires parameter: %w", err)
}

if time.Since(reqTime) > expires {
return utils.ErrExpiredSignature
}

// Build canonical request for presigned URL
canonicalReq := buildCanonicalRequestForPresignedURL(r, signedHeaders)

// Build string to sign
stringToSign := buildStringToSign(reqTime, v.region, v.service, canonicalReq)

// Calculate signature
calculatedSig := calculateSignature(secretKey, reqTime, v.region, v.service, stringToSign)

// Compare signatures
if !hmac.Equal([]byte(signature), []byte(calculatedSig)) {
return utils.ErrInvalidSignature
}

return nil
}

// parseAuthorizationHeader parses the Authorization header
func parseAuthorizationHeader(header string) (credential, signedHeaders, signature string, err error) {
// Format: AWS4-HMAC-SHA256 Credential=..., SignedHeaders=..., Signature=...
if !strings.HasPrefix(header, SignatureV4Algorithm+" ") {
return "", "", "", fmt.Errorf("invalid algorithm")
}

parts := strings.Split(strings.TrimPrefix(header, SignatureV4Algorithm+" "), ", ")
for _, part := range parts {
kv := strings.SplitN(part, "=", 2)
if len(kv) != 2 {
continue
}

switch kv[0] {
case "Credential":
credential = kv[1]
case "SignedHeaders":
signedHeaders = kv[1]
case "Signature":
signature = kv[1]
}
}

if credential == "" || signedHeaders == "" || signature == "" {
return "", "", "", fmt.Errorf("missing required components")
}

return credential, signedHeaders, signature, nil
}

// buildCanonicalRequest builds the canonical request string
func buildCanonicalRequest(r *http.Request, signedHeaders string) string {
var buf bytes.Buffer

// HTTP method
buf.WriteString(r.Method)
buf.WriteString("\n")

// Canonical URI
buf.WriteString(getCanonicalURI(r.URL.Path))
buf.WriteString("\n")

// Canonical query string
buf.WriteString(getCanonicalQueryString(r.URL.Query()))
buf.WriteString("\n")

// Canonical headers
headers := strings.Split(signedHeaders, ";")
for _, h := range headers {
buf.WriteString(h)
buf.WriteString(":")
buf.WriteString(strings.TrimSpace(r.Header.Get(h)))
buf.WriteString("\n")
}
buf.WriteString("\n")

// Signed headers
buf.WriteString(signedHeaders)
buf.WriteString("\n")

// Payload hash
payloadHash := r.Header.Get("X-Amz-Content-Sha256")
if payloadHash == "" {
payloadHash = "UNSIGNED-PAYLOAD"
}
buf.WriteString(payloadHash)

return buf.String()
}

// buildCanonicalRequestForPresignedURL builds canonical request for presigned URL
func buildCanonicalRequestForPresignedURL(r *http.Request, signedHeaders string) string {
var buf bytes.Buffer

// HTTP method
buf.WriteString(r.Method)
buf.WriteString("\n")

// Canonical URI
buf.WriteString(getCanonicalURI(r.URL.Path))
buf.WriteString("\n")

// Canonical query string (excluding X-Amz-Signature)
query := r.URL.Query()
query.Del("X-Amz-Signature")
buf.WriteString(getCanonicalQueryString(query))
buf.WriteString("\n")

// Canonical headers
headers := strings.Split(signedHeaders, ";")
for _, h := range headers {
buf.WriteString(h)
buf.WriteString(":")
buf.WriteString(strings.TrimSpace(r.Header.Get(h)))
buf.WriteString("\n")
}
buf.WriteString("\n")

// Signed headers
buf.WriteString(signedHeaders)
buf.WriteString("\n")

// For presigned URLs, payload is always UNSIGNED-PAYLOAD
buf.WriteString("UNSIGNED-PAYLOAD")

return buf.String()
}

// getCanonicalURI returns the canonical URI
func getCanonicalURI(path string) string {
if path == "" {
return "/"
}

// URL encode each path segment
segments := strings.Split(path, "/")
for i, seg := range segments {
segments[i] = url.PathEscape(seg)
}

return strings.Join(segments, "/")
}

// getCanonicalQueryString returns the canonical query string
func getCanonicalQueryString(query url.Values) string {
if len(query) == 0 {
return ""
}

// Sort keys
keys := make([]string, 0, len(query))
for k := range query {
keys = append(keys, k)
}
sort.Strings(keys)

// Build canonical query string
var parts []string
for _, k := range keys {
values := query[k]
sort.Strings(values)
for _, v := range values {
parts = append(parts, url.QueryEscape(k)+"="+url.QueryEscape(v))
}
}

return strings.Join(parts, "&")
}

// buildStringToSign builds the string to sign
func buildStringToSign(reqTime time.Time, region, service, canonicalRequest string) string {
var buf bytes.Buffer

// Algorithm
buf.WriteString(SignatureV4Algorithm)
buf.WriteString("\n")

// Request timestamp
buf.WriteString(reqTime.Format(TimeFormat))
buf.WriteString("\n")

// Credential scope
buf.WriteString(reqTime.Format(DateFormat))
buf.WriteString("/")
buf.WriteString(region)
buf.WriteString("/")
buf.WriteString(service)
buf.WriteString("/aws4_request\n")

// Hashed canonical request
hash := sha256.Sum256([]byte(canonicalRequest))
buf.WriteString(hex.EncodeToString(hash[:]))

return buf.String()
}

// calculateSignature calculates the signature
func calculateSignature(secretKey string, reqTime time.Time, region, service, stringToSign string) string {
// Derive signing key
kDate := hmacSHA256([]byte("AWS4"+secretKey), []byte(reqTime.Format(DateFormat)))
kRegion := hmacSHA256(kDate, []byte(region))
kService := hmacSHA256(kRegion, []byte(service))
kSigning := hmacSHA256(kService, []byte("aws4_request"))

// Calculate signature
signature := hmacSHA256(kSigning, []byte(stringToSign))
return hex.EncodeToString(signature)
}

// hmacSHA256 computes HMAC-SHA256
func hmacSHA256(key, data []byte) []byte {
h := hmac.New(sha256.New, key)
h.Write(data)
return h.Sum(nil)
}

// GeneratePresignedURL generates a presigned URL
func GeneratePresignedURL(method, bucket, key, accessKey, secretKey, region string, expires time.Duration) (string, error) {
// Build base URL
u := &url.URL{
Scheme: "https",
Host:   fmt.Sprintf("%s.s3.%s.amazonaws.com", bucket, region),
Path:   "/" + key,
}

// Add query parameters
now := time.Now().UTC()
query := u.Query()
query.Set("X-Amz-Algorithm", SignatureV4Algorithm)
query.Set("X-Amz-Credential", fmt.Sprintf("%s/%s/%s/s3/aws4_request", 
accessKey, now.Format(DateFormat), region))
query.Set("X-Amz-Date", now.Format(TimeFormat))
query.Set("X-Amz-Expires", fmt.Sprintf("%d", int(expires.Seconds())))
query.Set("X-Amz-SignedHeaders", "host")
u.RawQuery = query.Encode()

// Build canonical request
canonicalReq := fmt.Sprintf("%s\n%s\n%s\nhost:%s\n\nhost\nUNSIGNED-PAYLOAD",
method, u.Path, u.RawQuery, u.Host)

// Build string to sign
stringToSign := buildStringToSign(now, region, "s3", canonicalReq)

// Calculate signature
signature := calculateSignature(secretKey, now, region, "s3", stringToSign)

// Add signature to query
query.Set("X-Amz-Signature", signature)
u.RawQuery = query.Encode()

return u.String(), nil
}
```

## File: pkg/auth/keys.go

```go
// path: pkg/auth/keys.go
package auth

import (
"context"
"crypto/rand"
"encoding/base64"
"fmt"
"time"

"golang.org/x/crypto/argon2"

"github.com/dadyutenga/bucket/pkg/utils"
)

// AccessKey represents an access key credential
type AccessKey struct {
ID           string
SecretHash   string // Argon2id hash of the secret
Salt         []byte
UserID       string
Description  string
Status       KeyStatus
CreatedAt    time.Time
UpdatedAt    time.Time
LastUsedAt   *time.Time
ExpiresAt    *time.Time
Permissions  []string
}

// KeyStatus represents the status of an access key
type KeyStatus string

const (
KeyStatusActive   KeyStatus = "active"
KeyStatusInactive KeyStatus = "inactive"
KeyStatusExpired  KeyStatus = "expired"
)

// KeyManager manages access keys
type KeyManager struct {
// Argon2id parameters
memory      uint32
iterations  uint32
parallelism uint8
keyLength   uint32
}

// NewKeyManager creates a new key manager
func NewKeyManager(memory, iterations uint32, parallelism uint8) *KeyManager {
return &KeyManager{
memory:      memory,
iterations:  iterations,
parallelism: parallelism,
keyLength:   32,
}
}

// GenerateAccessKey generates a new access key pair
func (km *KeyManager) GenerateAccessKey() (accessKeyID, secretAccessKey string, err error) {
// Generate access key ID (20 characters, base64)
accessKeyBytes := make([]byte, 15)
if _, err := rand.Read(accessKeyBytes); err != nil {
return "", "", fmt.Errorf("failed to generate access key ID: %w", err)
}
accessKeyID = base64.RawURLEncoding.EncodeToString(accessKeyBytes)

// Generate secret access key (40 characters, base64)
secretKeyBytes := make([]byte, 30)
if _, err := rand.Read(secretKeyBytes); err != nil {
return "", "", fmt.Errorf("failed to generate secret access key: %w", err)
}
secretAccessKey = base64.RawURLEncoding.EncodeToString(secretKeyBytes)

return accessKeyID, secretAccessKey, nil
}

// HashSecret hashes a secret access key using Argon2id
func (km *KeyManager) HashSecret(secret string) (hash string, salt []byte, err error) {
// Generate salt
salt = make([]byte, 16)
if _, err := rand.Read(salt); err != nil {
return "", nil, fmt.Errorf("failed to generate salt: %w", err)
}

// Hash secret
hashBytes := argon2.IDKey([]byte(secret), salt, km.iterations, km.memory, km.parallelism, km.keyLength)
hash = base64.RawStdEncoding.EncodeToString(hashBytes)

return hash, salt, nil
}

// VerifySecret verifies a secret against its hash
func (km *KeyManager) VerifySecret(secret, hash string, salt []byte) bool {
// Hash the provided secret with the stored salt
hashBytes := argon2.IDKey([]byte(secret), salt, km.iterations, km.memory, km.parallelism, km.keyLength)
computedHash := base64.RawStdEncoding.EncodeToString(hashBytes)

// Compare hashes
return computedHash == hash
}

// KeyRepository defines the interface for access key storage
type KeyRepository interface {
Create(ctx context.Context, key *AccessKey) error
GetByID(ctx context.Context, id string) (*AccessKey, error)
GetByUserID(ctx context.Context, userID string) ([]*AccessKey, error)
Update(ctx context.Context, key *AccessKey) error
Delete(ctx context.Context, id string) error
UpdateLastUsed(ctx context.Context, id string, timestamp time.Time) error
}

// KeyService provides access key management operations
type KeyService struct {
manager *KeyManager
repo    KeyRepository
}

// NewKeyService creates a new key service
func NewKeyService(manager *KeyManager, repo KeyRepository) *KeyService {
return &KeyService{
manager: manager,
repo:    repo,
}
}

// CreateKey creates a new access key
func (ks *KeyService) CreateKey(ctx context.Context, userID, description string, permissions []string, expiresAt *time.Time) (*AccessKey, string, error) {
// Generate key pair
accessKeyID, secretAccessKey, err := ks.manager.GenerateAccessKey()
if err != nil {
return nil, "", fmt.Errorf("failed to generate key pair: %w", err)
}

// Hash secret
secretHash, salt, err := ks.manager.HashSecret(secretAccessKey)
if err != nil {
return nil, "", fmt.Errorf("failed to hash secret: %w", err)
}

// Create access key
now := time.Now()
key := &AccessKey{
ID:          accessKeyID,
SecretHash:  secretHash,
Salt:        salt,
UserID:      userID,
Description: description,
Status:      KeyStatusActive,
CreatedAt:   now,
UpdatedAt:   now,
ExpiresAt:   expiresAt,
Permissions: permissions,
}

// Store in repository
if err := ks.repo.Create(ctx, key); err != nil {
return nil, "", fmt.Errorf("failed to store access key: %w", err)
}

// Return key and plaintext secret (only time it's available)
return key, secretAccessKey, nil
}

// VerifyKey verifies an access key and secret
func (ks *KeyService) VerifyKey(ctx context.Context, accessKeyID, secretAccessKey string) (*AccessKey, error) {
// Retrieve access key
key, err := ks.repo.GetByID(ctx, accessKeyID)
if err != nil {
if utils.IsNotFound(err) {
return nil, utils.ErrUnauthorized
}
return nil, fmt.Errorf("failed to retrieve access key: %w", err)
}

// Check status
if key.Status != KeyStatusActive {
return nil, utils.ErrUnauthorized
}

// Check expiration
if key.ExpiresAt != nil && time.Now().After(*key.ExpiresAt) {
key.Status = KeyStatusExpired
ks.repo.Update(ctx, key)
return nil, utils.ErrUnauthorized
}

// Verify secret
if !ks.manager.VerifySecret(secretAccessKey, key.SecretHash, key.Salt) {
return nil, utils.ErrUnauthorized
}

// Update last used timestamp
go ks.repo.UpdateLastUsed(context.Background(), key.ID, time.Now())

return key, nil
}

// DeactivateKey deactivates an access key
func (ks *KeyService) DeactivateKey(ctx context.Context, accessKeyID string) error {
key, err := ks.repo.GetByID(ctx, accessKeyID)
if err != nil {
return fmt.Errorf("failed to retrieve access key: %w", err)
}

key.Status = KeyStatusInactive
key.UpdatedAt = time.Now()

if err := ks.repo.Update(ctx, key); err != nil {
return fmt.Errorf("failed to update access key: %w", err)
}

return nil
}

// ActivateKey activates an access key
func (ks *KeyService) ActivateKey(ctx context.Context, accessKeyID string) error {
key, err := ks.repo.GetByID(ctx, accessKeyID)
if err != nil {
return fmt.Errorf("failed to retrieve access key: %w", err)
}

key.Status = KeyStatusActive
key.UpdatedAt = time.Now()

if err := ks.repo.Update(ctx, key); err != nil {
return fmt.Errorf("failed to update access key: %w", err)
}

return nil
}

// DeleteKey deletes an access key
func (ks *KeyService) DeleteKey(ctx context.Context, accessKeyID string) error {
if err := ks.repo.Delete(ctx, accessKeyID); err != nil {
return fmt.Errorf("failed to delete access key: %w", err)
}

return nil
}

// ListKeys lists access keys for a user
func (ks *KeyService) ListKeys(ctx context.Context, userID string) ([]*AccessKey, error) {
keys, err := ks.repo.GetByUserID(ctx, userID)
if err != nil {
return nil, fmt.Errorf("failed to list access keys: %w", err)
}

return keys, nil
}

// RotateKey creates a new key and deactivates the old one
func (ks *KeyService) RotateKey(ctx context.Context, oldAccessKeyID, userID, description string, permissions []string) (*AccessKey, string, error) {
// Create new key
newKey, secret, err := ks.CreateKey(ctx, userID, description, permissions, nil)
if err != nil {
return nil, "", fmt.Errorf("failed to create new key: %w", err)
}

// Deactivate old key
if err := ks.DeactivateKey(ctx, oldAccessKeyID); err != nil {
// Attempt to clean up new key
ks.repo.Delete(ctx, newKey.ID)
return nil, "", fmt.Errorf("failed to deactivate old key: %w", err)
}

return newKey, secret, nil
}
```

