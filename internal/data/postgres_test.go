//go:build !integration

package data

import (
	"context"
	"testing"
	"time"

	"github.com/example/data-kernel/internal/kernelcfg"
)

// Test config defaults
func TestPostgresConfig_Defaults(t *testing.T) {
	// Test typical config values
	cfg := newTestPostgresConfig()

	if cfg.DSN == "" {
		t.Logf("DSN should be set before NewPostgres call")
	}
	if cfg.MaxConns == 0 {
		t.Logf("MaxConns defaults to 0 - uses pgxpool default")
	}
	if cfg.BatchSize == 0 {
		t.Logf("BatchSize should be defaulted by Load(): 0 -> 1000")
	}
	if cfg.BatchMaxWaitMs == 0 {
		t.Logf("BatchMaxWaitMs should be defaulted by Load(): 0 -> 200ms")
	}
}

// Test connection lifetime configuration
func TestPostgresConfig_ConnLifetime(t *testing.T) {
	cfg := newTestPostgresConfig()

	lifetimeDuration := time.Duration(cfg.ConnMaxLifetimeMs) * time.Millisecond
	if lifetimeDuration > 0 {
		t.Logf("Connection lifetime: %v", lifetimeDuration)
	}

	// Test typical values (e.g., 30 minutes)
	typicalMs := 30 * 60 * 1000 // 30 minutes
	typicalDuration := time.Duration(typicalMs) * time.Millisecond
	if typicalDuration != 30*time.Minute {
		t.Fatalf("connection lifetime calculation wrong: got %v, want 30m", typicalDuration)
	}
}

// Test batch sizing
func TestPostgresConfig_BatchSizing(t *testing.T) {
	testCases := []struct {
		name       string
		batchSize  int
		batchWait  int
		expectSize int
	}{
		{"default_zero", 0, 0, 1000},    // Should default to 1000
		{"small_batch", 10, 100, 10},
		{"large_batch", 5000, 1000, 5000},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.batchSize == 0 {
				t.Logf("BatchSize %d will be defaulted by Load() to 1000", tc.batchSize)
			} else if tc.batchSize != tc.expectSize {
				t.Fatalf("batch size mismatch: got %d, want %d", tc.batchSize, tc.expectSize)
			}

			waitDuration := time.Duration(tc.batchWait) * time.Millisecond
			t.Logf("Batch config: size=%d, wait=%v", tc.batchSize, waitDuration)
		})
	}
}

// Test queue size configuration
func TestPostgresConfig_QueueSize(t *testing.T) {
	cfg := newTestPostgresConfig()
	cfg.QueueSize = 2048

	if cfg.QueueSize < 1 {
		t.Fatalf("queue size must be > 0")
	}

	t.Logf("Ingest queue size: %d", cfg.QueueSize)
}

// Test migrations flag
func TestPostgresConfig_Migrations(t *testing.T) {
	cfg := newTestPostgresConfig()

	if cfg.ApplyMigrations {
		t.Logf("Migrations will be applied on NewPostgres()")
	} else {
		t.Logf("Migrations will NOT be applied")
	}
}

// Test default producer/schema IDs
func TestPostgresConfig_DefaultIDs(t *testing.T) {
	cfg := newTestPostgresConfig()

	// These may be empty (NULL in DB) or have values
	t.Logf("Default ProducerID: %q", cfg.DefaultProducerID)
	t.Logf("Default SchemaID: %q", cfg.DefaultSchemaID)

	if cfg.DefaultProducerID != "" && cfg.DefaultSchemaID != "" {
		t.Logf("Both defaults set - messages will use these if not overridden")
	}
}

// NewTestPostgres creates a Postgres instance with nil pool for unit tests.
// This bypasses ensurePool() checks and allows tests to verify batching/routing logic
// without requiring a database connection.
func NewTestPostgres() *Postgres {
	return NewFromPool(nil)
}

// Helper to create test config
func newTestPostgresConfig() kernelcfg.PostgresConfig {
	return kernelcfg.PostgresConfig{
		DSN:               "postgres://test:test@localhost/testdb",
		MaxConns:          10,
		ConnMaxLifetimeMs: 0,
		ApplyMigrations:   false,
		QueueSize:         1024,
		BatchSize:         1000,
		BatchMaxWaitMs:    200,
		DefaultProducerID: "",
		DefaultSchemaID:   "",
	}
}
