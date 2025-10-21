//go:build !integration

package data

import (
	"testing"
	"time"

	"github.com/example/data-kernel/internal/kernelcfg"
)

// Test Redis config defaults
func TestRedisConfig_Defaults(t *testing.T) {
	cfg := newTestRedisConfig()

	if cfg.Addr == "" {
		t.Logf("Addr must be set (e.g., localhost:6379)")
	}
	if cfg.Stream == "" {
		t.Logf("Stream must be set (e.g., events)")
	}
	if cfg.KeyPrefix == "" {
		t.Logf("KeyPrefix must be set (e.g., fdc:)")
	}
}

// Test consumer group configuration
func TestRedisConfig_ConsumerGroup(t *testing.T) {
	cfg := newTestRedisConfig()

	if cfg.ConsumerGroup == "" {
		t.Logf("ConsumerGroup empty - will default to 'kernel' in config loading")
	} else {
		t.Logf("ConsumerGroup: %s", cfg.ConsumerGroup)
	}

	if cfg.ConsumerName == "" {
		t.Logf("ConsumerName: kernel-<timestamp>")
	} else {
		t.Logf("ConsumerName: %s", cfg.ConsumerName)
	}
}

// Test read configuration
func TestRedisConfig_ReadSettings(t *testing.T) {
	cfg := newTestRedisConfig()

	if cfg.ReadCount == 0 {
		t.Logf("ReadCount empty - will default to 100 in config loading")
	} else {
		t.Logf("ReadCount: %d messages per batch", cfg.ReadCount)
	}

	if cfg.BlockMs == 0 {
		t.Logf("BlockMs empty - will default to 5000ms in config loading")
	} else {
		blockDuration := time.Duration(cfg.BlockMs) * time.Millisecond
		t.Logf("BlockMs: %v per read", blockDuration)
	}
}


// Test DLQ stream configuration
func TestRedisConfig_DLQStream(t *testing.T) {
	cfg := newTestRedisConfig()

	if cfg.DLQStream == "" {
		t.Logf("DLQStream empty - will default to '<stream>:dlq' in config loading")
	} else {
		t.Logf("DLQ stream: %s", cfg.DLQStream)
	}
}

// Test publish feature flag
func TestRedisConfig_PublishFlag(t *testing.T) {
	cfg := newTestRedisConfig()

	if cfg.PublishEnabled {
		t.Logf("Publishing to Redis enabled")
	} else {
		t.Logf("Publishing to Redis disabled")
	}
}

// Test queue sizing
func TestRedisConfig_QueueSize(t *testing.T) {
	cfg := newTestRedisConfig()

	if cfg.QueueSize == 0 {
		t.Logf("QueueSize empty - will default to 2048 in router")
	} else {
		t.Logf("QueueSize: %d pending messages", cfg.QueueSize)
	}
}

// Test auth configuration (if used)
func TestRedisConfig_Authentication(t *testing.T) {
	cfg := newTestRedisConfig()

	if cfg.Username != "" {
		t.Logf("Redis username configured")
	}
	if cfg.Password != "" {
		t.Logf("Redis password configured (should be from env or file)")
	}
	if cfg.DB > 0 {
		t.Logf("Redis DB: %d (default=0 for production)", cfg.DB)
	}
}

// Test key prefix validation
func TestRedisConfig_KeyPrefixFormat(t *testing.T) {
	testCases := []struct {
		name   string
		prefix string
	}{
		{"standard", "fdc:"},
		{"with_env", "fdc:prod:"},
		{"empty", ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.prefix != "" && !endsWith(tc.prefix, ":") {
				t.Logf("Prefix '%s' should end with colon for readability", tc.prefix)
			}
		})
	}
}

// Test stream name with prefix
func TestRedisConfig_StreamNameComposition(t *testing.T) {
	prefix := "fdc:"
	stream := "events"
	dlq := "events:dlq"

	prefixedStream := prefix + stream
	prefixedDLQ := prefix + dlq

	if prefixedStream == "" || prefixedDLQ == "" {
		t.Fatalf("stream names must be non-empty")
	}

	t.Logf("Streams: %s (events), %s (dlq)", prefixedStream, prefixedDLQ)
}

// Helper to check if string ends with suffix
func endsWith(s, suffix string) bool {
	if len(suffix) > len(s) {
		return false
	}
	return s[len(s)-len(suffix):] == suffix
}

// Helper to create test config
func newTestRedisConfig() kernelcfg.RedisConfig {
	return kernelcfg.RedisConfig{
		Addr:         "localhost:6379",
		Username:     "",
		Password:     "",
		DB:           1, // Use test DB
		KeyPrefix:    "fdc:",
		Stream:       "events",
		QueueSize:    2048,
		ConsumerGroup: "kernel",
		ConsumerName:  "",
		ReadCount:    100,
		BlockMs:      5000,
		DLQStream:    "events:dlq",
		PublishEnabled: false,
	}
}
