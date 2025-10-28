package kernelcfg

import (
    "fmt"
    "os"
    "strings"

    "gopkg.in/yaml.v3"
)

type Config struct {
    Server ServerConfig `yaml:"server"`
    Postgres PostgresConfig `yaml:"postgres"`
    Redis RedisConfig `yaml:"redis"`
    Logging LoggingConfig `yaml:"logging"`
    Auth   AuthConfig   `yaml:"auth"`
    Performance PerformanceConfig `yaml:"performance"`
}

type ServerConfig struct {
	Listen          string `yaml:"listen"`
	MaxMessageBytes int64  `yaml:"max_message_bytes"`
	ReadTimeoutMs   int    `yaml:"read_timeout_ms"`
    IngestQueueSize int    `yaml:"ingest_queue_size"`
    TLS             TLSConfig `yaml:"tls"`
}

type TLSConfig struct {
    CertFile        string `yaml:"cert_file"`
    KeyFile         string `yaml:"key_file"`
    ClientCAFile    string `yaml:"client_ca_file"`
    RequireClientCert bool `yaml:"require_client_cert"`
}

// sinks removed (file sink was deprecated)

// removed ModulesConfig; modules are external

type PostgresConfig struct {
    DSN string `yaml:"dsn"`
    MaxConns int `yaml:"max_conns"`
    ConnMaxLifetimeMs int `yaml:"conn_max_lifetime_ms"`
    ApplyMigrations bool `yaml:"apply_migrations"`
    MigrationsDir string `yaml:"migrations_dir"`
    QueueSize int `yaml:"queue_size"`
    BatchSize int `yaml:"batch_size"`
    BatchMaxWaitMs int `yaml:"batch_max_wait_ms"`
    // Circuit breaker settings
    CircuitBreakerThreshold int `yaml:"circuit_breaker_threshold"`
    CircuitBreakerTimeoutSeconds int `yaml:"circuit_breaker_timeout_seconds"`
    // Defaults used by router when deriving ids at ingest
    DefaultProducerID string `yaml:"default_producer_id"`
    DefaultSchemaID   string `yaml:"default_schema_id"`
}

type RedisConfig struct {
    Addr string `yaml:"addr"`
    Username string `yaml:"username"`
    Password string `yaml:"password"`
    DB int `yaml:"db"`
    KeyPrefix string `yaml:"key_prefix"`
    Stream string `yaml:"stream"`
    QueueSize int `yaml:"queue_size"`
    // Ingest (consumer) settings
    ConsumerGroup   string `yaml:"consumer_group"`
    ConsumerName    string `yaml:"consumer_name"`
    ReadCount       int    `yaml:"read_count"`
    BlockMs         int    `yaml:"block_ms"`
    DLQStream       string `yaml:"dlq_stream"`
    // Producer (publisher) feature flag
    PublishEnabled  bool   `yaml:"publish_enabled"`
    // Connection pool settings
    PoolSize int `yaml:"pool_size"`
    MinIdleConns int `yaml:"min_idle_conns"`
    // Timeout settings for different operations
    ReadTimeoutMs int `yaml:"read_timeout_ms"`
    WriteTimeoutMs int `yaml:"write_timeout_ms"`
    DialTimeoutMs int `yaml:"dial_timeout_ms"`
    XAddTimeoutMs int `yaml:"xadd_timeout_ms"`
    // Retry and backoff settings
    RetryMaxAttempts int `yaml:"retry_max_attempts"`
    RetryBaseBackoffMs int `yaml:"retry_base_backoff_ms"`
    RetryMaxBackoffMs int `yaml:"retry_max_backoff_ms"`
    // Note: test-only enable flags removed; rely on production config wiring
}

type LoggingConfig struct {
    Level string `yaml:"level"`
    Buffer int `yaml:"buffer"`
    Output string `yaml:"output"`
}

type AuthConfig struct {
    Issuer string `yaml:"issuer"`
    Audience string `yaml:"audience"`
    KeyID string `yaml:"key_id"`
    // Whether to require token exchange for producer interactions
    RequireToken bool `yaml:"require_token"`
    // Base64 (raw) Ed25519 keys; private optional (only needed to issue tokens)
    PublicKeys map[string]string `yaml:"public_keys"`
    PrivateKey string `yaml:"private_key"`
    // Alternative key sources
    PrivateKeyFile string            `yaml:"private_key_file"`   // path to PEM/OpenSSH private key (ed25519)
    PrivateKeyPassphraseFile string  `yaml:"private_key_passphrase_file"`
    PublicKeysSSH  map[string]string `yaml:"public_keys_ssh"`   // kid -> OpenSSH public key lines
    AdminSSHCA  string `yaml:"admin_ssh_ca"` // OpenSSH CA public key (text)
    ProducerSSHCA string `yaml:"producer_ssh_ca"` // OpenSSH CA public key for producers (text)
    // Producer registrations and token exchange require CA-signed certificates
    // Cache and clock skew
    CacheTTLSeconds int `yaml:"cache_ttl_seconds"`
    SkewSeconds int `yaml:"skew_seconds"`
    // Registration response TTL
    RegistrationResponseTTLSeconds int `yaml:"registration_response_ttl_seconds"`
    // Rate limiting
    RegistrationRateLimitRPM int `yaml:"registration_rate_limit_rpm"` // requests per minute per fingerprint
    RegistrationRateLimitBurst int `yaml:"registration_rate_limit_burst"` // burst allowance
    // Key status cache settings
    KeyStatusCacheTTLSeconds int `yaml:"key_status_cache_ttl_seconds"`
    // Token cache settings
    TokenCacheTTLSeconds int `yaml:"token_cache_ttl_seconds"`
    // Admin request detached signature requirements
    AdminPrincipal string   `yaml:"admin_principal"`
    AdminAllowedSubjects []string `yaml:"admin_allowed_subjects"`
    AdminSignRequired bool `yaml:"admin_sign_required"`
}

type PerformanceConfig struct {
    // Schema cache settings
    SchemaCacheTTLSeconds int `yaml:"schema_cache_ttl_seconds"`
    SchemaCacheRefreshSeconds int `yaml:"schema_cache_refresh_seconds"`
    // Object pooling settings
    JSONPoolSize int `yaml:"json_pool_size"`
    EventPoolSize int `yaml:"event_pool_size"`
    // Metrics collection
    MetricsBatchSize int `yaml:"metrics_batch_size"`
    MetricsFlushIntervalSeconds int `yaml:"metrics_flush_interval_seconds"`
    // Spill mechanism settings
    SpillBatchSize int `yaml:"spill_batch_size"`
    SpillMaxFileSizeMB int `yaml:"spill_max_file_size_mb"`
    // Rate limiting settings
    RateLimitLuaEnabled bool `yaml:"rate_limit_lua_enabled"`
}

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}
	if cfg.Server.Listen == "" {
		cfg.Server.Listen = ":7600"
	}
	if cfg.Server.MaxMessageBytes == 0 {
		cfg.Server.MaxMessageBytes = 1 << 20
	}
	if cfg.Server.ReadTimeoutMs == 0 {
		cfg.Server.ReadTimeoutMs = 15000
	}
    // no file sink defaults
    // Env overrides for secrets
    if v := os.Getenv("KERNEL_PG_DSN"); v != "" {
        cfg.Postgres.DSN = v
    }
    if v := os.Getenv("KERNEL_PG_DSN_FILE"); v != "" {
        if b, err := os.ReadFile(v); err == nil { cfg.Postgres.DSN = strings.TrimSpace(string(b)) }
    }
    if v := os.Getenv("KERNEL_REDIS_PASSWORD"); v != "" {
        cfg.Redis.Password = v
    }
    if v := os.Getenv("KERNEL_REDIS_PASSWORD_FILE"); v != "" {
        if b, err := os.ReadFile(v); err == nil { cfg.Redis.Password = strings.TrimSpace(string(b)) }
    }
    // Defaults for Redis consumer
    if cfg.Redis.ConsumerGroup == "" { cfg.Redis.ConsumerGroup = "kernel" }
    if cfg.Redis.ReadCount <= 0 { cfg.Redis.ReadCount = 100 }
    if cfg.Redis.BlockMs <= 0 { cfg.Redis.BlockMs = 5000 }
    if cfg.Redis.DLQStream == "" && cfg.Redis.Stream != "" { cfg.Redis.DLQStream = cfg.Redis.Stream + ":dlq" }
    // Connection pool defaults
    if cfg.Redis.PoolSize <= 0 { cfg.Redis.PoolSize = 10 }
    if cfg.Redis.MinIdleConns <= 0 { cfg.Redis.MinIdleConns = 2 }
    // Timeout defaults
    if cfg.Redis.ReadTimeoutMs <= 0 { cfg.Redis.ReadTimeoutMs = 1000 }
    if cfg.Redis.WriteTimeoutMs <= 0 { cfg.Redis.WriteTimeoutMs = 1000 }
    if cfg.Redis.DialTimeoutMs <= 0 { cfg.Redis.DialTimeoutMs = 2000 }
    if cfg.Redis.XAddTimeoutMs <= 0 { cfg.Redis.XAddTimeoutMs = 1000 }
    // Retry defaults
    if cfg.Redis.RetryMaxAttempts <= 0 { cfg.Redis.RetryMaxAttempts = 3 }
    if cfg.Redis.RetryBaseBackoffMs <= 0 { cfg.Redis.RetryBaseBackoffMs = 200 }
    if cfg.Redis.RetryMaxBackoffMs <= 0 { cfg.Redis.RetryMaxBackoffMs = 5000 }

    // Defaults for Postgres batching
    if cfg.Postgres.BatchSize <= 0 { cfg.Postgres.BatchSize = 1000 }
    if cfg.Postgres.BatchMaxWaitMs <= 0 { cfg.Postgres.BatchMaxWaitMs = 200 }
    // Circuit breaker defaults
    if cfg.Postgres.CircuitBreakerThreshold <= 0 { cfg.Postgres.CircuitBreakerThreshold = 5 }
    if cfg.Postgres.CircuitBreakerTimeoutSeconds <= 0 { cfg.Postgres.CircuitBreakerTimeoutSeconds = 30 }

    // Defaults for auth (mandatory)
    if cfg.Auth.CacheTTLSeconds <= 0 { cfg.Auth.CacheTTLSeconds = 300 }
    if cfg.Auth.SkewSeconds <= 0 { cfg.Auth.SkewSeconds = 60 }
    if cfg.Auth.RegistrationResponseTTLSeconds <= 0 { cfg.Auth.RegistrationResponseTTLSeconds = 300 }
    if cfg.Auth.RegistrationRateLimitRPM <= 0 { cfg.Auth.RegistrationRateLimitRPM = 10 }
    if cfg.Auth.RegistrationRateLimitBurst <= 0 { cfg.Auth.RegistrationRateLimitBurst = 3 }
    if cfg.Auth.KeyStatusCacheTTLSeconds <= 0 { cfg.Auth.KeyStatusCacheTTLSeconds = 300 }
    if cfg.Auth.TokenCacheTTLSeconds <= 0 { cfg.Auth.TokenCacheTTLSeconds = 3600 }
    if !cfg.Auth.AdminSignRequired { cfg.Auth.AdminSignRequired = true }

    // Defaults for performance tuning
    if cfg.Performance.SchemaCacheTTLSeconds <= 0 { cfg.Performance.SchemaCacheTTLSeconds = 3600 }
    if cfg.Performance.SchemaCacheRefreshSeconds <= 0 { cfg.Performance.SchemaCacheRefreshSeconds = 300 }
    if cfg.Performance.JSONPoolSize <= 0 { cfg.Performance.JSONPoolSize = 1000 }
    if cfg.Performance.EventPoolSize <= 0 { cfg.Performance.EventPoolSize = 500 }
    if cfg.Performance.MetricsBatchSize <= 0 { cfg.Performance.MetricsBatchSize = 100 }
    if cfg.Performance.MetricsFlushIntervalSeconds <= 0 { cfg.Performance.MetricsFlushIntervalSeconds = 10 }
    if cfg.Performance.SpillBatchSize <= 0 { cfg.Performance.SpillBatchSize = 1000 }
    if cfg.Performance.SpillMaxFileSizeMB <= 0 { cfg.Performance.SpillMaxFileSizeMB = 100 }
    // Validate mandatory settings
    if cfg.Postgres.DSN == "" { return nil, fmt.Errorf("postgres.dsn is required") }
    if cfg.Redis.Addr == "" || cfg.Redis.Stream == "" || cfg.Redis.KeyPrefix == "" { return nil, fmt.Errorf("redis.addr, redis.stream, and redis.key_prefix are required") }
    if cfg.Auth.Issuer == "" || cfg.Auth.Audience == "" || cfg.Auth.KeyID == "" { return nil, fmt.Errorf("auth.issuer, auth.audience, and auth.key_id are required") }
    if cfg.Auth.ProducerSSHCA == "" { return nil, fmt.Errorf("auth.producer_ssh_ca is required") }
    // Enforce TLS with client certs for admin endpoints only if TLS files are configured
    if cfg.Server.TLS.CertFile != "" || cfg.Server.TLS.KeyFile != "" || cfg.Server.TLS.ClientCAFile != "" {
        if cfg.Server.TLS.CertFile == "" || cfg.Server.TLS.KeyFile == "" || cfg.Server.TLS.ClientCAFile == "" {
            return nil, fmt.Errorf("server.tls.cert_file, server.tls.key_file, and server.tls.client_ca_file are all required for admin mTLS")
        }
        if !cfg.Server.TLS.RequireClientCert {
            cfg.Server.TLS.RequireClientCert = true
        }
    }
    // AdminSSHCA is required if not in test mode (allow test mode to skip)
    if cfg.Server.TLS.CertFile != "" && cfg.Auth.AdminSSHCA == "" {
        return nil, fmt.Errorf("auth.admin_ssh_ca is required when server.tls is configured")
    }
	return &cfg, nil
}

func (c *Config) String() string {
    return fmt.Sprintf("listen=%s", c.Server.Listen)
}

