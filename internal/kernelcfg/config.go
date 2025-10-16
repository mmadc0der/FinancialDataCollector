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
    Spill SpillConfig `yaml:"spill"`
    Auth   AuthConfig   `yaml:"auth"`
}

type ServerConfig struct {
	Listen          string `yaml:"listen"`
	MaxMessageBytes int64  `yaml:"max_message_bytes"`
	ReadTimeoutMs   int    `yaml:"read_timeout_ms"`
    IngestQueueSize int    `yaml:"ingest_queue_size"`
}

// sinks removed (file sink was deprecated)

// removed ModulesConfig; modules are external

type PostgresConfig struct {
    Enabled bool `yaml:"enabled"`
    DSN string `yaml:"dsn"`
    MaxConns int `yaml:"max_conns"`
    ConnMaxLifetimeMs int `yaml:"conn_max_lifetime_ms"`
    ApplyMigrations bool `yaml:"apply_migrations"`
    QueueSize int `yaml:"queue_size"`
    BatchSize int `yaml:"batch_size"`
    BatchMaxWaitMs int `yaml:"batch_max_wait_ms"`
    // Defaults used by router when deriving ids at ingest is not configured
    DefaultProducerID string `yaml:"default_producer_id"`
    DefaultSchemaID   string `yaml:"default_schema_id"`
}

type RedisConfig struct {
    Enabled bool `yaml:"enabled"`
    Addr string `yaml:"addr"`
    Username string `yaml:"username"`
    Password string `yaml:"password"`
    DB int `yaml:"db"`
    KeyPrefix string `yaml:"key_prefix"`
    Stream string `yaml:"stream"`
    MaxLenApprox int64 `yaml:"maxlen_approx"`
    QueueSize int `yaml:"queue_size"`
    // Ingest (consumer) settings
    ConsumerEnabled bool   `yaml:"consumer_enabled"`
    ConsumerGroup   string `yaml:"consumer_group"`
    ConsumerName    string `yaml:"consumer_name"`
    ReadCount       int    `yaml:"read_count"`
    BlockMs         int    `yaml:"block_ms"`
    DLQStream       string `yaml:"dlq_stream"`
    // Producer (publisher) feature flag
    PublishEnabled  bool   `yaml:"publish_enabled"`
    // Registration rate limiting
    RegistrationRateLimitRPM int `yaml:"registration_rate_limit_rpm"`
}

type SpillConfig struct {
    Enabled bool `yaml:"enabled"`
    Directory string `yaml:"directory"`
    RotateMB int `yaml:"rotate_mb"`
    Compression string `yaml:"compression"`
}

type LoggingConfig struct {
    Level string `yaml:"level"`
    Buffer int `yaml:"buffer"`
    Output string `yaml:"output"`
}

type AuthConfig struct {
    Enabled bool `yaml:"enabled"`
    RequireToken bool `yaml:"require_token"`
    Issuer string `yaml:"issuer"`
    Audience string `yaml:"audience"`
    KeyID string `yaml:"key_id"`
    // Base64 (raw) Ed25519 keys; private optional (only needed to issue tokens)
    PublicKeys map[string]string `yaml:"public_keys"`
    PrivateKey string `yaml:"private_key"`
    // Alternative key sources
    PrivateKeyFile string            `yaml:"private_key_file"`   // path to PEM/OpenSSH private key (ed25519)
    PrivateKeyPassphraseFile string  `yaml:"private_key_passphrase_file"`
    PublicKeysSSH  map[string]string `yaml:"public_keys_ssh"`   // kid -> OpenSSH public key lines
    AdminSSHCA  string `yaml:"admin_ssh_ca"` // OpenSSH CA public key (text)
    ProducerSSHCA string `yaml:"producer_ssh_ca"` // OpenSSH CA public key for producers (text)
    ProducerCertRequired bool `yaml:"producer_cert_required"`
    TrustOnFirstUse bool `yaml:"trust_on_first_use"`
    // Cache and clock skew
    CacheTTLSeconds int `yaml:"cache_ttl_seconds"`
    SkewSeconds int `yaml:"skew_seconds"`
    // Registration response TTL
    RegistrationResponseTTLSeconds int `yaml:"registration_response_ttl_seconds"`
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
    if cfg.Redis.RegistrationRateLimitRPM <= 0 { cfg.Redis.RegistrationRateLimitRPM = 10 }
    // Defaults for Postgres batching
    if cfg.Postgres.BatchSize <= 0 { cfg.Postgres.BatchSize = 1000 }
    if cfg.Postgres.BatchMaxWaitMs <= 0 { cfg.Postgres.BatchMaxWaitMs = 200 }
    // Defaults for auth
    if cfg.Auth.Enabled {
        if cfg.Auth.CacheTTLSeconds <= 0 { cfg.Auth.CacheTTLSeconds = 300 }
        if cfg.Auth.SkewSeconds <= 0 { cfg.Auth.SkewSeconds = 60 }
        if !cfg.Auth.RequireToken { cfg.Auth.RequireToken = true }
        if cfg.Auth.ProducerSSHCA != "" && !cfg.Auth.ProducerCertRequired { cfg.Auth.ProducerCertRequired = true }
        if cfg.Auth.RegistrationResponseTTLSeconds <= 0 { cfg.Auth.RegistrationResponseTTLSeconds = 300 }
    }
	return &cfg, nil
}

func (c *Config) String() string {
    return fmt.Sprintf("listen=%s", c.Server.Listen)
}

