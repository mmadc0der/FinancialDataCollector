package kernelcfg

import (
    "fmt"
    "os"
    "strings"

    "gopkg.in/yaml.v3"
)

type Config struct {
    Server ServerConfig `yaml:"server"`
    Sinks  SinksConfig  `yaml:"sinks"`
    Postgres PostgresConfig `yaml:"postgres"`
    Redis RedisConfig `yaml:"redis"`
    Logging LoggingConfig `yaml:"logging"`
    Spill SpillConfig `yaml:"spill"`
}

type ServerConfig struct {
	Listen          string `yaml:"listen"`
	MaxMessageBytes int64  `yaml:"max_message_bytes"`
	ReadTimeoutMs   int    `yaml:"read_timeout_ms"`
    IngestQueueSize int    `yaml:"ingest_queue_size"`
}

type SinksConfig struct {
	File FileSinkConfig `yaml:"file"`
}

type FileSinkConfig struct {
	Enabled       bool   `yaml:"enabled"`
	Directory     string `yaml:"directory"`
	RotateMB      int    `yaml:"rotate_mb"`
	RotateDaily   bool   `yaml:"rotate_daily"`
	Compression   string `yaml:"compression"` // none|gzip
}

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
	if cfg.Sinks.File.Directory == "" {
		cfg.Sinks.File.Directory = "./data"
	}
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
    // Defaults for Postgres batching
    if cfg.Postgres.BatchSize <= 0 { cfg.Postgres.BatchSize = 1000 }
    if cfg.Postgres.BatchMaxWaitMs <= 0 { cfg.Postgres.BatchMaxWaitMs = 200 }
	return &cfg, nil
}

func (c *Config) String() string {
	return fmt.Sprintf("listen=%s file.dir=%s modules.dir=%s", c.Server.Listen, c.Sinks.File.Directory, c.Modules.Dir)
}

