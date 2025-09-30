package kernelcfg

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server ServerConfig `yaml:"server"`
	Sinks  SinksConfig  `yaml:"sinks"`
	Modules ModulesConfig `yaml:"modules"`
    Postgres PostgresConfig `yaml:"postgres"`
    Redis RedisConfig `yaml:"redis"`
    Logging LoggingConfig `yaml:"logging"`
}

type ServerConfig struct {
	Listen          string `yaml:"listen"`
	AuthToken       string `yaml:"auth_token"`
	MaxMessageBytes int64  `yaml:"max_message_bytes"`
	ReadTimeoutMs   int    `yaml:"read_timeout_ms"`
    AllowedOrigins  []string `yaml:"allowed_origins"`
    WindowSize      int    `yaml:"window_size"`
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

type ModulesConfig struct {
	Dir string `yaml:"dir"`
}

type PostgresConfig struct {
    Enabled bool `yaml:"enabled"`
    DSN string `yaml:"dsn"`
    MaxConns int `yaml:"max_conns"`
    ConnMaxLifetimeMs int `yaml:"conn_max_lifetime_ms"`
    ApplyMigrations bool `yaml:"apply_migrations"`
    QueueSize int `yaml:"queue_size"`
}

type RedisConfig struct {
    Enabled bool `yaml:"enabled"`
    Addr string `yaml:"addr"`
    Username string `yaml:"username"`
    Password string `yaml:"password"`
    DB int `yaml:"db"`
    Stream string `yaml:"stream"`
    MaxLenApprox int64 `yaml:"maxlen_approx"`
    QueueSize int `yaml:"queue_size"`
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
	if cfg.Modules.Dir == "" {
		cfg.Modules.Dir = "./modules.d"
	}
    // Env overrides for secrets
    if v := os.Getenv("KERNEL_AUTH_TOKEN"); v != "" {
        cfg.Server.AuthToken = v
    }
    if v := os.Getenv("KERNEL_AUTH_TOKEN_FILE"); v != "" {
        if b, err := os.ReadFile(v); err == nil { cfg.Server.AuthToken = strings.TrimSpace(string(b)) }
    }
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
	return &cfg, nil
}

func (c *Config) String() string {
	return fmt.Sprintf("listen=%s file.dir=%s modules.dir=%s", c.Server.Listen, c.Sinks.File.Directory, c.Modules.Dir)
}

