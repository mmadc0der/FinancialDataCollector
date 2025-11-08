package logging

import (
	"encoding/json"
	"io"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/example/data-kernel/internal/kernelcfg"
)

type Level int32

const (
	DebugLevel Level = iota
	InfoLevel
	WarnLevel
	ErrorLevel
)

type Field struct {
	Key   string
	Value any
}

func F(key string, value any) Field { return Field{Key: key, Value: value} }
func Err(err error) Field {
    if err == nil { return Field{Key: "err", Value: nil} }
    return Field{Key: "err", Value: err.Error()}
}

type event struct {
	TS    int64          `json:"ts"`
	Level string         `json:"level"`
	Msg   string         `json:"msg"`
	Fields map[string]any `json:"fields,omitempty"`
}

var (
    logLevel atomic.Int32
    logCh    chan event
    dropped  atomic.Int64
    stopCh   chan struct{}
    writer   io.Writer = os.Stdout
)

func parseLevel(s string) Level {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "debug":
		return DebugLevel
	case "warn":
		return WarnLevel
	case "error":
		return ErrorLevel
	default:
		return InfoLevel
	}
}

func Init(cfg kernelcfg.LoggingConfig) func() {
    if cfg.Buffer <= 0 {
        cfg.Buffer = 4096
    }
    // Create per-init channels, but keep exporting logCh globally for callers.
    localLogCh := make(chan event, cfg.Buffer)
    logCh = localLogCh
    logLevel.Store(int32(parseLevel(cfg.Level)))
    localStop := make(chan struct{})
    stopCh = localStop // retained for diagnostics if needed, not used by drain
    // Select output writer and capture it for this drain instance
    switch cfg.Output {
    case "stderr":
        writer = os.Stderr
    case "stdout", "":
        writer = os.Stdout
    default:
        f, err := os.OpenFile(cfg.Output, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
        if err == nil {
            writer = f
        }
    }
    localWriter := writer
    go drain(localLogCh, localStop, localWriter)
    return func() { close(localStop) }
}

func drain(ch <-chan event, stop <-chan struct{}, w io.Writer) {
    flushTicker := time.NewTicker(10 * time.Second)
    defer flushTicker.Stop()
    enc := json.NewEncoder(w)
    for {
        select {
        case ev := <-ch:
            _ = enc.Encode(ev)
        case <-flushTicker.C:
            if n := dropped.Swap(0); n > 0 {
                _ = enc.Encode(event{TS: time.Now().UnixNano(), Level: "warn", Msg: "logs_dropped", Fields: map[string]any{"count": n}})
            }
		case <-stop:
			for {
				select {
				case ev := <-ch:
					_ = enc.Encode(ev)
				default:
					if n := dropped.Swap(0); n > 0 {
						_ = enc.Encode(event{TS: time.Now().UnixNano(), Level: "warn", Msg: "logs_dropped", Fields: map[string]any{"count": n}})
					}
					return
				}
			}
        }
    }
}

func allowed(l Level) bool { return l >= Level(logLevel.Load()) }

func log(lvl Level, msg string, fields ...Field) {
	if !allowed(lvl) || logCh == nil {
		return
	}
	fm := make(map[string]any, len(fields))
	for _, f := range fields {
		fm[f.Key] = f.Value
	}
	ev := event{TS: time.Now().UnixNano(), Level: toStr(lvl), Msg: msg}
	if len(fm) > 0 {
		ev.Fields = fm
	}
	select {
	case logCh <- ev:
	default:
		dropped.Add(1)
	}
}

func toStr(l Level) string {
	switch l {
	case DebugLevel:
		return "debug"
	case InfoLevel:
		return "info"
	case WarnLevel:
		return "warn"
	case ErrorLevel:
		return "error"
	default:
		return "info"
	}
}

func Debug(msg string, fields ...Field) { log(DebugLevel, msg, fields...) }
func Info(msg string, fields ...Field)  { log(InfoLevel, msg, fields...) }
func Warn(msg string, fields ...Field)  { log(WarnLevel, msg, fields...) }
func Error(msg string, fields ...Field) { log(ErrorLevel, msg, fields...) }

