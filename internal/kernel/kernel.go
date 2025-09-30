package kernel

import (
    "context"
    "fmt"
    "net/http"
    "time"

    "github.com/example/data-kernel/internal/kernelcfg"
    "github.com/example/data-kernel/internal/logging"
    "github.com/example/data-kernel/internal/metrics"
    "github.com/example/data-kernel/internal/supervisor"
)

type Kernel struct {
	cfg *kernelcfg.Config
	ws  *wsServer
    rt  *router
    inbound chan []byte
}

func NewKernel(configPath string) (*Kernel, error) {
	cfg, err := kernelcfg.Load(configPath)
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}
	return &Kernel{cfg: cfg}, nil
}

func (k *Kernel) Start(ctx context.Context) error {
    stopLog := logging.Init(k.cfg.Logging)
    defer stopLog()
    logging.Info("kernel_start", logging.F("listen", k.cfg.Server.Listen))

    r, err := newRouter(k.cfg)
    if err != nil {
        return err
    }
    k.rt = r

    // Bounded ingest queue for backpressure
    qsize := k.cfg.Server.IngestQueueSize
    if qsize <= 0 {
        qsize = 8192
    }
    k.inbound = make(chan []byte, qsize)

    // Start dispatcher goroutine
    go func() {
        for {
            select {
            case <-ctx.Done():
                return
            case msg := <-k.inbound:
                k.routeRaw(msg)
            }
        }
    }()

    k.ws = newWSServer(k.cfg, k.enqueueRaw)
    mux := http.NewServeMux()
    mux.Handle("/ws", k.ws)
    mux.Handle("/metrics", metrics.Handler())
    server := &http.Server{Addr: k.cfg.Server.Listen, Handler: mux}

    // start supervisor for modules
    sup := supervisor.NewSupervisor(k.cfg.Modules.Dir)
    _ = sup.Start(ctx)

    go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}


// enqueueRaw attempts to enqueue without blocking; drops when full
func (k *Kernel) enqueueRaw(msg []byte) {
    select {
    case k.inbound <- msg:
    default:
        logging.Warn("ingest_drop", logging.F("reason", "queue_full"))
        // metrics.IngestDropped.Add(1) // avoid import cycle; accounted in WS metrics
    }
}


