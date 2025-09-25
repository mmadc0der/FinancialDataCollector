package kernel

import (
    "context"
    "fmt"
    "log"
    "net/http"
    "time"

    "github.com/example/data-kernel/internal/kernelcfg"
    "github.com/example/data-kernel/internal/supervisor"
)

type Kernel struct {
	cfg *kernelcfg.Config
	ws  *wsServer
    rt  *router
}

func NewKernel(configPath string) (*Kernel, error) {
	cfg, err := kernelcfg.Load(configPath)
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}
	return &Kernel{cfg: cfg}, nil
}

func (k *Kernel) Start(ctx context.Context) error {
	log.Printf("kernel starting on %s", k.cfg.Server.Listen)

    r, err := newRouter(k.cfg)
    if err != nil {
        return err
    }
    k.rt = r

    k.ws = newWSServer(k.cfg, k.routeRaw)
	server := &http.Server{Addr: k.cfg.Server.Listen, Handler: k.ws}

    // start supervisor for modules
    sup := supervisor.NewSupervisor(k.cfg.Modules.Dir)
    if err := sup.Start(ctx); err != nil {
        log.Printf("supervisor error: %v", err)
    }

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


