package main

import (
    "context"
    "flag"
    "os"
    "os/signal"
    "syscall"

    "github.com/example/data-kernel/internal/kernel"
    "github.com/example/data-kernel/internal/logging"
)

func main() {
    configPath := flag.String("config", "./config/kernel.yaml", "path to kernel config")
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

    k, err := kernel.NewKernel(*configPath)
    if err != nil {
        ev := logging.NewEventLogger()
        ev.Infra("init", "kernel", "failed", "new_kernel_error: "+err.Error())
        os.Exit(1)
    }
    if err := k.Start(ctx); err != nil {
        ev := logging.NewEventLogger()
        ev.Infra("error", "kernel", "failed", "start_error: "+err.Error())
        os.Exit(1)
    }
}

