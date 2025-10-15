package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/example/data-kernel/internal/kernel"
)

func main() {
    configPath := flag.String("config", "./config/kernel.yaml", "path to kernel config")
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	k, err := kernel.NewKernel(*configPath)
	if err != nil {
		log.Printf("error: %v", err)
		os.Exit(1)
	}
	if err := k.Start(ctx); err != nil {
		log.Printf("kernel stopped with error: %v", err)
		os.Exit(1)
	}
}

