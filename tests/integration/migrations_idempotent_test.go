//go:build integration

package it

import (
    "context"
    "os"
    "testing"
    "time"

    itutil "github.com/example/data-kernel/tests/itutil"
    "github.com/example/data-kernel/internal/data"
)

func TestMigrations_Idempotent(t *testing.T) {
    if os.Getenv("RUN_IT") == "" { t.Skip("integration test; set RUN_IT=1 to run") }
    pgc, dsn := itutil.StartPostgres(t)
    defer pgc.Terminate(context.Background())
    itutil.WaitForPostgresReady(t, dsn, 10*time.Second)

    pg, err := data.NewPostgres(context.Background(), itutil.NewPostgresConfig(dsn))
    if err != nil { t.Fatalf("pg: %v", err) }
    itutil.WaitForMigrations(t, pg, 10*time.Second)
    // Run again explicitly
    if err := pg.ApplyMigrations(context.Background()); err != nil { t.Fatalf("apply again: %v", err) }
    pg.Close()
}
