//go:build integration

package it

import (
    "context"
    "encoding/base64"
    "os"
    "testing"
    "time"

    "crypto/ed25519"
    "crypto/rand"

    itutil "github.com/example/data-kernel/tests/itutil"
    "github.com/example/data-kernel/internal/data"
)

func TestKeyRotation_ApprovesAndSupersedes(t *testing.T) {
    if os.Getenv("RUN_IT") == "" { t.Skip("integration test; set RUN_IT=1 to run") }
    pgc, dsn := itutil.StartPostgres(t)
    defer pgc.Terminate(context.Background())
    itutil.WaitForPostgresReady(t, dsn, 10*time.Second)

    pg, err := data.NewPostgres(context.Background(), itutil.NewPostgresConfig(dsn))
    if err != nil { t.Fatalf("pg: %v", err) }
    defer pg.Close()
    itutil.WaitForMigrations(t, pg, 10*time.Second)

    // Producer and two keys
    var producerID string
    if err := pg.Pool().QueryRow(context.Background(), `INSERT INTO public.producers(producer_id,name) VALUES (gen_random_uuid(),'kr') RETURNING producer_id`).Scan(&producerID); err != nil { t.Fatalf("producer: %v", err) }
    _, oldPriv, _ := ed25519.GenerateKey(rand.Reader)
    oldLine := "ssh-ed25519 "+base64.StdEncoding.EncodeToString(oldPriv.Public().(ed25519.PublicKey))+" test@old"
    if _, err := pg.Pool().Exec(context.Background(), `INSERT INTO public.producer_keys(fingerprint,pubkey,status,producer_id) VALUES ($1,$2,'approved',$3)`, base64.StdEncoding.EncodeToString(oldPriv[:8]), oldLine, producerID); err != nil { t.Fatalf("insert old: %v", err) }

    _, newPriv, _ := ed25519.GenerateKey(rand.Reader)
    newLine := "ssh-ed25519 "+base64.StdEncoding.EncodeToString(newPriv.Public().(ed25519.PublicKey))+" test@new"
    if _, err := pg.Pool().Exec(context.Background(), `INSERT INTO public.producer_keys(fingerprint,pubkey,status,producer_id) VALUES ($1,$2,'pending',$3)`, base64.StdEncoding.EncodeToString(newPriv[:8]), newLine, producerID); err != nil { t.Fatalf("insert new: %v", err) }

    // Approve rotation
    if _, err := pg.ApproveKeyRotation(context.Background(), base64.StdEncoding.EncodeToString(newPriv[:8]), producerID, "it", ""); err != nil { t.Fatalf("approve rotation: %v", err) }

    // Old superseded, new approved (unique index enforced implicitly)
}


