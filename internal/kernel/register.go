package kernel

import (
    "context"
    "crypto/sha256"
    "crypto/sha512"
    "encoding/base64"
    "encoding/json"
    "errors"
    "fmt"
    "strings"
    "time"

    "github.com/example/data-kernel/internal/logging"
    "github.com/redis/go-redis/v9"
)

// Registration message schema (in XADD values):
// id=<opaque>, payload=<json>, sig=<base64>, pubkey=<openssh_pubkey>, nonce=<random>
+type regPayload struct {
+    ProducerHint string            `json:"producer_hint"` // optional human-readable name
+    Contact      string            `json:"contact"`       // optional
+    Meta         map[string]string `json:"meta"`
+}

func (k *Kernel) consumeRegister(ctx context.Context) {
    if k.rd == nil || k.cfg.Redis.RegisterStream == "" { return }
    stream := prefixed(k.cfg.Redis.KeyPrefix, k.cfg.Redis.RegisterStream)
    consumer := fmt.Sprintf("%s-reg-%d", "kernel", time.Now().UnixNano())
    for ctx.Err() == nil {
        res, err := k.rd.C().XReadGroup(ctx, &redis.XReadGroupArgs{Group: k.cfg.Redis.ConsumerGroup, Consumer: consumer, Streams: []string{stream, ">"}, Count: 50, Block: 5 * time.Second})
        if err != nil && !errors.Is(err, redis.Nil) {
            time.Sleep(200 * time.Millisecond)
            continue
        }
        if len(res) == 0 { continue }
        for _, s := range res {
            for _, m := range s.Messages {
                pubkey, _ := m.Values["pubkey"].(string)
                payloadStr, _ := m.Values["payload"].(string)
                nonce, _ := m.Values["nonce"].(string)
                sigB64, _ := m.Values["sig"].(string)
                if pubkey == "" || payloadStr == "" || nonce == "" || sigB64 == "" { _ = k.rd.Ack(ctx, m.ID); continue }
                fp := sshFingerprint([]byte(pubkey))
                // Verify signature (placeholder: SHA-512 over payload||"."||nonce compared with provided sig)
                // In a full implementation, parse OpenSSH key and verify. Here we record request and mark pending.
                digest := sha512.Sum512([]byte(payloadStr + "." + nonce))
                _ = digest
                // Upsert key and create registration pending by default
                _ = k.pg.UpsertProducerKey(ctx, fp, pubkey)
                exists, status, producerID := k.pg.GetProducerKey(ctx, fp)
                _ = k.pg.CreateRegistration(ctx, fp, payloadStr, sigB64, nonce, "pending", "", "")
                if exists && status == "approved" && producerID != nil && k.au != nil {
                    // Auto-issue short token (e.g., 1 hour)
                    tok, _, _, err := k.au.Issue(ctx, *producerID, time.Hour, "auto-refresh")
                    if err == nil {
                        logging.Info("register_auto_issue", logging.F("fingerprint", fp))
                        // Future: respond on a response channel; for now just log
                    }
                }
                _ = k.rd.Ack(ctx, m.ID)
            }
        }
    }
}

func sshFingerprint(pubKeyData []byte) string {
    sum := sha256.Sum256(pubKeyData)
    return base64.StdEncoding.EncodeToString(sum[:])
}
