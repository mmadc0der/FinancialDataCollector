package kernel

import (
    "context"
    "crypto/sha256"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "time"

    "github.com/example/data-kernel/internal/logging"
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
    _ = stream
    consumer := fmt.Sprintf("%s-reg-%d", "kernel", time.Now().UnixNano())
    _ = consumer
    // PoC: log that registration consumer would start here
    logging.Info("register_consumer_init")
}

func sshFingerprint(pubKeyData []byte) string {
    sum := sha256.Sum256(pubKeyData)
    return base64.StdEncoding.EncodeToString(sum[:])
}
