package kernel

import (
    "context"
    "crypto/ed25519"
    "crypto/sha256"
    "encoding/base64"
    "encoding/json"
    "errors"
    "fmt"
    "time"

    "github.com/example/data-kernel/internal/logging"
    "github.com/example/data-kernel/internal/data"
    "github.com/redis/go-redis/v9"
    ssh "golang.org/x/crypto/ssh"
)

// Registration message schema (in XADD values):
// id=<opaque>, payload=<json>, sig=<base64>, pubkey=<openssh_pubkey>, nonce=<random>
type regPayload struct {
    ProducerHint string            `json:"producer_hint"` // optional human-readable name
    Contact      string            `json:"contact"`       // optional
    Meta         map[string]string `json:"meta"`
}

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
                // Nonce replay guard (best-effort via Redis)
                if k.rd != nil && k.rd.C() != nil {
                    if ok, _ := k.rd.C().SetNX(ctx, prefixed(k.cfg.Redis.KeyPrefix, "reg:nonce:"+fp+":"+nonce), 1, time.Hour).Result(); !ok {
                        _ = k.pg.CreateRegistration(ctx, fp, payloadStr, sigB64, nonce, "replay", "duplicate_nonce", "")
                        _ = k.rd.Ack(ctx, m.ID)
                        continue
                    }
                }
                // Parse SSH public key and support Ed25519 verification
                parsedPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubkey))
                validSig := false
                if err == nil {
                    if cp, ok := parsedPub.(ssh.CryptoPublicKey); ok {
                        if edpk, ok := cp.CryptoPublicKey().(ed25519.PublicKey); ok && len(edpk) == ed25519.PublicKeySize {
                            // Canonicalize payload JSON deterministically
                            var tmp any
                            if json.Unmarshal([]byte(payloadStr), &tmp) == nil {
                                if cb, err := json.Marshal(tmp); err == nil {
                                    payloadStr = string(cb)
                                }
                            }
                            // Verify over exact canonical bytes
                            msg := []byte(payloadStr + "." + nonce)
                            sigBytes, decErr := base64.RawStdEncoding.DecodeString(sigB64)
                            if decErr != nil {
                                sigBytes, _ = base64.StdEncoding.DecodeString(sigB64)
                            }
                            if len(sigBytes) == ed25519.SignatureSize && ed25519.Verify(edpk, msg, sigBytes) {
                                validSig = true
                            }
                        }
                    }
                }
                // Upsert key and create registration record
                _ = k.pg.UpsertProducerKey(ctx, fp, pubkey)
                exists, status, producerID := k.pg.GetProducerKey(ctx, fp)
                regStatus := "pending"
                regReason := ""
                if !validSig { regStatus = "invalid_sig"; regReason = "signature_verification_failed" }
                _ = k.pg.CreateRegistration(ctx, fp, payloadStr, sigB64, nonce, regStatus, regReason, "")
                if validSig && exists && status == "approved" && producerID != nil && k.au != nil && k.pg != nil {
                    // Atomically gate via DB and record token metadata
                    tok, jti, exp, err := k.au.Issue(ctx, *producerID, time.Hour, "auto-refresh", fp)
                    if err == nil {
                        if pid, perr := k.pg.TryAutoIssueAndRecord(ctx, fp, jti, exp, "auto-refresh"); perr == nil && pid != "" {
                            logging.Info("register_auto_issue", logging.F("fingerprint", fp))
                            if k.cfg.Redis.RegisterRespStream != "" && k.rd != nil && k.rd.C() != nil {
                                _ = k.rd.C().XAdd(ctx, &redis.XAddArgs{
                                    Stream: prefixed(k.cfg.Redis.KeyPrefix, k.cfg.Redis.RegisterRespStream),
                                    MaxLen: k.cfg.Redis.MaxLenApprox,
                                    Approx: true,
                                    Values: map[string]any{"fingerprint": fp, "token": tok, "producer_id": pid},
                                }).Err()
                            }
                        }
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

