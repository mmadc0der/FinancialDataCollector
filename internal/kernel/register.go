package kernel

import (
    "context"
    "crypto/ed25519"
    "bytes"
    "encoding/base64"
    "encoding/json"
    "errors"
    "fmt"
    "time"

    "github.com/example/data-kernel/internal/logging"
    "github.com/redis/go-redis/v9"
    ssh "golang.org/x/crypto/ssh"
    "golang.org/x/crypto/sha3"
)

// Registration message schema (in XADD values):
// id=<opaque>, payload=<json>, sig=<base64>, pubkey=<openssh_pubkey>, nonce=<random>
type regPayload struct {
    ProducerHint string            `json:"producer_hint"` // optional human-readable name
    Contact      string            `json:"contact"`       // optional
    Meta         map[string]string `json:"meta"`
}

func (k *Kernel) consumeRegister(ctx context.Context) {
    if k.rd == nil { return }
    if k.pg == nil {
        logging.Warn("register_consumer_disabled_no_pg")
        return
    }
    stream := prefixed(k.cfg.Redis.KeyPrefix, "fdc:register")
    // Ensure consumer group exists for the registration stream (ignore BUSYGROUP errors)
    if k.rd.C() != nil && k.cfg.Redis.ConsumerGroup != "" {
        _ = k.rd.C().XGroupCreateMkStream(ctx, stream, k.cfg.Redis.ConsumerGroup, "$" ).Err()
    }
    logging.Info("register_consumer_start", logging.F("stream", stream), logging.F("group", k.cfg.Redis.ConsumerGroup))
    consumer := fmt.Sprintf("%s-reg-%d", "kernel", time.Now().UnixNano())
    for ctx.Err() == nil {
        res, err := k.rd.C().XReadGroup(ctx, &redis.XReadGroupArgs{Group: k.cfg.Redis.ConsumerGroup, Consumer: consumer, Streams: []string{stream, ">"}, Count: 50, Block: 5 * time.Second}).Result()
        if err != nil && !errors.Is(err, redis.Nil) {
            logging.Warn("register_read_error", logging.Err(err))
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
                if pubkey == "" || payloadStr == "" || nonce == "" || sigB64 == "" {
                    logging.Warn("register_missing_fields", logging.F("id", m.ID))
                    _ = k.rd.Ack(ctx, m.ID); continue }
                fp := sshFingerprint([]byte(pubkey))
                logging.Info("register_received", logging.F("id", m.ID), logging.F("fingerprint", fp))
                // Nonce replay guard (best-effort via Redis)
                if k.rd != nil && k.rd.C() != nil {
                    ok, nxErr := k.rd.C().SetNX(ctx, prefixed(k.cfg.Redis.KeyPrefix, "reg:nonce:"+fp+":"+nonce), 1, time.Hour).Result()
                    if nxErr != nil {
                        logging.Warn("register_nonce_guard_error", logging.Err(nxErr), logging.F("fingerprint", fp))
                    } else if !ok {
                        logging.Warn("register_nonce_replay", logging.F("fingerprint", fp), logging.F("nonce", nonce))
                        _ = k.pg.CreateRegistration(ctx, fp, payloadStr, sigB64, nonce, "replay", "duplicate_nonce", "")
                        _ = k.rd.Ack(ctx, m.ID)
                        continue
                    }
                }
                // Parse SSH public key and support Ed25519 verification; if producer_cert_required, enforce cert signed by ProducerSSHCA
                parsedPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubkey))
                validSig := false
                if err == nil {
                    // If certificate required, unwrap cert and check CA
                    if k.cfg.Auth.ProducerCertRequired && k.cfg.Auth.ProducerSSHCA != "" {
                        caPub, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(k.cfg.Auth.ProducerSSHCA))
                        if cert, ok := parsedPub.(*ssh.Certificate); ok && caPub != nil && bytes.Equal(cert.SignatureKey.Marshal(), caPub.Marshal()) {
                            logging.Info("register_cert_verified", logging.F("fingerprint", fp), logging.F("cert_key_id", cert.KeyId))
                            parsedPub = cert.Key
                        } else {
                            logging.Warn("register_cert_invalid", logging.F("fingerprint", fp))
                            parsedPub = nil }
                    }
                    if cp, ok := parsedPub.(ssh.CryptoPublicKey); ok {
                        if edpk, ok := cp.CryptoPublicKey().(ed25519.PublicKey); ok && len(edpk) == ed25519.PublicKeySize {
                            // Canonicalize payload JSON deterministically
                            var tmp any
                            if json.Unmarshal([]byte(payloadStr), &tmp) == nil {
                                if cb, err := json.Marshal(tmp); err == nil {
                                    payloadStr = string(cb)
                                }
                            }
                            // Verify over prehashed canonical bytes (SHA3-512)
                            msg := []byte(payloadStr + "." + nonce)
                            sum := sha3.Sum512(msg)
                            sigBytes, decErr := base64.RawStdEncoding.DecodeString(sigB64)
                            if decErr != nil {
                                sigBytes, _ = base64.StdEncoding.DecodeString(sigB64)
                            }
                            if len(sigBytes) == ed25519.SignatureSize && ed25519.Verify(edpk, sum[:], sigBytes) {
                                validSig = true
                                logging.Info("register_sig_valid", logging.F("fingerprint", fp))
                            } else {
                                logging.Warn("register_sig_invalid", logging.F("fingerprint", fp))
                            }
                        }
                    }
                } else { logging.Warn("register_pubkey_parse_error", logging.F("fingerprint", fp), logging.Err(err)) }
                // Ensure producer exists/bind key if missing; create registration record and respond
                _ = k.pg.UpsertProducerKey(ctx, fp, pubkey)
                exists, status, producerID := k.pg.GetProducerKey(ctx, fp)
                if !exists || producerID == nil || *producerID == "" {
                    // create a new producer row and bind key without changing approval status
                    if pid, err := k.pg.EnsureProducerForFingerprint(ctx, fp, ""); err == nil && pid != "" {
                        producerID = &pid
                    }
                }
                regStatus := "pending"
                regReason := ""
                if !validSig { regStatus = "invalid_sig"; regReason = "signature_verification_failed" }
                _ = k.pg.CreateRegistration(ctx, fp, payloadStr, sigB64, nonce, regStatus, regReason, "")
                // Always respond (no token here)
                if producerID != nil && k.rd != nil && k.rd.C() != nil {
                    _ = k.rd.C().XAdd(ctx, &redis.XAddArgs{Stream: prefixed(k.cfg.Redis.KeyPrefix, "fdc:register:resp"), MaxLen: k.cfg.Redis.MaxLenApprox, Approx: true, Values: map[string]any{"fingerprint": fp, "producer_id": *producerID, "status": regStatus}}).Err()
                }
                _ = k.rd.Ack(ctx, m.ID)
                logging.Debug("register_ack", logging.F("id", m.ID))
            }
        }
    }
}

func sshFingerprint(pubKeyData []byte) string {
    sum := sha3.Sum512(pubKeyData)
    return base64.StdEncoding.EncodeToString(sum[:])
}

