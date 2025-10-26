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
    "github.com/example/data-kernel/internal/metrics"
    "github.com/redis/go-redis/v9"
    ssh "golang.org/x/crypto/ssh"
    "golang.org/x/crypto/sha3"
    "sync"
)

// In-memory rate limiter for better performance than Lua scripts
type RateLimiter struct {
    mu    sync.RWMutex
    store map[string]*rateLimitEntry
}

type rateLimitEntry struct {
    count     int
    windowStart time.Time
    burst     int
}

func newRateLimiter() *RateLimiter {
    rl := &RateLimiter{
        store: make(map[string]*rateLimitEntry),
    }
    // Cleanup old entries periodically
    go rl.cleanupLoop()
    return rl
}

func (rl *RateLimiter) cleanupLoop() {
    ticker := time.NewTicker(60 * time.Second)
    defer ticker.Stop()
    for range ticker.C {
        rl.cleanup()
    }
}

func (rl *RateLimiter) cleanup() {
    rl.mu.Lock()
    defer rl.mu.Unlock()

    now := time.Now()
    for key, entry := range rl.store {
        // Remove entries older than 2 minutes
        if now.Sub(entry.windowStart) > 2*time.Minute {
            delete(rl.store, key)
        }
    }
}

func (rl *RateLimiter) isAllowed(key string, rpm, burst int) bool {
    rl.mu.Lock()
    defer rl.mu.Unlock()

    now := time.Now()
    entry, exists := rl.store[key]
    if !exists || now.Sub(entry.windowStart) >= time.Minute {
        // New window or expired entry
        rl.store[key] = &rateLimitEntry{
            count:       1,
            windowStart: now,
            burst:      burst,
        }
        return true
    }

    // Check if we're within burst allowance
    if entry.count < entry.burst {
        entry.count++
        return true
    }

    // Check if we're within rate limit
    maxRequests := (rpm * int(now.Sub(entry.windowStart).Seconds())) / 60
    if entry.count < maxRequests {
        entry.count++
        return true
    }

    return false
}

var globalRateLimiter = newRateLimiter()

// Registration message schema (in XADD values):
// id=<opaque>, payload=<json>, sig=<base64>, pubkey=<openssh_pubkey>, nonce=<random>
type regPayload struct {
    ProducerHint string            `json:"producer_hint"` // optional human-readable name
    Contact      string            `json:"contact"`       // optional
    Meta         map[string]string `json:"meta"`
    ProducerID   string            `json:"producer_id,omitempty"` // optional for key rotation
}

// Rate limiting check - returns true if request should be allowed
// Uses Redis sliding window rate limiting per producer_id (fail-closed security)
func (k *Kernel) checkRateLimit(ctx context.Context, producerID string) bool {
    if k.rd == nil || k.rd.C() == nil {
        logging.Error("rate_limit_redis_unavailable")
        return false // deny if Redis unavailable (fail-closed)
    }

    rpm := k.cfg.Auth.RegistrationRateLimitRPM
    burst := k.cfg.Auth.RegistrationRateLimitBurst
    if rpm <= 0 {
        return true // no rate limiting configured
    }

    // Use sliding window rate limiting with Redis
    // Key format: fdc:rate:reg:<producer_id>
    rateKey := prefixed(k.cfg.Redis.KeyPrefix, "rate:reg:"+producerID)

    // Use in-memory rate limiter for better performance
    allowed := globalRateLimiter.isAllowed(rateKey, rpm, burst)
    if !allowed {
        logging.Info("rate_limited",
            logging.F("producer_id", producerID),
            logging.F("rpm", rpm),
            logging.F("burst", burst))
        metrics.RegistrationRateLimited.Inc()
    }

    return allowed
}


// Check nonce replay prevention
func (k *Kernel) checkNonceReplay(ctx context.Context, fingerprint, nonce string) bool {
    if k.rd == nil || k.rd.C() == nil {
        return true // allow if Redis unavailable
    }
    
    nonceKey := prefixed(k.cfg.Redis.KeyPrefix, "reg:nonce:"+fingerprint+":"+nonce)
    ok, err := k.rd.C().SetNX(ctx, nonceKey, 1, time.Hour).Result()
    if err != nil {
        logging.Info("registration_nonce_guard_error", logging.Err(err), logging.F("fingerprint", fingerprint))
        return true // allow on error
    }
    
    if !ok {
        logging.Info("registration_nonce_replay", 
            logging.F("fingerprint", fingerprint), 
            logging.F("nonce", nonce))
        return false
    }
    
    return true
}

// Verify certificate signature and TTL
func (k *Kernel) verifyCertificate(pubkey string) (bool, string, time.Time, time.Time) {
    // Producer certificate is mandatory and must be signed by configured CA
    if k.cfg.Auth.ProducerSSHCA == "" { return false, "", time.Time{}, time.Time{} }
    
    parsedPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubkey))
    if err != nil {
        logging.Info("registration_cert_parse_error", logging.Err(err))
        return false, "", time.Time{}, time.Time{}
    }
    
    cert, ok := parsedPub.(*ssh.Certificate)
    if !ok {
        logging.Info("registration_not_certificate")
        return false, "", time.Time{}, time.Time{}
    }
    
    // Check CA signature
    caPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(k.cfg.Auth.ProducerSSHCA))
    if err != nil || caPub == nil {
        logging.Info("registration_ca_parse_error", logging.Err(err))
        return false, "", time.Time{}, time.Time{}
    }
    
    if !bytes.Equal(cert.SignatureKey.Marshal(), caPub.Marshal()) {
        logging.Info("registration_ca_signature_invalid")
        return false, "", time.Time{}, time.Time{}
    }
    
    // Check TTL
    now := time.Now()
    va := time.Unix(int64(cert.ValidAfter), 0)
    vb := time.Unix(int64(cert.ValidBefore), 0)
    if cert.ValidAfter != 0 && now.Before(time.Unix(int64(cert.ValidAfter), 0)) {
        logging.Info("registration_cert_not_yet_valid", 
            logging.F("valid_after", va))
        return false, "", time.Time{}, time.Time{}
    }
    
    if cert.ValidBefore != 0 && now.After(time.Unix(int64(cert.ValidBefore), 0)) {
        logging.Info("registration_cert_expired", 
            logging.F("valid_before", vb))
        return false, "", time.Time{}, time.Time{}
    }

    // Do not log here to avoid duplicate events; caller will emit a single combined log
    return true, cert.KeyId, va, vb
}

// Verify signature over payload + nonce
func (k *Kernel) verifySignature(pubkey, payloadStr, nonce, sigB64 string) bool {
    parsedPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubkey))
    if err != nil {
        logging.Info("registration_pubkey_parse_error", logging.Err(err))
        return false
    }
    
    // If certificate required, unwrap cert
    // Always require CA-signed certificate; unwrap to raw key for signature verify
    if k.cfg.Auth.ProducerSSHCA == "" { logging.Info("registration_cert_missing_ca"); return false }
    caPub, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(k.cfg.Auth.ProducerSSHCA))
    if cert, ok := parsedPub.(*ssh.Certificate); ok && caPub != nil && bytes.Equal(cert.SignatureKey.Marshal(), caPub.Marshal()) {
        parsedPub = cert.Key
    } else {
        logging.Info("registration_cert_invalid")
        return false
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
            // Verify raw Ed25519 signature over canonical bytes (no prehash)
            msg := []byte(payloadStr + "." + nonce)
            sigBytes, decErr := base64.RawStdEncoding.DecodeString(sigB64)
            if decErr != nil {
                sigBytes, _ = base64.StdEncoding.DecodeString(sigB64)
            }
            if len(sigBytes) == ed25519.SignatureSize && ed25519.Verify(edpk, msg, sigBytes) {
                logging.Info("registration_sig_valid")
                return true
            } else {
                logging.Info("registration_sig_invalid")
                return false
            }
        }
    }
    
    logging.Info("registration_unsupported_key_type")
    return false
}

// Send response to Redis stream
func (k *Kernel) sendRegistrationResponse(ctx context.Context, nonce string, response map[string]any) {
    if k.rd == nil || k.rd.C() == nil {
        logging.Error("registration_response_error", logging.F("error", "redis_unavailable"))
        return
    }

    respStream := prefixed(k.cfg.Redis.KeyPrefix, "register:resp:"+nonce)
    ttl := time.Duration(k.cfg.Auth.RegistrationResponseTTLSeconds) * time.Second
    if ttl <= 0 {
        ttl = 5 * time.Minute // default
    }

    // Log the response being sent for debugging
    logging.Info("registration_response_sending",
        logging.F("nonce", nonce),
        logging.F("stream", respStream),
        logging.F("status", response["status"]))

    err := k.rd.C().XAdd(ctx, &redis.XAddArgs{
        Stream: respStream,
        Values: response,
    }).Err()

    if err != nil {
        logging.Info("registration_response_error", logging.Err(err), logging.F("stream", respStream))
    } else {
        // Set TTL on response stream
        if expireErr := k.rd.C().Expire(ctx, respStream, ttl).Err(); expireErr != nil {
            logging.Info("registration_response_ttl_error", logging.Err(expireErr), logging.F("stream", respStream))
        }
    }
}

// Main registration consumer with new state machine
func (k *Kernel) consumeRegister(ctx context.Context) {
    if k.rd == nil { 
        logging.Info("registration_consumer_disabled_no_redis")
        return 
    }
    if k.pg == nil {
        logging.Info("registration_consumer_disabled_no_pg")
        return
    }
    
    stream := prefixed(k.cfg.Redis.KeyPrefix, "register")
    // Ensure consumer group exists for the registration stream (ignore BUSYGROUP errors)
    if k.rd.C() != nil && k.cfg.Redis.ConsumerGroup != "" {
        _ = k.rd.C().XGroupCreateMkStream(ctx, stream, k.cfg.Redis.ConsumerGroup, "0-0" ).Err()
    }
    
    logging.Info("register_consumer_start", 
        logging.F("stream", stream), 
        logging.F("group", k.cfg.Redis.ConsumerGroup))
    
    consumer := fmt.Sprintf("%s-reg-%d", "kernel", time.Now().UnixNano())
    
    for ctx.Err() == nil {
        res, err := k.rd.C().XReadGroup(ctx, &redis.XReadGroupArgs{
            Group: k.cfg.Redis.ConsumerGroup, 
            Consumer: consumer, 
            Streams: []string{stream, ">"}, 
            Count: 50, 
            Block: 5 * time.Second,
        }).Result()
        
        if err != nil && !errors.Is(err, redis.Nil) {
            logging.Info("register_read_error", logging.Err(err))
            time.Sleep(200 * time.Millisecond)
            continue
        }
        if len(res) == 0 { continue }
        
        for _, s := range res {
            for _, m := range s.Messages {
                k.processRegistrationMessage(ctx, m)
            }
        }
    }
}

// Process a single registration message
func (k *Kernel) processRegistrationMessage(ctx context.Context, m redis.XMessage) {
    // Extract fields
    pubkey, _ := m.Values["pubkey"].(string)
    payloadStr, _ := m.Values["payload"].(string)
    nonce, _ := m.Values["nonce"].(string)
    sigB64, _ := m.Values["sig"].(string)
    action, _ := m.Values["action"].(string)
    
    if pubkey == "" || payloadStr == "" || nonce == "" || sigB64 == "" {
        logging.Info("registration_missing_fields", logging.F("id", m.ID))
        k.rd.Ack(ctx, m.ID)
        return
    }
    
    fp := sshFingerprint([]byte(pubkey))
    logging.Info("registration_received",
        logging.F("id", m.ID),
        logging.F("fingerprint", fp),
        logging.F("action", action))

    // Parse payload first to get producer_id for rate limiting
    var payload regPayload
    if err := json.Unmarshal([]byte(payloadStr), &payload); err != nil {
        logging.Info("registration_payload_parse_error",
            logging.F("fingerprint", fp),
            logging.Err(err))
        k.rd.Ack(ctx, m.ID)
        return
    }

    // For new producers, we don't have producer_id yet, so we'll use fingerprint for rate limiting
    // For existing producers, we'll use producer_id
    var rateLimitID string
    if payload.ProducerID != "" {
        rateLimitID = payload.ProducerID
    } else {
        rateLimitID = fp // fallback to fingerprint for new producers
    }

    // Rate limiting check per producer_id/fingerprint
    if !k.checkRateLimit(ctx, rateLimitID) {
        k.rd.Ack(ctx, m.ID)
        return // silent drop for rate limited requests
    }
    
    // Check nonce replay
    if !k.checkNonceReplay(ctx, fp, nonce) {
        // Create registration record for audit
        k.pg.CreateRegistration(ctx, fp, payloadStr, sigB64, nonce, "replay", "duplicate_nonce", "")
        k.rd.Ack(ctx, m.ID)
        return
    }
    
    // Verify signature
    if !k.verifySignature(pubkey, payloadStr, nonce, sigB64) {
        logging.Info("registration_signature_invalid", logging.F("fingerprint", fp))
        k.pg.CreateRegistration(ctx, fp, payloadStr, sigB64, nonce, "invalid_sig", "signature_verification_failed", "")
        k.sendRegistrationResponse(ctx, nonce, map[string]any{
            "fingerprint": fp,
            "status": "invalid_sig",
            "reason": "signature_verification_failed",
        })
        k.rd.Ack(ctx, m.ID)
        return
    }
    
    // Verify certificate if required
    if true {
        certValid, keyID, validAfter, validBefore := k.verifyCertificate(pubkey)
        if !certValid {
            logging.Info("registration_cert_invalid", logging.F("fingerprint", fp))
            k.pg.CreateRegistration(ctx, fp, payloadStr, sigB64, nonce, "invalid_cert", "certificate_verification_failed", "")
            k.sendRegistrationResponse(ctx, nonce, map[string]any{
                "fingerprint": fp,
                "status": "invalid_cert",
                "reason": "certificate_verification_failed",
            })
            k.rd.Ack(ctx, m.ID)
            return
        }
        logging.Info("registration_cert_verified",
            logging.F("fingerprint", fp),
            logging.F("cert_key_id", keyID),
            logging.F("valid_after", validAfter),
            logging.F("valid_before", validBefore))
    }

    // Atomically create producer and bind fingerprint for first-time registration
    var producerID string
    var err error
    producerID, err = k.pg.RegisterProducerKey(ctx, fp, pubkey, payload.ProducerHint, payload.Contact, payload.Meta)
    if err != nil {
        logging.Error("registration_producer_key_register_error",
            logging.F("fingerprint", fp),
            logging.Err(err))
        k.rd.Ack(ctx, m.ID)
        return
    }
    logging.Info("registration_producer_registered", logging.F("producer_id", producerID), logging.F("fingerprint", fp), logging.F("hint", payload.ProducerHint))

    // Handle deregister action
    if action == "deregister" {
        k.handleDeregister(ctx, producerID, fp, m.ID, nonce)
        return
    }

    // Check current key status (should exist now after RegisterProducerKey)
    status, statusProducerID, err := k.pg.GetKeyStatus(ctx, fp)
    if err != nil {
        logging.Error("registration_status_check_error",
            logging.F("producer_id", producerID),
            logging.F("fingerprint", fp),
            logging.Err(err))
        k.rd.Ack(ctx, m.ID)
        return
    }
    _ = statusProducerID // unused but part of API

    // Create pending registration record for audit
    _ = k.pg.CreateRegistration(ctx, fp, payloadStr, sigB64, nonce, status, "", "")

    // State machine based on current status
    switch status {
    case "approved":
        k.handleKnownApproved(ctx, producerID, fp, m.ID, nonce)
    case "pending":
        k.handleKnownPending(ctx, producerID, fp, m.ID, nonce)
    case "revoked", "superseded":
        k.handleKnownDenied(ctx, &producerID, fp, status, m.ID, nonce)
    default:
        // This shouldn't happen after RegisterProducerKey, but handle gracefully
        logging.Info("registration_unknown_status", logging.F("producer_id", producerID), logging.F("status", status))
        k.handleNewProducer(ctx, producerID, fp, payload, payloadStr, sigB64, nonce, m.ID)
    }
}

// Handle deregister action
func (k *Kernel) handleDeregister(ctx context.Context, producerID, fp string, msgID, nonce string) {
    logging.Info("registration_deregister_received", logging.F("producer_id", producerID))
    
    err := k.pg.DisableProducer(ctx, producerID)
    if err != nil {
        logging.Error("registration_deregister_error",
            logging.F("producer_id", producerID),
            logging.Err(err))
    } else {
        logging.Info("registration_deregister_success",
            logging.F("producer_id", producerID))
    }
    
    k.sendRegistrationResponse(ctx, nonce, map[string]any{
        "fingerprint": fp,
        "producer_id": producerID,
        "status": "deregistered",
    })
    k.rd.Ack(ctx, msgID)
}

// Handle known approved key
func (k *Kernel) handleKnownApproved(ctx context.Context, producerID, fp string, msgID, nonce string) {
    logging.Info("registration_known_approved", 
        logging.F("producer_id", producerID), 
        logging.F("fingerprint", fp))
    
    k.sendRegistrationResponse(ctx, nonce, map[string]any{
        "fingerprint": fp,
        "producer_id": producerID,
        "status": "approved",
    })
    k.rd.Ack(ctx, msgID)
}

// Handle known pending key
func (k *Kernel) handleKnownPending(ctx context.Context, producerID, fp string, msgID, nonce string) {
    logging.Info("registration_known_pending", 
        logging.F("producer_id", producerID), 
        logging.F("fingerprint", fp))
    
    // Silent - no response for pending keys per protocol
    k.rd.Ack(ctx, msgID)
}

// Handle known denied key
func (k *Kernel) handleKnownDenied(ctx context.Context, producerID *string, fp, status, msgID, nonce string) {
    var pid string
    if producerID != nil { pid = *producerID }
    logging.Info("registration_known_denied",
        logging.F("producer_id", pid),
        logging.F("status", status))
    
    k.sendRegistrationResponse(ctx, nonce, map[string]any{
        "fingerprint": fp,
        "producer_id": pid,
        "status": "denied",
        "reason": status,
    })
    k.rd.Ack(ctx, msgID)
}

// Handle new producer registration (fallback - should not occur post-RegisterProducerKey)
func (k *Kernel) handleNewProducer(ctx context.Context, producerID, fp string, payload regPayload, payloadStr, sigB64, nonce, msgID string) {
    logging.Info("registration_new_producer", logging.F("producer_id", producerID))
    
    k.sendRegistrationResponse(ctx, nonce, map[string]any{
        "fingerprint": fp,
        "producer_id": producerID,
        "status": "pending",
    })
    k.rd.Ack(ctx, msgID)
}

func sshFingerprint(pubKeyData []byte) string {
    sum := sha3.Sum512(pubKeyData)
    return base64.StdEncoding.EncodeToString(sum[:])
}
