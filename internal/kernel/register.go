package kernel

import (
    "bytes"
    "context"
    "crypto/ed25519"
    "encoding/base64"
    "encoding/json"
    "errors"
    "fmt"
    "time"

    "sync"
    "strings"

    "github.com/example/data-kernel/internal/logging"
    "github.com/example/data-kernel/internal/metrics"
    "github.com/example/data-kernel/internal/protocol"
    "github.com/redis/go-redis/v9"
    "golang.org/x/crypto/sha3"
    ssh "golang.org/x/crypto/ssh"
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
// Uses Redis sliding window rate limiting per producer_id (fail-open when Redis unavailable)
func (k *Kernel) checkRateLimit(ctx context.Context, op, producerID string) bool {
    ev := logging.NewEventLogger()

    if k.rd == nil || k.rd.C() == nil {
        ev.Infra("error", "redis", "failed", "rate limit check: redis unavailable - allowing request")
        return true // allow if Redis unavailable (fail-open for rate limiting)
    }

    rpm := k.cfg.Auth.RegistrationRateLimitRPM
    burst := k.cfg.Auth.RegistrationRateLimitBurst
    if rpm <= 0 {
        return true // no rate limiting configured
    }

    // Distributed token bucket via Redis Lua (atomic)
    // Keys/Args: KEYS[1]=bucket key, ARGV[1]=capacity, ARGV[2]=refill_rate_tokens_per_sec
    rateKey := prefixed(k.cfg.Redis.KeyPrefix, fmt.Sprintf("rl:%s:%s", op, producerID))
    lua := `
local key = KEYS[1]
local capacity = tonumber(ARGV[1])
local refill = tonumber(ARGV[2])
local now = redis.call('TIME')
local now_s = tonumber(now[1])
local data = redis.call('HMGET', key, 'tokens', 'ts')
local tokens = tonumber(data[1]) or capacity
local ts = tonumber(data[2]) or now_s
local delta = now_s - ts
if delta > 0 then
  tokens = math.min(capacity, tokens + delta * refill)
end
local allowed = 0
if tokens >= 1 then
  tokens = tokens - 1
  allowed = 1
end
redis.call('HMSET', key, 'tokens', tokens, 'ts', now_s)
redis.call('EXPIRE', key, 120)
return allowed
`
    refill := float64(rpm) / 60.0
    // Eval returns int64 1/0
    res, err := k.rd.C().Eval(ctx, lua, []string{rateKey}, burst, refill).Int()
    if err != nil {
        ev.Infra("error", "redis", "failed", fmt.Sprintf("rate limit eval error: %v - allowing request", err))
        return true // allow on Redis errors (fail-open)
    }
    if res == 0 {
        metrics.RegistrationRateLimited.Inc()
        metrics.RateLimitDeny.WithLabelValues(op).Inc()
        return false
    }
    metrics.RateLimitAllow.WithLabelValues(op).Inc()
    return true
}


// Check nonce replay prevention
func (k *Kernel) checkNonceReplay(ctx context.Context, fingerprint, nonce string) bool {
    ev := logging.NewEventLogger()
    
    if k.rd == nil || k.rd.C() == nil {
        ev.Infra("error", "redis", "failed", "nonce replay check: redis unavailable")
        return true // allow if Redis unavailable
    }
    
    nonceKey := prefixed(k.cfg.Redis.KeyPrefix, "reg:nonce:"+fingerprint+":"+nonce)
    ok, err := k.rd.C().SetNX(ctx, nonceKey, 1, time.Hour).Result()
    if err != nil {
        ev.Infra("error", "redis", "failed", fmt.Sprintf("nonce guard error: %v", err))
        return true // allow on error
    }
    
    if !ok {
        // Replay detected - log as security event
        ev.Registration("replay", fingerprint, "", "", "duplicate_nonce")
        return false
    }
    
    return true
}

// Verify certificate signature and TTL
func (k *Kernel) verifyCertificate(pubkey string) (bool, string, time.Time, time.Time) {
    ev := logging.NewEventLogger()
    
    // Producer certificate is mandatory and must be signed by configured CA
    if k.cfg.Auth.ProducerSSHCA == "" { 
        ev.Infra("error", "auth", "failed", "certificate verification: ProducerSSHCA not configured")
        return false, "", time.Time{}, time.Time{} 
    }
    
    parsedPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubkey))
    if err != nil {
        ev.Infra("error", "auth", "failed", fmt.Sprintf("certificate parse error: %v", err))
        return false, "", time.Time{}, time.Time{}
    }
    
    cert, ok := parsedPub.(*ssh.Certificate)
    if !ok {
        ev.Infra("error", "auth", "failed", "pubkey is not a certificate")
        return false, "", time.Time{}, time.Time{}
    }
    
    // Check CA signature
    caPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(k.cfg.Auth.ProducerSSHCA))
    if err != nil || caPub == nil {
        ev.Infra("error", "auth", "failed", fmt.Sprintf("CA pubkey parse error: %v", err))
        return false, "", time.Time{}, time.Time{}
    }
    
    if !bytes.Equal(cert.SignatureKey.Marshal(), caPub.Marshal()) {
        ev.Infra("error", "auth", "failed", "certificate signature does not match CA")
        return false, "", time.Time{}, time.Time{}
    }
    
    // Check TTL
    now := time.Now()
    va := time.Unix(int64(cert.ValidAfter), 0)
    vb := time.Unix(int64(cert.ValidBefore), 0)
    if cert.ValidAfter != 0 && now.Before(time.Unix(int64(cert.ValidAfter), 0)) {
        ev.Infra("error", "auth", "failed", fmt.Sprintf("certificate not yet valid: valid_after=%v", va))
        return false, "", time.Time{}, time.Time{}
    }
    
    if cert.ValidBefore != 0 && now.After(time.Unix(int64(cert.ValidBefore), 0)) {
        ev.Infra("error", "auth", "failed", fmt.Sprintf("certificate expired: valid_before=%v", vb))
        return false, "", time.Time{}, time.Time{}
    }

    // Certificate verified successfully
    ev.Infra("verify", "auth", "success", fmt.Sprintf("certificate verified: key_id=%s", cert.KeyId))
    return true, cert.KeyId, va, vb
}

// Verify signature over payload + nonce (certificate validity already verified)
func (k *Kernel) verifySignature(pubkey, payloadStr, nonce, sigB64 string) bool {
    ev := logging.NewEventLogger()
    
    parsedPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubkey))
    if err != nil {
        ev.Infra("error", "auth", "failed", fmt.Sprintf("signature verification: pubkey parse error: %v", err))
        return false
    }
    
    // Extract the raw key from certificate (certificate validity already verified)
    if k.cfg.Auth.ProducerSSHCA != "" {
        caPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(k.cfg.Auth.ProducerSSHCA))
        if err != nil {
            ev.Infra("error", "auth", "failed", fmt.Sprintf("signature verification: CA parse error: %v", err))
            return false
        }
        if cert, ok := parsedPub.(*ssh.Certificate); ok && caPub != nil && bytes.Equal(cert.SignatureKey.Marshal(), caPub.Marshal()) {
            parsedPub = cert.Key
        } else {
            ev.Infra("error", "auth", "failed", "signature verification: certificate key extraction failed")
            return false
        }
    }
    
    if cp, ok := parsedPub.(ssh.CryptoPublicKey); ok {
        if edpk, ok := cp.CryptoPublicKey().(ed25519.PublicKey); ok && len(edpk) == ed25519.PublicKeySize {
            canon := string(protocol.CanonicalizeJSON([]byte(payloadStr)))
            msg := []byte(canon + "." + nonce)
            sigBytes, decErr := base64.RawStdEncoding.DecodeString(sigB64)
            if decErr != nil {
                sigBytes, _ = base64.StdEncoding.DecodeString(sigB64)
            }
            if len(sigBytes) == ed25519.SignatureSize && ed25519.Verify(edpk, msg, sigBytes) {
                ev.Infra("verify", "auth", "success", "signature verified")
                return true
            } else {
                ev.Infra("error", "auth", "failed", "signature verification failed: invalid signature")
                return false
            }
        }
    }
    
    ev.Infra("error", "auth", "failed", "signature verification: unsupported key type")
    return false
}

// Send response to Redis stream
func (k *Kernel) sendRegistrationResponse(ctx context.Context, nonce string, response map[string]any) {
    ev := logging.NewEventLogger()
    
    if k.rd == nil || k.rd.C() == nil {
        ev.Infra("error", "redis", "failed", "registration response: redis unavailable")
        return
    }

    respStream := prefixed(k.cfg.Redis.KeyPrefix, "register:resp:"+nonce)
    ttl := time.Duration(k.cfg.Auth.RegistrationResponseTTLSeconds) * time.Second
    if ttl <= 0 {
        ttl = 5 * time.Minute // default
    }

    err := k.rd.C().XAdd(ctx, &redis.XAddArgs{
        Stream: respStream,
        Values: response,
    }).Err()

    if err != nil {
        ev.Infra("write", "redis", "failed", fmt.Sprintf("registration response write error: %v", err))
    } else {
        // Set TTL on response stream
        if expireErr := k.rd.C().Expire(ctx, respStream, ttl).Err(); expireErr != nil {
            ev.Infra("error", "redis", "failed", fmt.Sprintf("registration response TTL error: %v", expireErr))
        }
    }
}

// Main registration consumer with new state machine
func (k *Kernel) consumeRegister(ctx context.Context) {
    ev := logging.NewEventLogger()
    
    if k.rd == nil { 
        ev.Infra("error", "redis", "failed", "registration consumer disabled: redis unavailable")
        return 
    }
    if k.pg == nil {
        ev.Infra("error", "postgres", "failed", "registration consumer disabled: postgres unavailable")
        return
    }
    
    stream := prefixed(k.cfg.Redis.KeyPrefix, "register")
    // Ensure consumer group exists for the registration stream
    if k.rd.C() != nil && k.cfg.Redis.ConsumerGroup != "" {
        if err := k.rd.C().XGroupCreateMkStream(ctx, stream, k.cfg.Redis.ConsumerGroup, "0-0" ).Err(); err != nil {
            // BUSYGROUP is expected if group already exists, but log other errors
            if !strings.Contains(err.Error(), "BUSYGROUP") {
                ev.Infra("error", "redis", "failed", fmt.Sprintf("failed to create consumer group: %v", err))
            }
        }
    }
    
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
            ev.Infra("read", "redis", "failed", fmt.Sprintf("registration stream read error: %v", err))
            time.Sleep(200 * time.Millisecond)
            continue
        }
        if len(res) == 0 { 
            continue 
        }
        
        for _, s := range res {
            for _, m := range s.Messages {
                k.processRegistrationMessage(ctx, stream, m)
            }
        }
    }
}

// Process a single registration message
func (k *Kernel) processRegistrationMessage(ctx context.Context, stream string, m redis.XMessage) {
    ev := logging.NewEventLogger()
    
    // Extract fields
    pubkey, _ := m.Values["pubkey"].(string)
    payloadStr, _ := m.Values["payload"].(string)
    nonce, _ := m.Values["nonce"].(string)
    sigB64, _ := m.Values["sig"].(string)
    action, _ := m.Values["action"].(string)
    
    if pubkey == "" || payloadStr == "" || nonce == "" || sigB64 == "" {
        ev.Registration("attempt", "", "", "failed", "missing_fields")
        if err := k.rd.AckStream(ctx, stream, m.ID); err != nil {
            ev.Infra("ack", "redis", "failed", fmt.Sprintf("failed to ack message with missing fields: %v", err))
        }
        return
    }
    
    fp := sshFingerprint([]byte(pubkey))
    ev.Registration("attempt", fp, "", "", "")

    // Parse payload first to get producer_id for rate limiting
    var payload regPayload
    if err := json.Unmarshal([]byte(payloadStr), &payload); err != nil {
        ev.Registration("attempt", fp, "", "failed", fmt.Sprintf("payload_parse_error: %v", err))
        if err := k.rd.AckStream(ctx, stream, m.ID); err != nil {
            ev.Infra("ack", "redis", "failed", fmt.Sprintf("failed to ack message with parse error: %v", err))
        }
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
    if !k.checkRateLimit(ctx, "reg", rateLimitID) {
        ev.Registration("rate_limited", fp, "", "", "")
        // respond to client on same per-nonce response stream for consistency
        k.sendRegistrationResponse(ctx, nonce, map[string]any{"status": "rate_limited"})
        if err := k.rd.AckStream(ctx, stream, m.ID); err != nil {
            ev.Infra("ack", "redis", "failed", fmt.Sprintf("failed to ack rate-limited message: %v", err))
        }
        return
    }
    
    // Check nonce replay
    if !k.checkNonceReplay(ctx, fp, nonce) {
        // Register producer key with audit record for replay
        producerID, err := k.pg.RegisterProducerKey(ctx, fp, pubkey, payload.ProducerHint, payload.Contact, payload.Meta, payloadStr, sigB64, nonce, "replay", "duplicate_nonce")
        if err != nil {
            ev.Infra("write", "postgres", "failed", fmt.Sprintf("failed to register producer key for replay: %v", err))
        }
        ev.Registration("replay", fp, producerID, "replay", "duplicate_nonce")
        k.sendRegistrationResponse(ctx, nonce, map[string]any{"status": "replay", "reason": "duplicate_nonce"})
        if err := k.rd.AckStream(ctx, stream, m.ID); err != nil {
            ev.Infra("ack", "redis", "failed", fmt.Sprintf("failed to ack replay message: %v", err))
        }
        return
    }
    
    // Verify certificate first (before signature verification)
    certValid, _, _, _ := k.verifyCertificate(pubkey)
    if !certValid {
        // Register producer key with audit record for invalid cert
        producerID, err := k.pg.RegisterProducerKey(ctx, fp, pubkey, payload.ProducerHint, payload.Contact, payload.Meta, payloadStr, sigB64, nonce, "invalid_cert", "certificate_verification_failed")
        if err != nil {
            ev.Infra("write", "postgres", "failed", fmt.Sprintf("failed to register producer key for invalid cert: %v", err))
        }
        ev.Registration("invalid_cert", fp, producerID, "invalid_cert", "certificate_verification_failed")
        k.sendRegistrationResponse(ctx, nonce, map[string]any{
            "fingerprint": fp,
            "status": "invalid_cert",
            "reason": "certificate_verification_failed",
        })
        if err := k.rd.AckStream(ctx, stream, m.ID); err != nil {
            ev.Infra("ack", "redis", "failed", fmt.Sprintf("failed to ack invalid cert message: %v", err))
        }
        return
    }
    // Certificate verified successfully - caller will log registration event
    
    // Verify signature (after certificate verification)
    if !k.verifySignature(pubkey, payloadStr, nonce, sigB64) {
        // Register producer key with audit record for invalid signature
        producerID, err := k.pg.RegisterProducerKey(ctx, fp, pubkey, payload.ProducerHint, payload.Contact, payload.Meta, payloadStr, sigB64, nonce, "invalid_sig", "signature_verification_failed")
        if err != nil {
            ev.Infra("write", "postgres", "failed", fmt.Sprintf("failed to register producer key for invalid sig: %v", err))
        }
        ev.Registration("invalid_sig", fp, producerID, "invalid_sig", "signature_verification_failed")
        k.sendRegistrationResponse(ctx, nonce, map[string]any{
            "fingerprint": fp,
            "status": "invalid_sig",
            "reason": "signature_verification_failed",
        })
        if err := k.rd.AckStream(ctx, stream, m.ID); err != nil {
            ev.Infra("ack", "redis", "failed", fmt.Sprintf("failed to ack invalid sig message: %v", err))
        }
        return
    }

    // Atomically create producer and bind fingerprint for first-time registration with audit record
    // Get current status first (or use "pending" as default for new registrations)
    status, _, _ := k.pg.GetKeyStatus(ctx, fp)
    if status == "" {
        status = "pending" // Default for new registrations
    }
    
    var producerID string
    var err error
    producerID, err = k.pg.RegisterProducerKey(ctx, fp, pubkey, payload.ProducerHint, payload.Contact, payload.Meta, payloadStr, sigB64, nonce, status, "")
    if err != nil {
        ev.Infra("write", "postgres", "failed", fmt.Sprintf("failed to register producer key: %v", err))
        if err := k.rd.AckStream(ctx, stream, m.ID); err != nil {
            ev.Infra("ack", "redis", "failed", fmt.Sprintf("failed to ack registration error: %v", err))
        }
        return
    }
    ev.Registration("attempt", fp, producerID, status, "")

    // Handle deregister action
    if action == "deregister" {
        k.handleDeregister(ctx, stream, producerID, fp, m.ID, nonce)
        return
    }

    // Check current key status (should exist now after RegisterProducerKey)
    status, statusProducerID, err := k.pg.GetKeyStatus(ctx, fp)
    if err != nil {
        ev.Infra("read", "postgres", "failed", fmt.Sprintf("failed to get key status: %v", err))
        if err := k.rd.AckStream(ctx, stream, m.ID); err != nil {
            ev.Infra("ack", "redis", "failed", fmt.Sprintf("failed to ack status check error: %v", err))
        }
        return
    }
    if statusProducerID != nil && *statusProducerID != "" {
        // Prefer authoritative producer_id from key status for responses
        producerID = *statusProducerID
    }

    // Audit record already created by RegisterProducerKey call above

    // State machine based on current status
    switch status {
    case "approved":
        k.handleKnownApproved(ctx, stream, producerID, fp, m.ID, nonce)
    case "pending":
        k.handleKnownPending(ctx, stream, producerID, fp, m.ID, nonce)
    case "revoked", "superseded":
        k.handleKnownDenied(ctx, stream, &producerID, fp, status, m.ID, nonce)
    default:
        // This shouldn't happen after RegisterProducerKey, but handle gracefully
        ev.Registration("attempt", fp, producerID, status, "unknown_status")
        k.handleNewProducer(ctx, stream, producerID, fp, payload, payloadStr, sigB64, nonce, m.ID)
    }
}

// Handle deregister action
func (k *Kernel) handleDeregister(ctx context.Context, stream, producerID, fp string, msgID, nonce string) {
    ev := logging.NewEventLogger()
    
    ev.Registration("attempt", fp, producerID, "deregister", "")
    
    err := k.pg.DisableProducer(ctx, producerID)
    if err != nil {
        ev.Infra("write", "postgres", "failed", fmt.Sprintf("failed to disable producer: %v", err))
    } else {
        ev.Registration("attempt", fp, producerID, "deregistered", "")
    }
    
    k.sendRegistrationResponse(ctx, nonce, map[string]any{
        "fingerprint": fp,
        "producer_id": producerID,
        "status": "deregistered",
    })
    if err := k.rd.AckStream(ctx, stream, msgID); err != nil {
        ev.Infra("ack", "redis", "failed", fmt.Sprintf("failed to ack deregister message: %v", err))
    }
}

// Handle known approved key
func (k *Kernel) handleKnownApproved(ctx context.Context, stream, producerID, fp string, msgID, nonce string) {
    ev := logging.NewEventLogger()
    
    ev.Registration("attempt", fp, producerID, "approved", "")
    
    k.sendRegistrationResponse(ctx, nonce, map[string]any{
        "fingerprint": fp,
        "producer_id": producerID,
        "status": "approved",
    })
    if err := k.rd.AckStream(ctx, stream, msgID); err != nil {
        ev.Infra("ack", "redis", "failed", fmt.Sprintf("failed to ack approved message: %v", err))
    }
}

// Handle known pending key
func (k *Kernel) handleKnownPending(ctx context.Context, stream, producerID, fp string, msgID, nonce string) {
    ev := logging.NewEventLogger()
    
    // Silent - no response for pending keys per protocol
    if err := k.rd.AckStream(ctx, stream, msgID); err != nil {
        ev.Infra("ack", "redis", "failed", fmt.Sprintf("failed to ack pending message: %v", err))
    }
}

// Handle known denied key
func (k *Kernel) handleKnownDenied(ctx context.Context, stream string, producerID *string, fp, status, msgID, nonce string) {
    ev := logging.NewEventLogger()
    
    var pid string
    if producerID != nil { pid = *producerID }
    ev.Registration("attempt", fp, pid, status, "")
    
    k.sendRegistrationResponse(ctx, nonce, map[string]any{
        "fingerprint": fp,
        "producer_id": pid,
        "status": "denied",
        "reason": status,
    })
    if err := k.rd.AckStream(ctx, stream, msgID); err != nil {
        ev.Infra("ack", "redis", "failed", fmt.Sprintf("failed to ack denied message: %v", err))
    }
}

// Handle new producer registration (fallback - should not occur post-RegisterProducerKey)
func (k *Kernel) handleNewProducer(ctx context.Context, stream, producerID, fp string, payload regPayload, payloadStr, sigB64, nonce, msgID string) {
    ev := logging.NewEventLogger()
    
    ev.Registration("attempt", fp, producerID, "pending", "")
    
    k.sendRegistrationResponse(ctx, nonce, map[string]any{
        "fingerprint": fp,
        "producer_id": producerID,
        "status": "pending",
    })
    if err := k.rd.AckStream(ctx, stream, msgID); err != nil {
        ev.Infra("ack", "redis", "failed", fmt.Sprintf("failed to ack new producer message: %v", err))
    }
}

func sshFingerprint(pubKeyData []byte) string {
    sum := sha3.Sum512(pubKeyData)
    return base64.StdEncoding.EncodeToString(sum[:])
}
