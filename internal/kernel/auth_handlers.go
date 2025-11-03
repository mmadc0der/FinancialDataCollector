package kernel

import (
    "bytes"
    "context"
    "crypto/ed25519"
    "encoding/base64"
    "encoding/json"
    "io"
    "net/http"
    "strings"
    "time"
    "fmt"

    "github.com/example/data-kernel/internal/logging"
    "github.com/example/data-kernel/internal/metrics"
    "github.com/example/data-kernel/internal/protocol"
    ssh "golang.org/x/crypto/ssh"
    "github.com/redis/go-redis/v9"
)

type reviewRequest struct {
    Action      string `json:"action"`      // "approve" | "deny"
    ProducerID  string `json:"producer_id"` // required
    Fingerprint string `json:"fingerprint"` // optional for context
    Reason      string `json:"reason"`      // required for deny
    Notes       string `json:"notes"`       // optional
}

// Legacy approve request for backward compatibility
type approveRequest struct {
	Fingerprint string `json:"fingerprint"`
    Name        string `json:"name"`        // producer name if creating
    ProducerID  string `json:"producer_id"` // optional: approve by existing producer id (preferred)
    Notes       string `json:"notes"`
}

// extractAdminPrincipal extracts the admin principal from the SSH certificate in X-Admin-Cert header
// Returns empty string if certificate is not available or cannot be parsed
func (k *Kernel) extractAdminPrincipal(r *http.Request) string {
    adminCert := r.Header.Get("X-Admin-Cert")
    if adminCert == "" {
        return ""
    }
    
    certPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(adminCert))
    if err != nil {
        return ""
    }
    
    cert, ok := certPub.(*ssh.Certificate)
    if !ok || len(cert.ValidPrincipals) == 0 {
        return ""
    }
    
    return cert.ValidPrincipals[0]
}

// GET /auth returns producer information based on filter criteria
// Query parameters:
// - filter=pending (default): pending registrations only
// - filter=all: all producers (including incomplete ones)
// - filter=active: only producers with active tokens
// - filter=registered: only producers that completed registration (have keys)
// - long=true: include detailed info like keys and tokens (default: false)
func (k *Kernel) handleListPending(w http.ResponseWriter, r *http.Request) {
    ev := logging.NewEventLogger()
    adminPrincipal := k.extractAdminPrincipal(r)
    
    if r.Method != http.MethodGet || !k.isAdmin(r) || k.pg == nil { 
        ev.APIAccess(logging.HTTPMethod(r), logging.RemoteAddr(r), "", r.URL.Path, "failed", "unauthorized", http.StatusUnauthorized)
        ev.Authorization("deny", adminPrincipal, r.URL.Path, "admin check failed")
        w.WriteHeader(http.StatusUnauthorized)
        return 
    }

    // Parse query parameters
    query := r.URL.Query()
    filter := query.Get("filter")
    showLong := query.Get("long") == "true"

    // Set default filter if not specified
    if filter == "" {
        if showLong {
            filter = "registered"  // Default to registered when long=true for better UX
        } else {
            filter = "pending"
        }
    }

    // Validate filter parameter
    validFilters := map[string]bool{
        "pending": true,
        "all":     true,
        "active":  true,
        "registered": true,
    }
    if !validFilters[filter] {
        ev.APIAccess(logging.HTTPMethod(r), logging.RemoteAddr(r), adminPrincipal, r.URL.Path, "failed", "invalid_filter", http.StatusBadRequest)
        w.WriteHeader(http.StatusBadRequest)
        return
    }

    // Log admin access as security event
    ev.APIAccess(logging.HTTPMethod(r), logging.RemoteAddr(r), adminPrincipal, r.URL.Path, "success", "", http.StatusOK)
    ev.Admin("access", adminPrincipal, "", fmt.Sprintf("filter=%s,long=%v", filter, showLong), true)

    cctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
    defer cancel()

    switch filter {
    case "pending":
        k.handlePendingRegistrations(w, r, cctx)
    case "all":
        k.handleAllProducers(w, r, cctx, showLong)
    case "active":
        k.handleActiveProducers(w, r, cctx, showLong)
    case "registered":
        k.handleRegisteredProducers(w, r, cctx, showLong)
    }
}

// handlePendingRegistrations handles pending registrations only
func (k *Kernel) handlePendingRegistrations(w http.ResponseWriter, r *http.Request, cctx context.Context) {
    ev := logging.NewEventLogger()
    
    type row struct {
        Fingerprint string  `json:"fingerprint"`
        TS          time.Time `json:"ts"`
        ProducerID  *string `json:"producer_id"`
        Name        *string `json:"name"`
    }
    rows := []row{}

    q := `
SELECT pr.fingerprint,
       pr.ts,
       pk.producer_id,
       p.name
FROM public.producer_registrations pr
JOIN public.producer_keys pk ON pk.fingerprint = pr.fingerprint
LEFT JOIN public.producers p ON p.producer_id = pk.producer_id
WHERE pr.status = 'pending'
ORDER BY pr.ts DESC
LIMIT 100`

    if k.pg.Pool() != nil {
        conn, err := k.pg.Pool().Acquire(cctx)
        if err != nil {
            ev.Infra("connect", "postgres", "failed", fmt.Sprintf("failed to acquire connection: %v", err))
        } else {
            defer conn.Release()
            rowscan, err := conn.Query(cctx, q)
            if err != nil {
                ev.Infra("read", "postgres", "failed", fmt.Sprintf("failed to query pending registrations: %v", err))
            } else {
                for rowscan.Next() {
                    var f string; var ts time.Time; var pid *string; var name *string
                    _ = rowscan.Scan(&f, &ts, &pid, &name)
                    rows = append(rows, row{Fingerprint: f, TS: ts, ProducerID: pid, Name: name})
                }
            }
        }
    } else {
        ev.Infra("error", "postgres", "failed", "database pool is nil")
    }
    _ = json.NewEncoder(w).Encode(rows)
}

// handleAllProducers handles all producers (including incomplete ones)
func (k *Kernel) handleAllProducers(w http.ResponseWriter, r *http.Request, cctx context.Context, showLong bool) {
    ev := logging.NewEventLogger()
    
    type producerInfo struct {
        ProducerID   string     `json:"producer_id"`
        Name         *string    `json:"name"`
        Description  *string    `json:"description,omitempty"`
        Status       string     `json:"status"`       // pending|approved|revoked|superseded|unknown
        CreatedAt    time.Time  `json:"created_at"`
        // Fields available when long=true
        ActiveKey       *string    `json:"active_key,omitempty"`        // only the single active key fingerprint
        AccessTokenJTI  *string    `json:"access_token_jti,omitempty"`  // JTI of the most recent access token
        TokenExpires    *time.Time `json:"token_expires,omitempty"`     // when the token expires
        TokenStatus     *string    `json:"token_status,omitempty"`      // status of the token: active|expired|revoked|unknown
    }

    producers := []producerInfo{}

    if !showLong {
        // Simple view - show each producer once with their current/most relevant status
        q := `
SELECT DISTINCT p.producer_id,
       p.name,
       p.description,
       p.created_at,
       COALESCE(
         (SELECT pk.status FROM public.producer_keys pk WHERE pk.producer_id = p.producer_id ORDER BY
          CASE pk.status
            WHEN 'approved' THEN 1
            WHEN 'pending' THEN 2
            WHEN 'superseded' THEN 3
            WHEN 'revoked' THEN 4
            ELSE 5
          END, pk.created_at DESC LIMIT 1),
         'unknown'
       ) as current_status
FROM public.producers p
ORDER BY p.created_at DESC`

        if k.pg.Pool() != nil {
            conn, err := k.pg.Pool().Acquire(cctx)
            if err != nil {
                ev.Infra("connect", "postgres", "failed", fmt.Sprintf("failed to acquire connection: %v", err))
            } else {
                defer conn.Release()
                rowscan, err := conn.Query(cctx, q)
                if err != nil {
                    ev.Infra("read", "postgres", "failed", fmt.Sprintf("failed to query all producers: %v", err))
                } else {
                    for rowscan.Next() {
                        var pid string; var name, desc *string; var createdAt time.Time; var status string
                        _ = rowscan.Scan(&pid, &name, &desc, &createdAt, &status)
                        producers = append(producers, producerInfo{
                            ProducerID:  pid,
                            Name:        name,
                            Description: desc,
                            Status:      status,
                            CreatedAt:   createdAt,
                        })
                    }
                }
            }
        } else {
            ev.Infra("error", "postgres", "failed", "database pool is nil")
        }
    } else {
        // Long view - include key and token info for all producers (can be null)
        q := `
SELECT DISTINCT p.producer_id,
       p.name,
       p.description,
       p.created_at,
       COALESCE(
         (SELECT pk.status FROM public.producer_keys pk WHERE pk.producer_id = p.producer_id ORDER BY
          CASE pk.status
            WHEN 'approved' THEN 1
            WHEN 'pending' THEN 2
            WHEN 'superseded' THEN 3
            WHEN 'revoked' THEN 4
            ELSE 5
          END, pk.created_at DESC LIMIT 1),
         'unknown'
       ) as current_status,
       (SELECT pk.fingerprint FROM public.producer_keys pk WHERE pk.producer_id = p.producer_id AND pk.status = 'approved' ORDER BY pk.created_at DESC LIMIT 1) as active_key,
       pt.jti as access_token_jti,
       pt.expires_at as token_expires,
       CASE
         WHEN pt.revoked_at IS NOT NULL THEN 'revoked'
         WHEN pt.expires_at < NOW() THEN 'expired'
         WHEN pt.revoked_at IS NULL AND pt.expires_at >= NOW() THEN 'active'
         ELSE 'unknown'
       END as token_status
FROM public.producers p
LEFT JOIN LATERAL (
    SELECT jti, expires_at, issued_at, revoked_at
    FROM public.producer_tokens
    WHERE producer_id = p.producer_id
    ORDER BY issued_at DESC
    LIMIT 1
) pt ON true
ORDER BY p.created_at DESC`

        if k.pg.Pool() != nil {
            conn, err := k.pg.Pool().Acquire(cctx)
            if err != nil {
                ev.Infra("connect", "postgres", "failed", fmt.Sprintf("failed to acquire connection: %v", err))
            } else {
                defer conn.Release()
                rowscan, err := conn.Query(cctx, q)
                if err != nil {
                    ev.Infra("read", "postgres", "failed", fmt.Sprintf("failed to query all producers (long): %v", err))
                } else {
                    for rowscan.Next() {
                        var pid string; var name, desc *string; var createdAt time.Time; var status string
                        var activeKey, accessTokenJTI *string; var tokenExpires *time.Time; var tokenStatus *string

                        _ = rowscan.Scan(&pid, &name, &desc, &createdAt, &status, &activeKey, &accessTokenJTI, &tokenExpires, &tokenStatus)
                        producers = append(producers, producerInfo{
                            ProducerID:     pid,
                            Name:           name,
                            Description:    desc,
                            Status:         status,
                            CreatedAt:      createdAt,
                            ActiveKey:      activeKey,
                            AccessTokenJTI: accessTokenJTI,
                            TokenExpires:   tokenExpires,
                            TokenStatus:    tokenStatus,
                        })
                    }
                }
            }
        }
    }

    _ = json.NewEncoder(w).Encode(producers)
}

// handleActiveProducers handles only producers with active tokens
func (k *Kernel) handleActiveProducers(w http.ResponseWriter, r *http.Request, cctx context.Context, showLong bool) {
    ev := logging.NewEventLogger()
    
    type producerInfo struct {
        ProducerID   string     `json:"producer_id"`
        Name         *string    `json:"name"`
        Description  *string    `json:"description,omitempty"`
        Status       string     `json:"status"`
        CreatedAt    time.Time  `json:"created_at"`
        // Fields available when long=true
        ActiveKey       *string    `json:"active_key,omitempty"`
        AccessTokenJTI  *string    `json:"access_token_jti,omitempty"`
        TokenExpires    *time.Time `json:"token_expires,omitempty"`
        TokenStatus     *string    `json:"token_status,omitempty"`
    }

    producers := []producerInfo{}

    var q string
    if !showLong {
        q = `
SELECT DISTINCT p.producer_id,
       p.name,
       p.description,
       'active' as status,
       p.created_at
FROM public.producers p
INNER JOIN public.producer_tokens pt ON pt.producer_id = p.producer_id
WHERE pt.revoked_at IS NULL AND pt.expires_at > NOW()
ORDER BY p.created_at DESC`
    } else {
        q = `
SELECT DISTINCT p.producer_id,
       p.name,
       p.description,
       p.created_at,
       'active' as status,
       (SELECT pk.fingerprint FROM public.producer_keys pk WHERE pk.producer_id = p.producer_id AND pk.status = 'approved' ORDER BY pk.created_at DESC LIMIT 1) as active_key,
       pt.jti as access_token_jti,
       pt.expires_at as token_expires,
       CASE
         WHEN pt.revoked_at IS NOT NULL THEN 'revoked'
         WHEN pt.expires_at < NOW() THEN 'expired'
         ELSE 'active'
       END as token_status
FROM public.producers p
INNER JOIN public.producer_tokens pt ON pt.producer_id = p.producer_id
WHERE pt.revoked_at IS NULL AND pt.expires_at > NOW()
ORDER BY p.created_at DESC`
    }

    if k.pg.Pool() != nil {
        conn, err := k.pg.Pool().Acquire(cctx)
        if err != nil {
            ev.Infra("connect", "postgres", "failed", fmt.Sprintf("failed to acquire connection: %v", err))
        } else {
            defer conn.Release()
            rowscan, err := conn.Query(cctx, q)
            if err != nil {
                ev.Infra("read", "postgres", "failed", fmt.Sprintf("failed to query active producers: %v", err))
            } else {
                if showLong {
                    for rowscan.Next() {
                        var pid string; var name, desc *string; var createdAt time.Time
                        var activeKey, accessTokenJTI *string; var tokenExpires *time.Time; var tokenStatus *string

                        _ = rowscan.Scan(&pid, &name, &desc, &createdAt, &activeKey, &accessTokenJTI, &tokenExpires, &tokenStatus)
                        producers = append(producers, producerInfo{
                            ProducerID:     pid,
                            Name:           name,
                            Description:    desc,
                            Status:         "active",
                            CreatedAt:      createdAt,
                            ActiveKey:      activeKey,
                            AccessTokenJTI: accessTokenJTI,
                            TokenExpires:   tokenExpires,
                        })
                    }
                } else {
                    for rowscan.Next() {
                        var pid string; var name, desc *string; var createdAt time.Time

                        _ = rowscan.Scan(&pid, &name, &desc, &createdAt)
                        producers = append(producers, producerInfo{
                            ProducerID:  pid,
                            Name:        name,
                            Description: desc,
                            Status:      "active",
                            CreatedAt:   createdAt,
                        })
                    }
                }
            }
        }
    }
    _ = json.NewEncoder(w).Encode(producers)
}

// handleRegisteredProducers handles only producers that completed registration (have keys)
func (k *Kernel) handleRegisteredProducers(w http.ResponseWriter, r *http.Request, cctx context.Context, showLong bool) {
    ev := logging.NewEventLogger()
    
    type producerInfo struct {
        ProducerID   string     `json:"producer_id"`
        Name         *string    `json:"name"`
        Description  *string    `json:"description,omitempty"`
        Status       string     `json:"status"`
        CreatedAt    time.Time  `json:"created_at"`
        // Fields available when long=true
        ActiveKey       *string    `json:"active_key,omitempty"`
        AccessTokenJTI  *string    `json:"access_token_jti,omitempty"`
        TokenExpires    *time.Time `json:"token_expires,omitempty"`
        TokenStatus     *string    `json:"token_status,omitempty"`
    }

    producers := []producerInfo{}

    var q string
    if !showLong {
        q = `
SELECT DISTINCT p.producer_id,
       p.name,
       p.description,
       p.created_at,
       COALESCE(
         (SELECT pk.status FROM public.producer_keys pk WHERE pk.producer_id = p.producer_id ORDER BY
          CASE pk.status
            WHEN 'approved' THEN 1
            WHEN 'pending' THEN 2
            WHEN 'superseded' THEN 3
            WHEN 'revoked' THEN 4
            ELSE 5
          END, pk.created_at DESC LIMIT 1),
         'unknown'
       ) as current_status
FROM public.producers p
WHERE EXISTS (SELECT 1 FROM public.producer_keys pk WHERE pk.producer_id = p.producer_id)
ORDER BY p.created_at DESC`
    } else {
        q = `
SELECT DISTINCT p.producer_id,
       p.name,
       p.description,
       p.created_at,
       COALESCE(
         (SELECT pk.status FROM public.producer_keys pk WHERE pk.producer_id = p.producer_id ORDER BY
          CASE pk.status
            WHEN 'approved' THEN 1
            WHEN 'pending' THEN 2
            WHEN 'superseded' THEN 3
            WHEN 'revoked' THEN 4
            ELSE 5
          END, pk.created_at DESC LIMIT 1),
         'unknown'
       ) as current_status,
       (SELECT pk.fingerprint FROM public.producer_keys pk WHERE pk.producer_id = p.producer_id AND pk.status = 'approved' ORDER BY pk.created_at DESC LIMIT 1) as active_key,
       pt.jti as access_token_jti,
       pt.expires_at as token_expires,
       CASE
         WHEN pt.revoked_at IS NOT NULL THEN 'revoked'
         WHEN pt.expires_at < NOW() THEN 'expired'
         WHEN pt.revoked_at IS NULL AND pt.expires_at >= NOW() THEN 'active'
         ELSE 'unknown'
       END as token_status
FROM public.producers p
LEFT JOIN LATERAL (
    SELECT jti, expires_at, issued_at, revoked_at
    FROM public.producer_tokens
    WHERE producer_id = p.producer_id
    ORDER BY issued_at DESC
    LIMIT 1
) pt ON true
WHERE EXISTS (SELECT 1 FROM public.producer_keys pk WHERE pk.producer_id = p.producer_id)
ORDER BY p.created_at DESC`
    }

    if k.pg.Pool() != nil {
        conn, err := k.pg.Pool().Acquire(cctx)
        if err != nil {
            ev.Infra("connect", "postgres", "failed", fmt.Sprintf("failed to acquire connection: %v", err))
        } else {
            defer conn.Release()
            rowscan, err := conn.Query(cctx, q)
            if err != nil {
                ev.Infra("read", "postgres", "failed", fmt.Sprintf("failed to query registered producers: %v", err))
            } else {
                if showLong {
                    for rowscan.Next() {
                        var pid string; var name, desc *string; var createdAt time.Time; var status string
                        var activeKey, accessTokenJTI *string; var tokenExpires *time.Time; var tokenStatus *string

                        _ = rowscan.Scan(&pid, &name, &desc, &createdAt, &status, &activeKey, &accessTokenJTI, &tokenExpires, &tokenStatus)
                        producers = append(producers, producerInfo{
                            ProducerID:     pid,
                            Name:           name,
                            Description:    desc,
                            Status:         status,
                            CreatedAt:      createdAt,
                            ActiveKey:      activeKey,
                            AccessTokenJTI: accessTokenJTI,
                            TokenExpires:   tokenExpires,
                            TokenStatus:    tokenStatus,
                        })
                    }
                } else {
                    for rowscan.Next() {
                        var pid string; var name, desc *string; var createdAt time.Time; var status string

                        _ = rowscan.Scan(&pid, &name, &desc, &createdAt, &status)
                        producers = append(producers, producerInfo{
                            ProducerID:  pid,
                            Name:        name,
                            Description: desc,
                            Status:      status,
                            CreatedAt:   createdAt,
                        })
                    }
                }
            }
        }
    }
    _ = json.NewEncoder(w).Encode(producers)
}

// Removed handleAuthOverview; /auth returns pending list in this revision.
// POST /auth/review handles both approve and deny actions
func (k *Kernel) handleReview(w http.ResponseWriter, r *http.Request) {
    ev := logging.NewEventLogger()
    adminPrincipal := k.extractAdminPrincipal(r)
    
    if r.Method != http.MethodPost || !k.isAdmin(r) || k.pg == nil { 
        ev.APIAccess(logging.HTTPMethod(r), logging.RemoteAddr(r), "", r.URL.Path, "failed", "unauthorized", http.StatusUnauthorized)
        ev.Authorization("deny", adminPrincipal, r.URL.Path, "admin check failed")
        w.WriteHeader(http.StatusUnauthorized)
        return 
    }
    
    var req reviewRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        ev.APIAccess(logging.HTTPMethod(r), logging.RemoteAddr(r), adminPrincipal, r.URL.Path, "failed", fmt.Sprintf("decode_error: %v", err), http.StatusBadRequest)
        w.WriteHeader(http.StatusBadRequest)
        return
    }
    
    // Validate required fields
    if req.Action == "" {
        ev.APIAccess(logging.HTTPMethod(r), logging.RemoteAddr(r), adminPrincipal, r.URL.Path, "failed", "missing_action", http.StatusBadRequest)
        w.WriteHeader(http.StatusBadRequest)
        return
    }
    if req.ProducerID == "" {
        ev.APIAccess(logging.HTTPMethod(r), logging.RemoteAddr(r), adminPrincipal, r.URL.Path, "failed", "missing_producer_id", http.StatusBadRequest)
        w.WriteHeader(http.StatusBadRequest)
        return
    }
    if req.Action == "deny" && req.Reason == "" {
        ev.APIAccess(logging.HTTPMethod(r), logging.RemoteAddr(r), adminPrincipal, r.URL.Path, "failed", "missing_reason_for_deny", http.StatusBadRequest)
        w.WriteHeader(http.StatusBadRequest)
        return
    }
    
    var result map[string]any
    var err error
    success := false
    
    if req.Action == "approve" {
        // Determine if this is new producer or key rotation
        // Check if producer has any approved keys
        var hasApprovedKey bool
        if k.pg.Pool() != nil {
            conn, err := k.pg.Pool().Acquire(r.Context())
            if err == nil {
                defer conn.Release()
                err = conn.QueryRow(r.Context(), 
                    `SELECT EXISTS(SELECT 1 FROM public.producer_keys WHERE producer_id=$1 AND status='approved')`, 
                    req.ProducerID).Scan(&hasApprovedKey)
            }
        }
        
        if err != nil {
            ev.Infra("read", "postgres", "failed", fmt.Sprintf("failed to check approved keys: %v", err))
            ev.Admin("approve", adminPrincipal, req.ProducerID, fmt.Sprintf("error: %v", err), false)
            ev.APIAccess(logging.HTTPMethod(r), logging.RemoteAddr(r), adminPrincipal, r.URL.Path, "failed", fmt.Sprintf("db_error: %v", err), http.StatusInternalServerError)
            w.WriteHeader(http.StatusInternalServerError)
            return
        }
        
        if hasApprovedKey {
            // Key rotation - need fingerprint
            if req.Fingerprint == "" {
                ev.APIAccess(logging.HTTPMethod(r), logging.RemoteAddr(r), adminPrincipal, r.URL.Path, "failed", "missing_fingerprint_for_rotation", http.StatusBadRequest)
                w.WriteHeader(http.StatusBadRequest)
                return
            }
            _, err = k.pg.ApproveKeyRotation(r.Context(), req.Fingerprint, req.ProducerID, adminPrincipal, req.Notes)
            if err != nil {
                ev.Infra("write", "postgres", "failed", fmt.Sprintf("failed to approve key rotation: %v", err))
                ev.Admin("approve", adminPrincipal, req.ProducerID, fmt.Sprintf("key_rotation_error: %v", err), false)
                ev.APIAccess(logging.HTTPMethod(r), logging.RemoteAddr(r), adminPrincipal, r.URL.Path, "failed", fmt.Sprintf("approve_error: %v", err), http.StatusBadRequest)
                w.WriteHeader(http.StatusBadRequest)
                return
            }
            result = map[string]any{"producer_id": req.ProducerID, "status": "approved", "fingerprint": req.Fingerprint, "type": "key_rotation"}
            success = true
            ev.Admin("approve", adminPrincipal, req.ProducerID, fmt.Sprintf("key_rotation: %s", req.Fingerprint), true)
        } else {
            // New producer - need fingerprint
            if req.Fingerprint == "" {
                ev.APIAccess(logging.HTTPMethod(r), logging.RemoteAddr(r), adminPrincipal, r.URL.Path, "failed", "missing_fingerprint_for_new_producer", http.StatusBadRequest)
                w.WriteHeader(http.StatusBadRequest)
                return
            }
            // Get producer name from existing producer record
            var producerName string
            if k.pg.Pool() != nil {
                conn, err := k.pg.Pool().Acquire(r.Context())
                if err == nil {
                    defer conn.Release()
                    err = conn.QueryRow(r.Context(), 
                        `SELECT name FROM public.producers WHERE producer_id=$1`, 
                        req.ProducerID).Scan(&producerName)
                }
            }
            if err != nil || producerName == "" {
                ev.Infra("read", "postgres", "failed", fmt.Sprintf("failed to lookup producer: %v", err))
                ev.Admin("approve", adminPrincipal, req.ProducerID, fmt.Sprintf("lookup_error: %v", err), false)
                ev.APIAccess(logging.HTTPMethod(r), logging.RemoteAddr(r), adminPrincipal, r.URL.Path, "failed", fmt.Sprintf("lookup_error: %v", err), http.StatusInternalServerError)
                w.WriteHeader(http.StatusInternalServerError)
                return
            }
            _, err = k.pg.ApproveNewProducerKey(r.Context(), req.Fingerprint, producerName, adminPrincipal, req.Notes)
            if err != nil {
                ev.Infra("write", "postgres", "failed", fmt.Sprintf("failed to approve new producer: %v", err))
                ev.Admin("approve", adminPrincipal, req.ProducerID, fmt.Sprintf("new_producer_error: %v", err), false)
                ev.APIAccess(logging.HTTPMethod(r), logging.RemoteAddr(r), adminPrincipal, r.URL.Path, "failed", fmt.Sprintf("approve_error: %v", err), http.StatusBadRequest)
                w.WriteHeader(http.StatusBadRequest)
                return
            }
            result = map[string]any{"producer_id": req.ProducerID, "status": "approved", "fingerprint": req.Fingerprint, "type": "new_producer"}
            success = true
            ev.Admin("approve", adminPrincipal, req.ProducerID, fmt.Sprintf("new_producer: %s", req.Fingerprint), true)
        }
        
    } else if req.Action == "deny" {
        if req.Fingerprint == "" {
            ev.APIAccess(logging.HTTPMethod(r), logging.RemoteAddr(r), adminPrincipal, r.URL.Path, "failed", "missing_fingerprint_for_deny", http.StatusBadRequest)
            w.WriteHeader(http.StatusBadRequest)
            return
        }
        err = k.pg.RejectProducerKey(r.Context(), req.Fingerprint, adminPrincipal, req.Reason)
        if err != nil {
            ev.Infra("write", "postgres", "failed", fmt.Sprintf("failed to reject producer key: %v", err))
            ev.Admin("deny", adminPrincipal, req.ProducerID, fmt.Sprintf("reject_error: %v", err), false)
            ev.APIAccess(logging.HTTPMethod(r), logging.RemoteAddr(r), adminPrincipal, r.URL.Path, "failed", fmt.Sprintf("reject_error: %v", err), http.StatusBadRequest)
            w.WriteHeader(http.StatusBadRequest)
            return
        }
        result = map[string]any{"producer_id": req.ProducerID, "status": "denied", "fingerprint": req.Fingerprint, "reason": req.Reason}
        success = true
        ev.Admin("deny", adminPrincipal, req.ProducerID, fmt.Sprintf("fingerprint=%s,reason=%s", req.Fingerprint, req.Reason), true)
    } else {
        ev.APIAccess(logging.HTTPMethod(r), logging.RemoteAddr(r), adminPrincipal, r.URL.Path, "failed", fmt.Sprintf("invalid_action: %s", req.Action), http.StatusBadRequest)
        w.WriteHeader(http.StatusBadRequest)
        return
    }
    
    // Log successful API access
    if success {
        ev.APIAccess(logging.HTTPMethod(r), logging.RemoteAddr(r), adminPrincipal, r.URL.Path, "success", "", http.StatusOK)
    }
    
    // After successful action, notify producer if this is an approval
    if req.Action == "approve" && req.Fingerprint != "" && k.rd != nil && k.rd.C() != nil && k.cfg != nil {
        // Retrieve the nonce from the most recent registration attempt for this fingerprint
        var nonce string
        if k.pg != nil && k.pg.Pool() != nil {
            conn, err := k.pg.Pool().Acquire(r.Context())
            if err == nil {
                defer conn.Release()
                // Get the most recent nonce for this fingerprint
                err = conn.QueryRow(r.Context(),
                    `SELECT nonce FROM public.producer_registrations WHERE fingerprint=$1 ORDER BY ts DESC LIMIT 1`,
                    req.Fingerprint).Scan(&nonce)
                if err == nil && nonce != "" {
                    // Send approval notification back to producer
                    respStream := prefixed(k.cfg.Redis.KeyPrefix, "register:resp:"+nonce)
                    ttl := time.Duration(k.cfg.Auth.RegistrationResponseTTLSeconds) * time.Second
                    if ttl <= 0 {
                        ttl = 5 * time.Minute
                    }
                    if err := k.rd.C().XAdd(r.Context(), &redis.XAddArgs{
                        Stream: respStream,
                        Values: map[string]any{
                            "fingerprint": req.Fingerprint,
                            "producer_id": req.ProducerID,
                            "status": "approved",
                        },
                    }).Err(); err != nil {
                        ev.Infra("write", "redis", "failed", fmt.Sprintf("failed to notify producer: %v", err))
                    } else {
                        if err := k.rd.C().Expire(r.Context(), respStream, ttl).Err(); err != nil {
                            ev.Infra("error", "redis", "failed", fmt.Sprintf("failed to set TTL on notification stream: %v", err))
                        }
                    }
                }
            }
        }
    }
    
    _ = json.NewEncoder(w).Encode(result)
}

// POST /admin/approve - backward compatibility, redirects to review (deprecated path)
func (k *Kernel) handleApprove(w http.ResponseWriter, r *http.Request) {
    ev := logging.NewEventLogger()
    
    if r.Method != http.MethodPost || !k.isAdmin(r) || k.pg == nil { 
        w.WriteHeader(http.StatusUnauthorized)
        return 
    }
    
    var req approveRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        w.WriteHeader(http.StatusBadRequest)
        return
    }
    
    // Convert to review request
    reviewReq := reviewRequest{
        Action:      "approve",
        ProducerID:  req.ProducerID,
        Fingerprint: req.Fingerprint,
        Notes:       req.Notes,
    }
    
    // If no producer_id provided, we need to create one - this is legacy behavior
    if reviewReq.ProducerID == "" {
        if req.Fingerprint == "" {
            ev.APIAccess(logging.HTTPMethod(r), logging.RemoteAddr(r), k.extractAdminPrincipal(r), r.URL.Path, "failed", "missing_fingerprint", http.StatusBadRequest)
            w.WriteHeader(http.StatusBadRequest)
            return
        }
        // For legacy, create producer with the provided name
        if req.Name == "" {
            ev.APIAccess(logging.HTTPMethod(r), logging.RemoteAddr(r), k.extractAdminPrincipal(r), r.URL.Path, "failed", "missing_name", http.StatusBadRequest)
            w.WriteHeader(http.StatusBadRequest)
            return
        }
        // This is a simplified legacy path - create producer and approve key
        pid, err := k.pg.ApproveNewProducerKey(r.Context(), req.Fingerprint, req.Name, k.extractAdminPrincipal(r), req.Notes)
        if err != nil {
            ev.Infra("write", "postgres", "failed", fmt.Sprintf("failed to approve new producer key: %v", err))
            ev.APIAccess(logging.HTTPMethod(r), logging.RemoteAddr(r), k.extractAdminPrincipal(r), r.URL.Path, "failed", fmt.Sprintf("approve_error: %v", err), http.StatusBadRequest)
            w.WriteHeader(http.StatusBadRequest)
            return
        }
        reviewReq.ProducerID = pid
    }
    
    // Create a new request body for the review handler
    newBody, _ := json.Marshal(reviewReq)
    r.Body = io.NopCloser(strings.NewReader(string(newBody)))
    
    // Call the review handler
    k.handleReview(w, r)
}

func (k *Kernel) handleRevokeToken(w http.ResponseWriter, r *http.Request) {
    ev := logging.NewEventLogger()
    adminPrincipal := k.extractAdminPrincipal(r)
    
    if k.au == nil || r.Method != http.MethodPost || !k.isAdmin(r) {
        ev.APIAccess(logging.HTTPMethod(r), logging.RemoteAddr(r), "", r.URL.Path, "failed", "unauthorized", http.StatusUnauthorized)
        ev.Authorization("deny", adminPrincipal, r.URL.Path, "admin check failed")
        w.WriteHeader(http.StatusUnauthorized)
        return
    }
    
    var req struct{ JTI string `json:"jti"`; Reason string `json:"reason"` }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.JTI == "" {
        ev.APIAccess(logging.HTTPMethod(r), logging.RemoteAddr(r), adminPrincipal, r.URL.Path, "failed", "invalid_request", http.StatusBadRequest)
        w.WriteHeader(http.StatusBadRequest)
        return
    }
    
    if err := k.au.Revoke(r.Context(), req.JTI, req.Reason); err != nil {
        ev.Infra("write", "postgres", "failed", fmt.Sprintf("failed to revoke token: %v", err))
        ev.Admin("revoke", adminPrincipal, req.JTI, fmt.Sprintf("error: %v", err), false)
        ev.APIAccess(logging.HTTPMethod(r), logging.RemoteAddr(r), adminPrincipal, r.URL.Path, "failed", fmt.Sprintf("revoke_error: %v", err), http.StatusInternalServerError)
        w.WriteHeader(http.StatusInternalServerError)
        return
    }
    
    ev.Token("revoke", "", "", req.JTI, true, req.Reason)
    ev.Admin("revoke", adminPrincipal, req.JTI, req.Reason, true)
    ev.APIAccess(logging.HTTPMethod(r), logging.RemoteAddr(r), adminPrincipal, r.URL.Path, "success", "", http.StatusNoContent)
    w.WriteHeader(http.StatusNoContent)
}

// isAdmin enforces strict mTLS and detached signature over the request
// Headers required: X-Admin-Cert (OpenSSH cert), X-Admin-Nonce, X-Admin-Signature (base64)
func (k *Kernel) isAdmin(r *http.Request) bool {
    ev := logging.NewEventLogger()
    
    if k.cfg == nil || k.cfg.Auth.AdminSSHCA == "" || !k.cfg.Auth.AdminSignRequired { return false }
    // Require mTLS at connection level
    if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 { 
        metrics.AdminMTLSDenied.Inc()
        ev.Auth("failure", "", logging.RemoteAddr(r), false, "mTLS certificate missing")
        return false 
    }
    // Optional CN/SAN allowlist
    if len(k.cfg.Auth.AdminAllowedSubjects) > 0 {
        subjOK := false
        pc := r.TLS.PeerCertificates[0]
        cn := pc.Subject.CommonName
        for _, s := range k.cfg.Auth.AdminAllowedSubjects { if strings.EqualFold(strings.TrimSpace(s), strings.TrimSpace(cn)) { subjOK = true; break } }
        if !subjOK {
            for _, name := range pc.DNSNames { for _, s := range k.cfg.Auth.AdminAllowedSubjects { if strings.EqualFold(strings.TrimSpace(s), strings.TrimSpace(name)) { subjOK = true; break } } }
        }
        if !subjOK { 
            ev.Auth("failure", "", logging.RemoteAddr(r), false, "subject not in allowlist")
            return false 
        }
    }

    // Detached signature requirements
    adminCert := r.Header.Get("X-Admin-Cert")
    nonce := r.Header.Get("X-Admin-Nonce")
    sigB64 := r.Header.Get("X-Admin-Signature")
    if adminCert == "" || nonce == "" || sigB64 == "" { 
        ev.Auth("failure", "", logging.RemoteAddr(r), false, "missing admin headers")
        return false 
    }

    // Prevent replay: nonce must be unique for a short window
    if k.rd != nil && k.rd.C() != nil {
        key := prefixed(k.cfg.Redis.KeyPrefix, "admin:nonce:"+nonce)
        ok, err := k.rd.C().SetNX(r.Context(), key, 1, 5*time.Minute).Result()
        if err != nil { 
            ev.Infra("error", "redis", "failed", fmt.Sprintf("admin nonce guard error: %v", err))
            ev.Auth("failure", "", logging.RemoteAddr(r), false, "nonce guard error")
            return false 
        }
        if !ok { 
            ev.Auth("failure", "", logging.RemoteAddr(r), false, "nonce replay detected")
            metrics.AdminReplay.Inc()
            return false 
        }
    }

    // Verify SSH certificate and principal against AdminSSHCA and configured principal allowlist
    caPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(k.cfg.Auth.AdminSSHCA))
    if err != nil || caPub == nil { 
        ev.Infra("error", "auth", "failed", fmt.Sprintf("failed to parse AdminSSHCA: %v", err))
        return false 
    }
    certPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(adminCert))
    if err != nil { 
        ev.Auth("failure", "", logging.RemoteAddr(r), false, fmt.Sprintf("failed to parse admin cert: %v", err))
        return false 
    }
    cert, ok := certPub.(*ssh.Certificate)
    if !ok { 
        ev.Auth("failure", "", logging.RemoteAddr(r), false, "admin cert is not a certificate")
        return false 
    }
    checker := ssh.CertChecker{ IsUserAuthority: func(auth ssh.PublicKey) bool { return bytes.Equal(auth.Marshal(), caPub.Marshal()) } }
    // Admin principal must match configured principal if provided
    principalOK := false
    if p := strings.TrimSpace(k.cfg.Auth.AdminPrincipal); p != "" {
        for _, vp := range cert.ValidPrincipals { if vp == p { principalOK = true; break } }
    } else {
        principalOK = len(cert.ValidPrincipals) > 0
    }
    if !principalOK { 
        ev.Auth("failure", "", logging.RemoteAddr(r), false, "admin principal mismatch")
        return false 
    }
    if err := checker.CheckCert(cert.ValidPrincipals[0], cert); err != nil { 
        ev.Auth("failure", "", logging.RemoteAddr(r), false, fmt.Sprintf("admin cert check failed: %v", err))
        return false 
    }

    // Build canonical string: canonicalJSON(body)+"\n"+method+"\n"+path+"\n"+nonce
    var bodyBytes []byte
    if r.Body != nil {
        bodyBytes, _ = io.ReadAll(r.Body)
        r.Body.Close()
        r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
    }
    if len(bodyBytes) == 0 { bodyBytes = []byte("{}") }
    canon := protocol.CanonicalizeJSON(bodyBytes)
    signing := append(canon, '\n')
    signing = append(signing, []byte(strings.ToUpper(r.Method))...)
    signing = append(signing, '\n')
    signing = append(signing, []byte(r.URL.Path)...)
    signing = append(signing, '\n')
    signing = append(signing, []byte(nonce)...)

    // Verify signature with ed25519 key from SSH certificate
    ok2 := false
    if cp, ok := cert.Key.(ssh.CryptoPublicKey); ok {
        if edpk, ok := cp.CryptoPublicKey().(ed25519.PublicKey); ok && len(edpk) == ed25519.PublicKeySize {
            sig, err := base64.RawStdEncoding.DecodeString(sigB64)
            if err != nil { sig, _ = base64.StdEncoding.DecodeString(sigB64) }
            if len(sig) == ed25519.SignatureSize && ed25519.Verify(edpk, signing, sig) { ok2 = true }
        }
    }
    if !ok2 { 
        ev.Auth("failure", "", logging.RemoteAddr(r), false, "admin signature invalid")
        metrics.AdminSigInvalid.Inc()
        return false 
    }
    
    // Successful admin authentication - log as security event
    principal := ""
    if len(cert.ValidPrincipals) > 0 {
        principal = cert.ValidPrincipals[0]
    }
    ev.Auth("verify", principal, logging.RemoteAddr(r), true, "")
    return true
}

