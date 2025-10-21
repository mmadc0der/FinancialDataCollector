package kernel

import (
    "bytes"
    "context"
    "encoding/json"
    "io"
    "net/http"
    "strings"
    "time"

    "github.com/example/data-kernel/internal/logging"
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

// GET /auth returns pending registrations (fingerprint + ts + producer_id + name)
func (k *Kernel) handleListPending(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet || !k.isAdmin(r) || k.pg == nil { w.WriteHeader(http.StatusUnauthorized); return }
    // log admin access
    logging.Info("admin_pending_list")
    type row struct{ Fingerprint string `json:"fingerprint"`; TS time.Time `json:"ts"`; ProducerID *string `json:"producer_id"`; Name *string `json:"name"` }
    rows := []row{}
    // include producer_id and name by joining keys and producers
    q := `
SELECT pr.fingerprint,
       MAX(pr.ts) AS ts,
       pk.producer_id,
       p.name
FROM public.producer_registrations pr
JOIN public.producer_keys pk ON pk.fingerprint = pr.fingerprint
LEFT JOIN public.producers p ON p.producer_id = pk.producer_id
WHERE pr.status = 'pending'
GROUP BY pr.fingerprint, pk.producer_id, p.name
ORDER BY ts DESC
LIMIT 100`
	cctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if k.pg.Pool() != nil {
		conn, err := k.pg.Pool().Acquire(cctx)
		if err == nil {
			defer conn.Release()
            rowscan, err := conn.Query(cctx, q)
			if err == nil {
				for rowscan.Next() {
                    var f string; var ts time.Time; var pid *string; var name *string
                    _ = rowscan.Scan(&f, &ts, &pid, &name)
                    rows = append(rows, row{Fingerprint: f, TS: ts, ProducerID: pid, Name: name})
				}
			}
		}
	}
    _ = json.NewEncoder(w).Encode(rows)
}

// Removed handleAuthOverview; /auth returns pending list in this revision.
// POST /auth/review handles both approve and deny actions
func (k *Kernel) handleReview(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost || !k.isAdmin(r) || k.pg == nil { 
        w.WriteHeader(http.StatusUnauthorized)
        return 
    }
    
    var req reviewRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        logging.Warn("admin_review_decode_error", logging.F("admin_principal", r.Header.Get("X-SSH-Principal")), logging.Err(err))
        w.WriteHeader(http.StatusBadRequest)
        return
    }
    
    // Validate required fields
    if req.Action == "" {
        logging.Warn("admin_review_missing_action", logging.F("admin_principal", r.Header.Get("X-SSH-Principal")), logging.F("producer_id", req.ProducerID), logging.F("fingerprint", req.Fingerprint))
        w.WriteHeader(http.StatusBadRequest)
        return
    }
    if req.ProducerID == "" {
        logging.Warn("admin_review_missing_producer_id", logging.F("admin_principal", r.Header.Get("X-SSH-Principal")), logging.F("action", req.Action))
        w.WriteHeader(http.StatusBadRequest)
        return
    }
    if req.Action == "deny" && req.Reason == "" {
        logging.Warn("admin_review_missing_reason", logging.F("admin_principal", r.Header.Get("X-SSH-Principal")), logging.F("action", req.Action), logging.F("producer_id", req.ProducerID))
        w.WriteHeader(http.StatusBadRequest)
        return
    }
    
    adminPrincipal := r.Header.Get("X-SSH-Principal")
    logging.Info("admin_review_request", 
        logging.F("action", req.Action), 
        logging.F("producer_id", req.ProducerID),
        logging.F("fingerprint", req.Fingerprint),
        logging.F("admin_principal", adminPrincipal))
    
    var result map[string]any
    var err error
    
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
            logging.Error("admin_review_error", logging.F("producer_id", req.ProducerID), logging.F("action", "approve"), logging.Err(err))
            w.WriteHeader(http.StatusInternalServerError)
            return
        }
        
        if hasApprovedKey {
            // Key rotation - need fingerprint
            if req.Fingerprint == "" {
                logging.Warn("admin_review_missing_field", logging.F("producer_id", req.ProducerID), logging.F("action", "approve"), logging.F("field", "fingerprint"))
                w.WriteHeader(http.StatusBadRequest)
                return
            }
            _, err = k.pg.ApproveKeyRotation(r.Context(), req.Fingerprint, req.ProducerID, adminPrincipal, req.Notes)
            if err != nil {
                logging.Error("admin_approve_key_rotation_error", logging.F("producer_id", req.ProducerID), logging.F("fingerprint", req.Fingerprint), logging.Err(err))
                w.WriteHeader(http.StatusBadRequest)
                return
            }
            result = map[string]any{"producer_id": req.ProducerID, "status": "approved", "fingerprint": req.Fingerprint, "type": "key_rotation"}
        } else {
            // New producer - need fingerprint
            if req.Fingerprint == "" {
                logging.Warn("admin_review_missing_field", logging.F("producer_id", req.ProducerID), logging.F("action", "approve"), logging.F("field", "fingerprint"))
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
                logging.Error("admin_approve_producer_lookup_error", logging.F("producer_id", req.ProducerID), logging.Err(err))
                w.WriteHeader(http.StatusInternalServerError)
                return
            }
            _, err = k.pg.ApproveNewProducerKey(r.Context(), req.Fingerprint, producerName, adminPrincipal, req.Notes)
            if err != nil {
                logging.Error("admin_approve_new_producer_error", logging.F("producer_id", req.ProducerID), logging.F("fingerprint", req.Fingerprint), logging.F("name", producerName), logging.Err(err))
                w.WriteHeader(http.StatusBadRequest)
                return
            }
            result = map[string]any{"producer_id": req.ProducerID, "status": "approved", "fingerprint": req.Fingerprint, "type": "new_producer"}
        }
        
        logging.Info("admin_approved", logging.F("producer_id", req.ProducerID), logging.F("fingerprint", req.Fingerprint))
        
    } else if req.Action == "deny" {
        if req.Fingerprint == "" {
            logging.Warn("admin_review_missing_field", logging.F("producer_id", req.ProducerID), logging.F("action", "deny"), logging.F("field", "fingerprint"))
            w.WriteHeader(http.StatusBadRequest)
            return
        }
        err = k.pg.RejectProducerKey(r.Context(), req.Fingerprint, adminPrincipal, req.Reason)
        if err != nil {
            logging.Error("admin_deny_error", logging.F("producer_id", req.ProducerID), logging.F("fingerprint", req.Fingerprint), logging.F("reason", req.Reason), logging.Err(err))
            w.WriteHeader(http.StatusBadRequest)
            return
        }
        result = map[string]any{"producer_id": req.ProducerID, "status": "denied", "fingerprint": req.Fingerprint, "reason": req.Reason}
        logging.Info("admin_denied", logging.F("producer_id", req.ProducerID), logging.F("fingerprint", req.Fingerprint), logging.F("reason", req.Reason))
    } else {
        logging.Warn("admin_review_invalid_action", logging.F("action", req.Action), logging.F("admin_principal", adminPrincipal))
        w.WriteHeader(http.StatusBadRequest)
        return
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
                    k.rd.C().XAdd(r.Context(), &redis.XAddArgs{
                        Stream: respStream,
                        Values: map[string]any{
                            "fingerprint": req.Fingerprint,
                            "producer_id": req.ProducerID,
                            "status": "approved",
                        },
                    })
                    k.rd.C().Expire(r.Context(), respStream, ttl)
                    logging.Info("admin_approval_notified_producer", logging.F("producer_id", req.ProducerID), logging.F("fingerprint", req.Fingerprint), logging.F("nonce", nonce))
                }
            }
        }
    }
    
    _ = json.NewEncoder(w).Encode(result)
}

// POST /admin/approve - backward compatibility, redirects to review (deprecated path)
func (k *Kernel) handleApprove(w http.ResponseWriter, r *http.Request) {
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
            logging.Warn("admin_approve_legacy_missing_field", logging.F("field", "fingerprint"))
            w.WriteHeader(http.StatusBadRequest)
            return
        }
        // For legacy, create producer with the provided name
        if req.Name == "" {
            logging.Warn("admin_approve_legacy_missing_field", logging.F("field", "name"))
            w.WriteHeader(http.StatusBadRequest)
            return
        }
        // This is a simplified legacy path - create producer and approve key
        pid, err := k.pg.ApproveNewProducerKey(r.Context(), req.Fingerprint, req.Name, r.Header.Get("X-SSH-Principal"), req.Notes)
        if err != nil {
            logging.Error("admin_approve_legacy_error", logging.F("fingerprint", req.Fingerprint), logging.F("name", req.Name), logging.Err(err))
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
	if k.au == nil || r.Method != http.MethodPost || !k.isAdmin(r) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	var req struct{ JTI string `json:"jti"`; Reason string `json:"reason"` }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.JTI == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
    if err := k.au.Revoke(r.Context(), req.JTI, req.Reason); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
    logging.Info("admin_revoke", logging.F("jti", req.JTI), logging.F("reason", req.Reason))
	w.WriteHeader(http.StatusNoContent)
}

// isAdmin verifies admin via OpenSSH CA cert headers
func (k *Kernel) isAdmin(r *http.Request) bool {
	if k.cfg != nil && k.cfg.Auth.AdminSSHCA != "" {
		certHeader := r.Header.Get("X-SSH-Cert")
		principal := r.Header.Get("X-SSH-Principal")
		if certHeader != "" && principal != "" {
			caPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(k.cfg.Auth.AdminSSHCA))
			if err == nil && caPub != nil {
				certPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(certHeader))
				if err == nil {
					if cert, ok := certPub.(*ssh.Certificate); ok {
						checker := ssh.CertChecker{ IsUserAuthority: func(auth ssh.PublicKey) bool { return bytes.Equal(auth.Marshal(), caPub.Marshal()) } }
						if err := checker.CheckCert(principal, cert); err == nil { return true }
						logging.Warn("admin_cert_check_failed", logging.F("principal", principal))
					}
				}
			}
		}
	}
	return false
}

