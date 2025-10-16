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

// GET /admin/pending returns pending registrations (fingerprint + ts)
func (k *Kernel) handleListPending(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || !k.isAdmin(r) || k.pg == nil { w.WriteHeader(http.StatusUnauthorized); return }
    // log admin access
    logging.Info("admin_pending_list")
	type row struct{ Fingerprint string `json:"fingerprint"`; TS time.Time `json:"ts"` }
	rows := []row{}
	// minimal query to list fingerprints with latest ts pending
	q := `SELECT pr.fingerprint, MAX(pr.ts) AS ts FROM public.producer_registrations pr WHERE pr.status='pending' GROUP BY pr.fingerprint ORDER BY ts DESC LIMIT 100`
	cctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if k.pg.Pool() != nil {
		conn, err := k.pg.Pool().Acquire(cctx)
		if err == nil {
			defer conn.Release()
			rowscan, err := conn.Query(cctx, q)
			if err == nil {
				for rowscan.Next() {
					var f string; var ts time.Time
					_ = rowscan.Scan(&f, &ts)
					rows = append(rows, row{Fingerprint: f, TS: ts})
				}
			}
		}
	}
    _ = json.NewEncoder(w).Encode(rows)
}

// GET /auth lists producers and key statuses (overview)
func (k *Kernel) handleAuthOverview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || !k.isAdmin(r) || k.pg == nil { w.WriteHeader(http.StatusUnauthorized); return }
    logging.Info("admin_auth_overview")
	type row struct{ Fingerprint string `json:"fingerprint"`; Status string `json:"status"`; ProducerID *string `json:"producer_id"`; Name *string `json:"name"`; CreatedAt string `json:"created_at"` }
	out := []row{}
	q := `SELECT fingerprint, status, producer_id, name, to_char(created_at, 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') FROM public.producer_overview ORDER BY created_at DESC LIMIT 200`
	cctx, cancel := context.WithTimeout(r.Context(), 5*time.Second); defer cancel()
	if k.pg.Pool() != nil { if conn, err := k.pg.Pool().Acquire(cctx); err == nil { defer conn.Release(); if rs, err := conn.Query(cctx, q); err == nil { for rs.Next() { var f, s, ts string; var pid *string; var nm *string; _ = rs.Scan(&f,&s,&pid,&nm,&ts); out = append(out, row{Fingerprint:f, Status:s, ProducerID:pid, Name:nm, CreatedAt:ts}) } } } }
    _ = json.NewEncoder(w).Encode(out)
}
// POST /admin/review handles both approve and deny actions
func (k *Kernel) handleReview(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost || !k.isAdmin(r) || k.pg == nil { 
        w.WriteHeader(http.StatusUnauthorized)
        return 
    }
    
    var req reviewRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        w.WriteHeader(http.StatusBadRequest)
        return
    }
    
    // Validate required fields
    if req.Action == "" || req.ProducerID == "" {
        w.WriteHeader(http.StatusBadRequest)
        return
    }
    if req.Action == "deny" && req.Reason == "" {
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
            logging.Info("admin_review_error", logging.Err(err))
            w.WriteHeader(http.StatusInternalServerError)
            return
        }
        
        if hasApprovedKey {
            // Key rotation - need fingerprint
            if req.Fingerprint == "" {
                w.WriteHeader(http.StatusBadRequest)
                return
            }
            _, err = k.pg.ApproveKeyRotation(r.Context(), req.Fingerprint, req.ProducerID, adminPrincipal, req.Notes)
            result = map[string]any{"producer_id": req.ProducerID, "status": "approved", "fingerprint": req.Fingerprint, "type": "key_rotation"}
        } else {
            // New producer - need name
            if req.Fingerprint == "" {
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
                logging.Info("admin_review_error", logging.Err(err))
                w.WriteHeader(http.StatusInternalServerError)
                return
            }
            _, err = k.pg.ApproveNewProducerKey(r.Context(), req.Fingerprint, producerName, adminPrincipal, req.Notes)
            result = map[string]any{"producer_id": req.ProducerID, "status": "approved", "fingerprint": req.Fingerprint, "type": "new_producer"}
        }
        
        if err != nil {
            logging.Info("admin_approve_error", logging.Err(err))
            w.WriteHeader(http.StatusBadRequest)
            return
        }
        logging.Info("admin_approved", logging.F("producer_id", req.ProducerID), logging.F("fingerprint", req.Fingerprint))
        
    } else if req.Action == "deny" {
        if req.Fingerprint == "" {
            w.WriteHeader(http.StatusBadRequest)
            return
        }
        err = k.pg.RejectProducerKey(r.Context(), req.Fingerprint, adminPrincipal, req.Reason)
        if err != nil {
            logging.Info("admin_deny_error", logging.Err(err))
            w.WriteHeader(http.StatusBadRequest)
            return
        }
        result = map[string]any{"producer_id": req.ProducerID, "status": "denied", "fingerprint": req.Fingerprint, "reason": req.Reason}
        logging.Info("admin_denied", logging.F("producer_id", req.ProducerID), logging.F("fingerprint", req.Fingerprint), logging.F("reason", req.Reason))
    } else {
        w.WriteHeader(http.StatusBadRequest)
        return
    }
    
    _ = json.NewEncoder(w).Encode(result)
}

// POST /admin/approve - backward compatibility, redirects to review
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
            w.WriteHeader(http.StatusBadRequest)
            return
        }
        // For legacy, create producer with the provided name
        if req.Name == "" {
            w.WriteHeader(http.StatusBadRequest)
            return
        }
        // This is a simplified legacy path - create producer and approve key
        pid, err := k.pg.ApproveNewProducerKey(r.Context(), req.Fingerprint, req.Name, r.Header.Get("X-SSH-Principal"), req.Notes)
        if err != nil {
            logging.Info("admin_approve_legacy_error", logging.Err(err))
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
	if k.cfg != nil && k.cfg.Auth.Enabled && k.cfg.Auth.AdminSSHCA != "" {
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
                        // include explicit deny log only when header present
                        logging.Warn("admin_cert_check_failed", logging.F("principal", principal))
                    }
				}
			}
		}
	}
	return false
}

