package kernel

import (
    "bytes"
    "context"
    "encoding/json"
    "net/http"
    "time"

    ssh "golang.org/x/crypto/ssh"
)

type approveRequest struct {
	Fingerprint string `json:"fingerprint"`
	Name        string `json:"name"`        // producer name if creating
	SchemaID    string `json:"schema_id"`   // required when creating
	Notes       string `json:"notes"`
	TTLSeconds  int    `json:"ttl_seconds"` // token TTL to issue after approval
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
// POST /admin/approve approves a fingerprint (and optionally creates a producer) and issues a token
func (k *Kernel) handleApprove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || !k.isAdmin(r) || k.pg == nil || k.au == nil { w.WriteHeader(http.StatusUnauthorized); return }
	var req approveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Fingerprint == "" || req.TTLSeconds <= 0 {
		w.WriteHeader(http.StatusBadRequest); return
	}
	pid, err := k.pg.ApproveProducerKey(r.Context(), req.Fingerprint, req.Name, req.SchemaID, r.Header.Get("X-SSH-Principal"), req.Notes)
    if err != nil || pid == "" { w.WriteHeader(http.StatusBadRequest); return }
	tok, jti, exp, err := k.au.Issue(r.Context(), pid, time.Duration(req.TTLSeconds)*time.Second, "approved", req.Fingerprint)
    if err != nil { w.WriteHeader(http.StatusInternalServerError); return }
    logging.Info("admin_approve", logging.F("fingerprint", req.Fingerprint), logging.F("producer_id", pid), logging.F("jti", jti))
	_ = json.NewEncoder(w).Encode(map[string]any{"producer_id": pid, "token": tok, "jti": jti, "expires_at": exp})
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

