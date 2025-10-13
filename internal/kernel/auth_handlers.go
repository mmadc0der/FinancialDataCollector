package kernel

import (
    "encoding/json"
    "net/http"
    "time"

    ssh "golang.org/x/crypto/ssh"
)

type issueRequest struct {
    ProducerID string `json:"producer_id"`
    TTLSeconds int    `json:"ttl_seconds"`
    Notes      string `json:"notes"`
}

func (k *Kernel) handleIssueToken(w http.ResponseWriter, r *http.Request) {
    if k.au == nil || r.Method != http.MethodPost || !k.isAdmin(r) {
        w.WriteHeader(http.StatusUnauthorized)
        return
    }
    var req issueRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ProducerID == "" || req.TTLSeconds <= 0 {
        w.WriteHeader(http.StatusBadRequest)
        return
    }
    tok, jti, exp, err := k.au.Issue(r.Context(), req.ProducerID, time.Duration(req.TTLSeconds)*time.Second, req.Notes)
    if err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        return
    }
    _ = json.NewEncoder(w).Encode(map[string]any{"token": tok, "jti": jti, "expires_at": exp})
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
    w.WriteHeader(http.StatusNoContent)
}

// isAdmin verifies admin via OpenSSH CA cert headers (PoC: falls back to X-Admin-Token)
func (k *Kernel) isAdmin(r *http.Request) bool {
    // Verify via OpenSSH certificate if configured
    if k.cfg != nil && k.cfg.Auth.Enabled && k.cfg.Auth.AdminSSHCA != "" {
        certHeader := r.Header.Get("X-SSH-Cert")
        principal := r.Header.Get("X-SSH-Principal")
        if certHeader != "" && principal != "" {
            caPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(k.cfg.Auth.AdminSSHCA))
            if err == nil && caPub != nil {
                certPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(certHeader))
                if err == nil {
                    if cert, ok := certPub.(*ssh.Certificate); ok {
                        checker := ssh.CertChecker{
                            IsAuthority: func(auth ssh.PublicKey) bool { return ssh.KeysEqual(auth, caPub) },
                        }
                        if err := checker.CheckCert(principal, cert); err == nil {
                            return true
                        }
                    }
                }
            }
        }
    }
    // Fallback to shared admin token if provided
    if k.cfg.Auth.AdminToken != "" && r.Header.Get("X-Admin-Token") == k.cfg.Auth.AdminToken {
        return true
    }
    return false
}

