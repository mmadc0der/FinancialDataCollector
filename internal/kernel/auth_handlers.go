package kernel

import (
    "encoding/json"
    "net/http"
    "time"
)

type issueRequest struct {
    ProducerID string `json:"producer_id"`
    TTLSeconds int    `json:"ttl_seconds"`
    Notes      string `json:"notes"`
}

func (k *Kernel) handleIssueToken(w http.ResponseWriter, r *http.Request) {
    if k.au == nil || r.Method != http.MethodPost || r.Header.Get("X-Admin-Token") != k.cfg.Auth.AdminToken {
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
    if k.au == nil || r.Method != http.MethodPost || r.Header.Get("X-Admin-Token") != k.cfg.Auth.AdminToken {
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
