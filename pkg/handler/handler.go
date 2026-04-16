package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/sirosfoundation/go-ztts/pkg/auth"
	"github.com/sirosfoundation/go-ztts/pkg/service"
	"github.com/sirosfoundation/go-ztts/pkg/types"
)

// Handler provides HTTP handlers for the ztts API.
type Handler struct {
	svc *service.TokenService
}

// NewHandler creates a new Handler.
func NewHandler(svc *service.TokenService) *Handler {
	return &Handler{svc: svc}
}

// maxBodySize limits request bodies to 1MB to prevent resource exhaustion.
const maxBodySize = 1 << 20

// TokenHandler handles POST /token requests.
func (h *Handler) TokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	claims, ok := auth.ClaimsFromContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "no authenticated claims")
		return
	}
	var req types.TokenRequest
	r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Profile == "" {
		writeError(w, http.StatusBadRequest, "profile is required")
		return
	}
	resp, err := h.svc.ProcessRequest(r.Context(), claims, &req)
	if err != nil {
		slog.Warn("token request denied", "err", err)
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// RevokeHandler handles POST /revoke requests.
func (h *Handler) RevokeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	_, ok := auth.ClaimsFromContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "no authenticated claims")
		return
	}
	var req struct {
		JTI       string    `json:"jti"`
		ExpiresAt time.Time `json:"expires_at"`
		Reason    string    `json:"reason"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.JTI == "" {
		writeError(w, http.StatusBadRequest, "jti is required")
		return
	}
	if err := h.svc.RevokeToken(r.Context(), req.JTI, req.ExpiresAt, req.Reason); err != nil {
		writeError(w, http.StatusInternalServerError, "revocation failed")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "revoked"})
}

// HealthHandler returns a simple health check.
func (h *Handler) HealthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(types.ErrorResponse{
		Error:   http.StatusText(status),
		Message: message,
	})
}
