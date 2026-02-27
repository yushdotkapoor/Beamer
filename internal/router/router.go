package router

import (
	"encoding/json"
	"net/http"

	"github.com/yushrajkapoor/beamer/internal/media"
	"github.com/yushrajkapoor/beamer/internal/middleware"
)

type Deps struct {
	MediaHandler    *media.Handler
	RateLimiter     *middleware.RateLimiter
	CORSOrigins     []string
	IPAllowlist     []string
	CertFingerprint string
}

func New(deps Deps) http.Handler {
	mux := http.NewServeMux()

	// Health & cert info
	mux.HandleFunc("GET /api/v1/health", handleHealth)
	mux.HandleFunc("GET /api/v1/cert/fingerprint", handleCertFingerprint(deps.CertFingerprint))

	// Media (mTLS-protected at TLS layer)
	mux.HandleFunc("GET /api/v1/media", deps.MediaHandler.ListMedia)
	mux.HandleFunc("GET /api/v1/media/browse", deps.MediaHandler.BrowseDirectories)
	mux.HandleFunc("GET /api/v1/media/search", deps.MediaHandler.SearchMedia)
	mux.HandleFunc("GET /api/v1/media/{id}", deps.MediaHandler.GetMedia)
	mux.HandleFunc("GET /api/v1/media/{id}/stream", deps.MediaHandler.StreamMedia)
	mux.HandleFunc("GET /api/v1/media/{id}/thumbnail", deps.MediaHandler.ServeThumbnail)

	// Media mutations
	mux.Handle("POST /api/v1/media/upload",
		withBodyLimit(4<<30, http.HandlerFunc(deps.MediaHandler.UploadMedia)))
	mux.Handle("POST /api/v1/media/upload/batch",
		withBodyLimit(4<<30, http.HandlerFunc(deps.MediaHandler.BatchUploadMedia)))
	mux.HandleFunc("DELETE /api/v1/media/{id}", deps.MediaHandler.DeleteMedia)
	mux.HandleFunc("PUT /api/v1/media/{id}", deps.MediaHandler.RenameMedia)

	// Admin
	mux.HandleFunc("POST /api/v1/admin/scan", deps.MediaHandler.TriggerRescan)

	// Middleware chain (outermost first)
	var handler http.Handler = mux
	handler = middleware.SecurityHeaders(handler)
	handler = middleware.CORS(deps.CORSOrigins)(handler)
	handler = middleware.IPAllowlist(deps.IPAllowlist)(handler)
	handler = deps.RateLimiter.Middleware(handler)
	handler = requireClientCert(handler)
	handler = middleware.Logging(handler)

	return handler
}

func withBodyLimit(limit int64, h http.Handler) http.Handler {
	return middleware.MaxBodySize(limit)(h)
}

// requireClientCert is a belt-and-suspenders check: the TLS layer already
// enforces RequireAndVerifyClientCert, but this rejects any request that
// somehow arrives without a verified peer certificate.
func requireClientCert(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error": map[string]string{
					"code":    "CERT_REQUIRED",
					"message": "Client certificate required",
				},
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func handleCertFingerprint(fingerprint string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"algorithm":   "SHA-256",
			"fingerprint": fingerprint,
		})
	}
}
