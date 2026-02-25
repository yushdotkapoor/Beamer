package router

import (
	"encoding/json"
	"net/http"

	"github.com/yushrajkapoor/beamer/internal/auth"
	"github.com/yushrajkapoor/beamer/internal/middleware"
)

type Deps struct {
	AuthHandler *auth.Handler
	JWTManager  *auth.JWTManager
	RateLimiter *middleware.RateLimiter
	AuthLimiter *middleware.RateLimiter
	CORSOrigins []string
	IPAllowlist []string
}

func New(deps Deps) http.Handler {
	mux := http.NewServeMux()

	// Health (unauthenticated)
	mux.HandleFunc("GET /api/v1/health", handleHealth)

	// Auth (unauthenticated)
	mux.HandleFunc("POST /api/v1/auth/register", deps.AuthHandler.Register)
	mux.HandleFunc("POST /api/v1/auth/login", deps.AuthHandler.Login)
	mux.HandleFunc("POST /api/v1/auth/totp/validate", deps.AuthHandler.TOTPValidate)
	mux.HandleFunc("POST /api/v1/auth/refresh", deps.AuthHandler.Refresh)

	// Auth (authenticated)
	mux.Handle("POST /api/v1/auth/logout", applyAuth(deps.JWTManager, http.HandlerFunc(deps.AuthHandler.Logout)))
	mux.Handle("POST /api/v1/auth/totp/setup", applyAuth(deps.JWTManager, http.HandlerFunc(deps.AuthHandler.TOTPSetup)))
	mux.Handle("POST /api/v1/auth/totp/verify", applyAuth(deps.JWTManager, http.HandlerFunc(deps.AuthHandler.TOTPVerify)))
	mux.Handle("DELETE /api/v1/auth/totp", applyAuth(deps.JWTManager, http.HandlerFunc(deps.AuthHandler.TOTPDisable)))

	// Admin
	mux.Handle("POST /api/v1/admin/users", applyAdmin(deps.JWTManager, http.HandlerFunc(deps.AuthHandler.CreateUser)))
	mux.Handle("GET /api/v1/admin/users", applyAdmin(deps.JWTManager, http.HandlerFunc(deps.AuthHandler.ListUsers)))
	mux.Handle("DELETE /api/v1/admin/users/{id}", applyAdmin(deps.JWTManager, http.HandlerFunc(deps.AuthHandler.DeleteUser)))

	// Build middleware chain (outermost first)
	var handler http.Handler = mux
	handler = middleware.SecurityHeaders(handler)
	handler = middleware.MaxBodySize(1 << 20)(handler) // 1MB
	handler = middleware.CORS(deps.CORSOrigins)(handler)
	handler = middleware.IPAllowlist(deps.IPAllowlist)(handler)
	handler = deps.RateLimiter.Middleware(handler)
	handler = middleware.Logging(handler)

	return handler
}

func applyAuth(jwtMgr *auth.JWTManager, h http.Handler) http.Handler {
	return auth.RequireAuth(jwtMgr)(h)
}

func applyAdmin(jwtMgr *auth.JWTManager, h http.Handler) http.Handler {
	return auth.RequireAdmin(jwtMgr)(h)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}
