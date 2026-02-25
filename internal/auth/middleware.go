package auth

import (
	"context"
	"net/http"
	"strings"
)

type contextKey string

const claimsKey contextKey = "claims"

func ClaimsFromContext(ctx context.Context) *TokenClaims {
	claims, _ := ctx.Value(claimsKey).(*TokenClaims)
	return claims
}

func RequireAuth(jwtMgr *JWTManager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := extractBearerToken(r)
			if token == "" {
				writeError(w, http.StatusUnauthorized, "MISSING_TOKEN", "Authorization header required")
				return
			}

			claims, err := jwtMgr.ValidateToken(token)
			if err != nil {
				writeError(w, http.StatusUnauthorized, "INVALID_TOKEN", "Invalid or expired token")
				return
			}

			if claims.Type != "access" {
				writeError(w, http.StatusUnauthorized, "WRONG_TOKEN_TYPE", "Access token required")
				return
			}

			ctx := context.WithValue(r.Context(), claimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func RequireAdmin(jwtMgr *JWTManager) func(http.Handler) http.Handler {
	authMiddleware := RequireAuth(jwtMgr)
	return func(next http.Handler) http.Handler {
		return authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := ClaimsFromContext(r.Context())
			if claims == nil || claims.Role != "admin" {
				writeError(w, http.StatusForbidden, "FORBIDDEN", "Admin access required")
				return
			}
			next.ServeHTTP(w, r)
		}))
	}
}

func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		// Fallback: check query parameter (for streaming clients like VLC)
		return r.URL.Query().Get("token")
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return ""
	}
	return parts[1]
}
