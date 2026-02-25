package auth

import (
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/yushrajkapoor/beamer/internal/config"
)

var usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9_]{3,32}$`)

type Handler struct {
	db  *sql.DB
	jwt *JWTManager
	cfg config.AuthConfig
}

func NewHandler(db *sql.DB, jwtMgr *JWTManager, cfg config.AuthConfig) *Handler {
	return &Handler{db: db, jwt: jwtMgr, cfg: cfg}
}

// --- Request / Response types ---

type registerRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type totpValidateRequest struct {
	TOTPToken string `json:"totp_token"`
	Code      string `json:"code"`
}

type totpVerifyRequest struct {
	Code string `json:"code"`
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type logoutRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type createUserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

// --- Handlers ---

func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	// Check if any admin exists — if so, registration is closed
	var adminCount int
	if err := h.db.QueryRow("SELECT COUNT(*) FROM users WHERE role = 'admin'").Scan(&adminCount); err != nil {
		writeError(w, http.StatusInternalServerError, "DATABASE_ERROR", "Internal error")
		return
	}
	if adminCount > 0 {
		writeError(w, http.StatusForbidden, "REGISTRATION_CLOSED", "Registration is closed. Contact an admin.")
		return
	}

	var req registerRequest
	if !readJSON(r, w, &req) {
		return
	}

	if !usernameRegex.MatchString(req.Username) {
		writeError(w, http.StatusBadRequest, "INVALID_USERNAME", "Username must be 3-32 characters, alphanumeric and underscores only")
		return
	}
	if len(req.Password) < 12 {
		writeError(w, http.StatusBadRequest, "WEAK_PASSWORD", "Password must be at least 12 characters")
		return
	}

	hash, err := HashPassword(req.Password, h.cfg.BcryptCost)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "HASH_ERROR", "Internal error")
		return
	}

	// First user is always admin
	role := "admin"

	result, err := h.db.Exec(
		"INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
		req.Username, hash, role,
	)
	if err != nil {
		writeError(w, http.StatusConflict, "USERNAME_TAKEN", "Username already exists")
		return
	}

	userID, _ := result.LastInsertId()

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"data": map[string]interface{}{
			"user_id":  userID,
			"username": req.Username,
			"role":     role,
			"message":  "Account created. Set up TOTP for 2FA.",
		},
	})
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if !readJSON(r, w, &req) {
		return
	}

	ip := remoteIP(r)

	// Check brute-force lockout
	if h.isLockedOut(ip) {
		writeError(w, http.StatusTooManyRequests, "LOCKED_OUT", "Too many failed attempts. Try again later.")
		return
	}

	var user struct {
		ID           int64
		Username     string
		PasswordHash string
		Role         string
		TOTPEnabled  bool
		TOTPSecret   sql.NullString
	}

	err := h.db.QueryRow(
		"SELECT id, username, password_hash, role, totp_enabled, totp_secret FROM users WHERE username = ?",
		req.Username,
	).Scan(&user.ID, &user.Username, &user.PasswordHash, &user.Role, &user.TOTPEnabled, &user.TOTPSecret)
	if err != nil {
		h.recordLoginAttempt(ip, req.Username, false)
		writeError(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "Username or password is incorrect")
		return
	}

	if !CheckPassword(user.PasswordHash, req.Password) {
		h.recordLoginAttempt(ip, req.Username, false)
		writeError(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "Username or password is incorrect")
		return
	}

	h.recordLoginAttempt(ip, req.Username, true)

	if user.TOTPEnabled {
		totpToken, err := h.jwt.GenerateTOTPPendingToken(user.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "TOKEN_ERROR", "Internal error")
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"data": map[string]interface{}{
				"totp_token":    totpToken,
				"requires_totp": true,
			},
		})
		return
	}

	h.issueTokens(w, user.ID, user.Username, user.Role)
}

func (h *Handler) TOTPValidate(w http.ResponseWriter, r *http.Request) {
	var req totpValidateRequest
	if !readJSON(r, w, &req) {
		return
	}

	claims, err := h.jwt.ValidateToken(req.TOTPToken)
	if err != nil || claims.Type != "totp_pending" {
		writeError(w, http.StatusUnauthorized, "INVALID_TOKEN", "Invalid or expired TOTP token")
		return
	}

	var user struct {
		ID         int64
		Username   string
		Role       string
		TOTPSecret string
	}
	err = h.db.QueryRow(
		"SELECT id, username, role, totp_secret FROM users WHERE id = ? AND totp_enabled = 1",
		claims.UserID,
	).Scan(&user.ID, &user.Username, &user.Role, &user.TOTPSecret)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "INVALID_TOKEN", "User not found or 2FA not enabled")
		return
	}

	if !ValidateTOTPCode(user.TOTPSecret, req.Code) {
		writeError(w, http.StatusUnauthorized, "INVALID_TOTP", "Invalid TOTP code")
		return
	}

	h.issueTokens(w, user.ID, user.Username, user.Role)
}

func (h *Handler) Refresh(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if !readJSON(r, w, &req) {
		return
	}

	tokenHash := HashRefreshToken(req.RefreshToken)

	var tokenRow struct {
		ID      int64
		UserID  int64
		Revoked bool
	}
	err := h.db.QueryRow(
		"SELECT id, user_id, revoked FROM refresh_tokens WHERE token_hash = ? AND expires_at > datetime('now')",
		tokenHash,
	).Scan(&tokenRow.ID, &tokenRow.UserID, &tokenRow.Revoked)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "INVALID_TOKEN", "Invalid or expired refresh token")
		return
	}

	if tokenRow.Revoked {
		// Reuse detected — revoke ALL tokens for this user
		slog.Warn("refresh token reuse detected, revoking all sessions", "user_id", tokenRow.UserID)
		h.db.Exec("UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?", tokenRow.UserID)
		writeError(w, http.StatusUnauthorized, "TOKEN_REUSED", "Refresh token already used. All sessions revoked.")
		return
	}

	// Revoke old token (single-use rotation)
	h.db.Exec("UPDATE refresh_tokens SET revoked = 1 WHERE id = ?", tokenRow.ID)

	var user struct {
		Username string
		Role     string
	}
	err = h.db.QueryRow("SELECT username, role FROM users WHERE id = ?", tokenRow.UserID).Scan(&user.Username, &user.Role)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "INVALID_TOKEN", "User not found")
		return
	}

	h.issueTokens(w, tokenRow.UserID, user.Username, user.Role)
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	var req logoutRequest
	if !readJSON(r, w, &req) {
		return
	}

	tokenHash := HashRefreshToken(req.RefreshToken)
	h.db.Exec("UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = ?", tokenHash)

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) TOTPSetup(w http.ResponseWriter, r *http.Request) {
	claims := ClaimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Not authenticated")
		return
	}

	var username string
	var totpEnabled bool
	err := h.db.QueryRow("SELECT username, totp_enabled FROM users WHERE id = ?", claims.UserID).Scan(&username, &totpEnabled)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "DATABASE_ERROR", "Internal error")
		return
	}
	if totpEnabled {
		writeError(w, http.StatusConflict, "TOTP_ALREADY_ENABLED", "2FA is already enabled")
		return
	}

	result, err := GenerateTOTP(username)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "TOTP_ERROR", "Failed to generate TOTP secret")
		return
	}

	// Store secret but don't enable yet — user must verify a code first
	_, err = h.db.Exec("UPDATE users SET totp_secret = ?, updated_at = datetime('now') WHERE id = ?",
		result.Secret, claims.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "DATABASE_ERROR", "Internal error")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"data": map[string]interface{}{
			"secret": result.Secret,
			"uri":    result.URI,
		},
	})
}

func (h *Handler) TOTPVerify(w http.ResponseWriter, r *http.Request) {
	claims := ClaimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Not authenticated")
		return
	}

	var req totpVerifyRequest
	if !readJSON(r, w, &req) {
		return
	}

	var secret sql.NullString
	err := h.db.QueryRow("SELECT totp_secret FROM users WHERE id = ? AND totp_enabled = 0", claims.UserID).Scan(&secret)
	if err != nil || !secret.Valid {
		writeError(w, http.StatusBadRequest, "NO_TOTP_PENDING", "No TOTP setup in progress. Call /auth/totp/setup first.")
		return
	}

	if !ValidateTOTPCode(secret.String, req.Code) {
		writeError(w, http.StatusUnauthorized, "INVALID_TOTP", "Invalid TOTP code. Check your authenticator app.")
		return
	}

	_, err = h.db.Exec("UPDATE users SET totp_enabled = 1, updated_at = datetime('now') WHERE id = ?", claims.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "DATABASE_ERROR", "Internal error")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"data": map[string]interface{}{
			"message": "2FA enabled successfully",
		},
	})
}

func (h *Handler) TOTPDisable(w http.ResponseWriter, r *http.Request) {
	claims := ClaimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Not authenticated")
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		writeError(w, http.StatusBadRequest, "MISSING_CODE", "TOTP code required as ?code= query parameter")
		return
	}

	var secret sql.NullString
	err := h.db.QueryRow("SELECT totp_secret FROM users WHERE id = ? AND totp_enabled = 1", claims.UserID).Scan(&secret)
	if err != nil || !secret.Valid {
		writeError(w, http.StatusBadRequest, "TOTP_NOT_ENABLED", "2FA is not enabled")
		return
	}

	if !ValidateTOTPCode(secret.String, code) {
		writeError(w, http.StatusUnauthorized, "INVALID_TOTP", "Invalid TOTP code")
		return
	}

	_, err = h.db.Exec("UPDATE users SET totp_enabled = 0, totp_secret = NULL, updated_at = datetime('now') WHERE id = ?", claims.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "DATABASE_ERROR", "Internal error")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"data": map[string]interface{}{
			"message": "2FA disabled",
		},
	})
}

// --- Admin handlers ---

func (h *Handler) CreateUser(w http.ResponseWriter, r *http.Request) {
	var req createUserRequest
	if !readJSON(r, w, &req) {
		return
	}

	if !usernameRegex.MatchString(req.Username) {
		writeError(w, http.StatusBadRequest, "INVALID_USERNAME", "Username must be 3-32 characters, alphanumeric and underscores only")
		return
	}
	if len(req.Password) < 12 {
		writeError(w, http.StatusBadRequest, "WEAK_PASSWORD", "Password must be at least 12 characters")
		return
	}

	role := req.Role
	if role == "" {
		role = "user"
	}
	if role != "admin" && role != "user" {
		writeError(w, http.StatusBadRequest, "INVALID_ROLE", "Role must be 'admin' or 'user'")
		return
	}

	hash, err := HashPassword(req.Password, h.cfg.BcryptCost)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "HASH_ERROR", "Internal error")
		return
	}

	result, err := h.db.Exec(
		"INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
		req.Username, hash, role,
	)
	if err != nil {
		writeError(w, http.StatusConflict, "USERNAME_TAKEN", "Username already exists")
		return
	}

	userID, _ := result.LastInsertId()

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"data": map[string]interface{}{
			"user_id":  userID,
			"username": req.Username,
			"role":     role,
		},
	})
}

func (h *Handler) ListUsers(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query("SELECT id, username, role, totp_enabled, created_at FROM users ORDER BY id")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "DATABASE_ERROR", "Internal error")
		return
	}
	defer rows.Close()

	var users []map[string]interface{}
	for rows.Next() {
		var id int64
		var username, role, createdAt string
		var totpEnabled bool
		if err := rows.Scan(&id, &username, &role, &totpEnabled, &createdAt); err != nil {
			continue
		}
		users = append(users, map[string]interface{}{
			"id":           id,
			"username":     username,
			"role":         role,
			"totp_enabled": totpEnabled,
			"created_at":   createdAt,
		})
	}

	if users == nil {
		users = []map[string]interface{}{}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"data": users,
	})
}

func (h *Handler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	userID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_ID", "Invalid user ID")
		return
	}

	claims := ClaimsFromContext(r.Context())
	if claims != nil && claims.UserID == userID {
		writeError(w, http.StatusBadRequest, "SELF_DELETE", "Cannot delete your own account")
		return
	}

	result, err := h.db.Exec("DELETE FROM users WHERE id = ?", userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "DATABASE_ERROR", "Internal error")
		return
	}

	affected, _ := result.RowsAffected()
	if affected == 0 {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "User not found")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// --- Internal helpers ---

func (h *Handler) issueTokens(w http.ResponseWriter, userID int64, username, role string) {
	accessToken, err := h.jwt.GenerateAccessToken(userID, username, role)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "TOKEN_ERROR", "Internal error")
		return
	}

	refreshToken, err := GenerateRefreshToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "TOKEN_ERROR", "Internal error")
		return
	}

	tokenHash := HashRefreshToken(refreshToken)
	expiresAt := time.Now().Add(h.jwt.RefreshTokenTTL())

	_, err = h.db.Exec(
		"INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)",
		userID, tokenHash, expiresAt.UTC().Format(time.RFC3339),
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "TOKEN_ERROR", "Internal error")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"data": map[string]interface{}{
			"access_token":  accessToken,
			"refresh_token": refreshToken,
			"token_type":    "Bearer",
			"expires_in":    int(h.jwt.accessTokenTTL.Seconds()),
		},
	})
}

func (h *Handler) isLockedOut(ip string) bool {
	var failCount int
	err := h.db.QueryRow(
		"SELECT COUNT(*) FROM login_attempts WHERE ip_address = ? AND success = 0 AND attempted_at > datetime('now', ?)",
		ip, "-"+strconv.Itoa(int(h.cfg.LockoutDuration.Minutes()))+" minutes",
	).Scan(&failCount)
	if err != nil {
		return false
	}
	return failCount >= h.cfg.MaxLoginAttempts
}

func (h *Handler) recordLoginAttempt(ip, username string, success bool) {
	successInt := 0
	if success {
		successInt = 1
	}
	h.db.Exec(
		"INSERT INTO login_attempts (ip_address, username, success) VALUES (?, ?, ?)",
		ip, username, successInt,
	)
}

// --- JSON helpers ---

func readJSON(r *http.Request, w http.ResponseWriter, dst interface{}) bool {
	if r.Body == nil {
		writeError(w, http.StatusBadRequest, "EMPTY_BODY", "Request body is required")
		return false
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)) // 1MB limit
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid request body")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]interface{}{
		"error": map[string]string{
			"code":    code,
			"message": message,
		},
	})
}

func remoteIP(r *http.Request) string {
	// Only use RemoteAddr — never trust X-Forwarded-For without a trusted proxy
	host := r.RemoteAddr
	// Strip port
	for i := len(host) - 1; i >= 0; i-- {
		if host[i] == ':' {
			return host[:i]
		}
	}
	return host
}
