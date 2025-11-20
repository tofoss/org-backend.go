package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"tofoss/org-go/pkg/db/repositories"
	"tofoss/org-go/pkg/handlers/errors"
	"tofoss/org-go/pkg/handlers/requests"
	"tofoss/org-go/pkg/handlers/responses"
	"tofoss/org-go/pkg/utils"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/net/xsrftoken"
)

// AuthConfig holds authentication-related configuration
type AuthConfig struct {
	AccessTokenDuration  time.Duration
	RefreshTokenDuration time.Duration
	CookieSecure         bool
}

type UserHandler struct {
	repo             *repositories.UserRepository
	refreshTokenRepo *repositories.RefreshTokenRepository
	jwtKey           []byte
	xsrfKey          []byte
	authConfig       AuthConfig
}

func NewUserHandler(
	repo *repositories.UserRepository,
	refreshTokenRepo *repositories.RefreshTokenRepository,
	jwtKey []byte,
	xsrfKey []byte,
	authConfig AuthConfig,
) UserHandler {
	return UserHandler{repo, refreshTokenRepo, jwtKey, xsrfKey, authConfig}
}

func (h *UserHandler) Status(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	res := responses.AuthStatus{
		LoggedIn: false,
	}

	claims, err := utils.ParseHeaderJWTClaims(r, h.jwtKey)
	if err != nil {
		log.Println("unable to parse claims")
		json.NewEncoder(w).Encode(res)
		return
	}

	userID, username, err := utils.ExtractUserInfo(claims)
	if err != nil {
		log.Println("userID or username not found in claims")
		json.NewEncoder(w).Encode(res)
		return
	}

	res.LoggedIn = true
	res.UserID = userID.String()
	res.Username = username

	json.NewEncoder(w).Encode(res)
}

func (h *UserHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req requests.Register
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		log.Printf("could not decode request, %v", err)
		errors.BadRequest(w)
		return
	}

	// Input validation
	if len(req.Username) < 3 || len(req.Username) > 50 {
		errors.BadRequest(w)
		w.Write([]byte(`{"error": "Username must be between 3 and 50 characters"}`))
		return
	}

	if len(req.Password) < 8 || len(req.Password) > 128 {
		errors.BadRequest(w)
		w.Write([]byte(`{"error": "Password must be between 8 and 128 characters"}`))
		return
	}

	usernameTaken, err := h.repo.CheckUserExists(r.Context(), req.Username)
	if err != nil {
		log.Printf("could not check if user exists, %v", err)
		errors.InternalServerError(w)
		return
	}

	if usernameTaken {
		errors.Conflict(w, "Username already exists")
		return
	}

	pw, err := hashPassword(req.Password)
	if err != nil {
		log.Printf("could not hash password, %v", err)
		errors.InternalServerError(w)
		return
	}

	err = h.repo.Insert(r.Context(), req.Username, pw)
	if err != nil {
		log.Printf("could not insert user, %v", err)
		errors.InternalServerError(w)
		return
	}

	w.WriteHeader(200)
}

func (h *UserHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req requests.Login
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		log.Printf("could not decode request, %v", err)
		errors.BadRequest(w)
		return
	}

	// Fetch hashed password (returns empty string if user doesn't exist)
	hash, err := h.repo.FetchHashedPassword(r.Context(), req.Username)

	// Use a dummy hash if user doesn't exist to prevent timing attacks
	// This ensures bcrypt is always run with the same cost factor
	if err != nil || hash == "" {
		// Use a valid bcrypt hash (cost 10) so timing is consistent
		hash = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
	}

	// Always run bcrypt verification, even if user doesn't exist
	validPassword := verifyPassord(hash, req.Password)

	// Fetch user info (may be nil if user doesn't exist)
	user, fetchErr := h.repo.FetchUser(r.Context(), req.Username)

	// Check both conditions after all operations complete
	if !validPassword || fetchErr != nil || user == nil {
		log.Printf("failed login attempt for username: %s", req.Username)
		errors.Unauthorized(w, "invalid username or password")
		return
	}

	// Generate access token
	accessToken, err := utils.SignAccessToken(h.jwtKey, user.ID, user.Username, h.authConfig.AccessTokenDuration)
	if err != nil {
		log.Printf("failed to sign access token, %v", err)
		errors.InternalServerError(w)
		return
	}

	// Generate refresh token (7 days)
	refreshToken, err := utils.GenerateRefreshToken()
	if err != nil {
		log.Printf("failed to generate refresh token, %v", err)
		errors.InternalServerError(w)
		return
	}

	// Store refresh token hash in database
	tokenHash := utils.HashToken(refreshToken)
	expiresAt := time.Now().Add(h.authConfig.RefreshTokenDuration)
	err = h.refreshTokenRepo.Insert(r.Context(), user.ID, tokenHash, expiresAt)
	if err != nil {
		log.Printf("failed to store refresh token, %v", err)
		errors.InternalServerError(w)
		return
	}

	// Set access token cookie
	jwtCookie := http.Cookie{
		Name:     "JWT-Cookie",
		Value:    accessToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.authConfig.CookieSecure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(h.authConfig.AccessTokenDuration.Seconds()),
	}

	// Set refresh token cookie
	refreshCookie := http.Cookie{
		Name:     "REFRESH-TOKEN",
		Value:    refreshToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.authConfig.CookieSecure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(h.authConfig.RefreshTokenDuration.Seconds()),
	}

	// Set XSRF token cookie (matches access token duration)
	xsrfCookie := http.Cookie{
		Name:     "XSRF-TOKEN",
		Value:    xsrftoken.Generate(string(h.xsrfKey), user.ID.String(), ""),
		Path:     "/",
		HttpOnly: false,
		Secure:   h.authConfig.CookieSecure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(h.authConfig.AccessTokenDuration.Seconds()),
	}

	http.SetCookie(w, &jwtCookie)
	http.SetCookie(w, &refreshCookie)
	http.SetCookie(w, &xsrfCookie)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Login successful"})
}

// Refresh handles token rotation - validates refresh token and issues new tokens
func (h *UserHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	// Get refresh token from cookie
	refreshCookie, err := r.Cookie("REFRESH-TOKEN")
	if err != nil {
		log.Printf("refresh token cookie not found, %v", err)
		errors.Unauthorized(w, "refresh token required")
		return
	}

	refreshToken := refreshCookie.Value
	tokenHash := utils.HashToken(refreshToken)

	// Validate refresh token and get user ID
	valid, userID, err := h.refreshTokenRepo.IsValid(r.Context(), tokenHash)
	if err != nil {
		log.Printf("error validating refresh token, %v", err)
		errors.InternalServerError(w)
		return
	}

	if !valid {
		log.Printf("invalid or expired refresh token")
		errors.Unauthorized(w, "invalid or expired refresh token")
		return
	}

	// Get user info by ID
	user, err := h.repo.FetchUserByID(r.Context(), userID.String())
	if err != nil {
		log.Printf("failed to fetch user by ID, %v", err)
		errors.InternalServerError(w)
		return
	}

	if user == nil {
		log.Printf("user not found for ID %s", userID.String())
		errors.Unauthorized(w, "user not found")
		return
	}

	// Revoke the old refresh token (single-use tokens)
	err = h.refreshTokenRepo.Revoke(r.Context(), tokenHash)
	if err != nil {
		log.Printf("failed to revoke old refresh token, %v", err)
		errors.InternalServerError(w)
		return
	}

	// Generate new access token
	accessToken, err := utils.SignAccessToken(h.jwtKey, userID, user.Username, h.authConfig.AccessTokenDuration)
	if err != nil {
		log.Printf("failed to sign access token, %v", err)
		errors.InternalServerError(w)
		return
	}

	// Generate new refresh token (7 days)
	newRefreshToken, err := utils.GenerateRefreshToken()
	if err != nil {
		log.Printf("failed to generate refresh token, %v", err)
		errors.InternalServerError(w)
		return
	}

	// Store new refresh token hash
	newTokenHash := utils.HashToken(newRefreshToken)
	expiresAt := time.Now().Add(h.authConfig.RefreshTokenDuration)
	err = h.refreshTokenRepo.Insert(r.Context(), userID, newTokenHash, expiresAt)
	if err != nil {
		log.Printf("failed to store refresh token, %v", err)
		errors.InternalServerError(w)
		return
	}

	// Set new access token cookie
	jwtCookie := http.Cookie{
		Name:     "JWT-Cookie",
		Value:    accessToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.authConfig.CookieSecure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(h.authConfig.AccessTokenDuration.Seconds()),
	}

	// Set new refresh token cookie
	newRefreshCookie := http.Cookie{
		Name:     "REFRESH-TOKEN",
		Value:    newRefreshToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.authConfig.CookieSecure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(h.authConfig.RefreshTokenDuration.Seconds()),
	}

	// Set new XSRF token cookie
	xsrfCookie := http.Cookie{
		Name:     "XSRF-TOKEN",
		Value:    xsrftoken.Generate(string(h.xsrfKey), userID.String(), ""),
		Path:     "/",
		HttpOnly: false,
		Secure:   h.authConfig.CookieSecure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(h.authConfig.AccessTokenDuration.Seconds()),
	}

	http.SetCookie(w, &jwtCookie)
	http.SetCookie(w, &newRefreshCookie)
	http.SetCookie(w, &xsrfCookie)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Token refreshed successfully"})
}

func hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return string(hash), nil
}

func verifyPassord(hash, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// Logout revokes the refresh token and clears all auth cookies
func (h *UserHandler) Logout(w http.ResponseWriter, r *http.Request) {
	// Try to revoke the refresh token if present
	refreshCookie, err := r.Cookie("REFRESH-TOKEN")
	if err == nil && refreshCookie.Value != "" {
		tokenHash := utils.HashToken(refreshCookie.Value)
		err = h.refreshTokenRepo.Revoke(r.Context(), tokenHash)
		if err != nil {
			log.Printf("failed to revoke refresh token during logout, %v", err)
			// Continue with logout even if revocation fails
		}
	}

	// Clear JWT cookie
	jwtCookie := http.Cookie{
		Name:     "JWT-Cookie",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   h.authConfig.CookieSecure,
		SameSite: http.SameSiteStrictMode,
	}

	// Clear refresh token cookie
	refreshTokenCookie := http.Cookie{
		Name:     "REFRESH-TOKEN",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   h.authConfig.CookieSecure,
		SameSite: http.SameSiteStrictMode,
	}

	// Clear XSRF cookie
	xsrfCookie := http.Cookie{
		Name:     "XSRF-TOKEN",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: false,
		Secure:   h.authConfig.CookieSecure,
		SameSite: http.SameSiteStrictMode,
	}

	http.SetCookie(w, &jwtCookie)
	http.SetCookie(w, &refreshTokenCookie)
	http.SetCookie(w, &xsrfCookie)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Logout successful"})
}
