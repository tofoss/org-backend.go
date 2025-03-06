package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"tofoss/org-go/pkg/db/repositories"
	"tofoss/org-go/pkg/handlers/errors"
	"tofoss/org-go/pkg/handlers/requests"
	"tofoss/org-go/pkg/handlers/responses"
	"tofoss/org-go/pkg/utils"

	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/net/xsrftoken"
)

type UserHandler struct {
	repo    *repositories.UserRepository
	jwtKey  []byte
	xsrfKey []byte
}

func NewUserHandler(
	repo *repositories.UserRepository,
	jwtKey []byte,
	xsrfKey []byte,
) UserHandler {
	return UserHandler{repo, jwtKey, xsrfKey}
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

	hash, err := h.repo.FetchHashedPassword(r.Context(), req.Username)
	if err != nil {
		log.Printf("could not fetch hashed password, %v", err)
		errors.InternalServerError(w)
		return
	}

	if !verifyPassord(hash, req.Password) {
		log.Printf("user %s failed login attempt", req.Username)
		errors.Unauthorized(w, "invalid username or password")
		return
	}

	user, err := h.repo.FetchUser(r.Context(), req.Username)
	if err != nil {
		log.Printf("failed to fetch user, %v", err)
		errors.InternalServerError(w)
		return
	}

	claims := jwt.MapClaims{
		"sub":      user.ID.String(),
		"username": user.Username,
	}

	jwt, err := utils.SignJWT(h.jwtKey, claims)
	if err != nil {
		log.Printf("failed to sign jwt, %v", err)
		errors.InternalServerError(w)
		return
	}

	jwtCookie := http.Cookie{
		Name:     "JWT-Cookie",
		Value:    jwt,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}

	xsrfCookie := http.Cookie{
		Name:     "XSRF-TOKEN",
		Value:    xsrftoken.Generate(string(h.xsrfKey), user.ID.String(), ""),
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   86400,
	}

	http.SetCookie(w, &jwtCookie)
	http.SetCookie(w, &xsrfCookie)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Login successful"})
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
