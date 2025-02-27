package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	repositories "tofoss/org-go/pkg/db/users"
	"tofoss/org-go/pkg/handlers/errors"
	"tofoss/org-go/pkg/handlers/requests"
	"tofoss/org-go/pkg/utils"

	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/net/xsrftoken"
)

type UserHandler struct {
	repo    *repositories.UserRepository
	jwtKey  string
	xsrfKey string
}

func NewUserHandler(
	repo *repositories.UserRepository,
	jwtKey string,
	xsrfKey string,
) UserHandler {
	return UserHandler{repo, jwtKey, xsrfKey}
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
		log.Printf("could fetch hashed password, %v", err)
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
		"sub": user.ID.String(),
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
		Value:    xsrftoken.Generate(h.xsrfKey, user.ID.String(), ""),
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

/*
loginHandler ::
  Connection ->
  CookieSettings ->
  JWTSettings ->
  LoginRequest ->
  Handler (Headers '[Header "Set-Cookie" SetCookie, Header "Set-Cookie" SetCookie] NoContent)
loginHandler conn cookieSettings jwtSettings loginRequest = do
  authResult <- liftIO $ authCheck conn loginRequest
  loginUser cookieSettings jwtSettings authResult

loginUser ::
  CookieSettings ->
  JWTSettings ->
  AuthResult User ->
  Handler (Headers '[Header "Set-Cookie" SetCookie, Header "Set-Cookie" SetCookie] NoContent)
loginUser cookieSettings jwtSettings authResult =
    auth authResult $ createCookies cookieSettings jwtSettings

createCookies ::
  CookieSettings ->
  JWTSettings ->
  User ->
  Handler (Headers '[Header "Set-Cookie" SetCookie, Header "Set-Cookie" SetCookie] NoContent)
createCookies cookieSettings jwtSettings user = do
  cookies <- liftIO $ acceptLogin cookieSettings jwtSettings user
  case cookies of
    Nothing -> throwError err500 {errBody = "Failed to create session"}
    Just c -> return $ c NoContent

authCheck :: Connection -> LoginRequest -> IO (AuthResult User)
authCheck conn LoginRequest {..} = do
  result <- verifyUser conn loginUsername loginPassword
  pure $ maybe Indefinite Authenticated result

verifyUser :: Connection -> String -> String -> IO (Maybe User)
verifyUser conn username password = do
  maybePassword <- liftIO $ fetchHashedPassword conn username
  case maybePassword of
    Nothing -> return Nothing
    Just hash -> do
      if not (verifyPassword password hash)
        then do
          return Nothing
        else do
          liftIO $ fetchUser conn username

authStatusHandler :: AuthResult User -> Handler AuthStatusResponse
authStatusHandler (Authenticated User {..}) = return $ AuthStatusResponse True username
authStatusHandler _ = return $ AuthStatusResponse False ""

*/
