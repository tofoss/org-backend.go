package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	repositories "tofoss/org-go/pkg/db/users"
	"tofoss/org-go/pkg/handlers/errors"
	"tofoss/org-go/pkg/handlers/requests"

	"golang.org/x/crypto/bcrypt"
)

type UserHandler struct {
	repo *repositories.UserRepository
}

func NewUserHandler(
	repo *repositories.UserRepository,
) UserHandler {
	return UserHandler{repo}
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
registerHandler :: Connection -> RegisterRequest -> Handler RegisterResponse
registerHandler conn RegisterRequest {..} = do
  userExists <- liftIO $ checkUserExists conn username
  if userExists
    then throwError err409 {errBody = "Username already exists"}
    else handleUserRegistration conn username password

handleUserRegistration :: Connection -> String -> String -> Handler RegisterResponse
handleUserRegistration conn username password = do
  hashedPassword <- hashPassword password
  registerUser conn username hashedPassword

hashPassword :: String -> Handler String
hashPassword password = do
  maybeHashedPassword <- liftIO $ hashPassword' password
  case maybeHashedPassword of
    Nothing -> throwError err500 {errBody = "Password hashing failed"}
    Just hash -> return hash

registerUser :: Connection -> String -> String -> Handler RegisterResponse
registerUser conn username hashedPassword = do
  success <- liftIO $ insertUser conn username hashedPassword
  if success
    then return RegisterResponse {message = "Success"}
    else throwError err500 {errBody = "User registration failed"}

authStatusHandler :: AuthResult User -> Handler AuthStatusResponse
authStatusHandler (Authenticated User {..}) = return $ AuthStatusResponse True username
authStatusHandler _ = return $ AuthStatusResponse False ""

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

*/
