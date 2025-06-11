package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
	"tofoss/org-go/pkg/db/repositories"
	"tofoss/org-go/pkg/handlers/requests"
	"tofoss/org-go/pkg/handlers/responses"
	"tofoss/org-go/pkg/models"
	"tofoss/org-go/pkg/utils"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func setupUserHandler(t *testing.T) (*UserHandler, pgxmock.PgxPoolIface) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)

	repo := repositories.NewUserRepository(mock)
	jwtKey := []byte("test-jwt-secret")
	xsrfKey := []byte("test-xsrf-secret")

	handler := NewUserHandler(repo, jwtKey, xsrfKey)
	return &handler, mock
}

func TestUserHandler_Register(t *testing.T) {
	tests := []struct {
		name           string
		requestBody    interface{}
		setupMock      func(mock pgxmock.PgxPoolIface)
		expectedStatus int
		checkResponse  func(t *testing.T, w *httptest.ResponseRecorder)
	}{
		{
			name: "successful registration",
			requestBody: requests.Register{
				Username: "newuser",
				Password: "password123",
			},
			setupMock: func(mock pgxmock.PgxPoolIface) {
				// User doesn't exist
				mock.ExpectQuery(`SELECT 1 FROM users WHERE username = \$1 LIMIT 1`).
					WithArgs("newuser").
					WillReturnError(pgx.ErrNoRows)

				// Insert user
				mock.ExpectExec(`INSERT INTO users \(username, password\) VALUES \(\$1, \$2\)`).
					WithArgs("newuser", pgxmock.AnyArg()).
					WillReturnResult(pgxmock.NewResult("INSERT", 1))
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Empty(t, w.Body.String())
			},
		},
		{
			name: "username already exists",
			requestBody: requests.Register{
				Username: "existinguser",
				Password: "password123",
			},
			setupMock: func(mock pgxmock.PgxPoolIface) {
				// User exists
				rows := pgxmock.NewRows([]string{"exists"}).AddRow(1)
				mock.ExpectQuery(`SELECT 1 FROM users WHERE username = \$1 LIMIT 1`).
					WithArgs("existinguser").
					WillReturnRows(rows)
			},
			expectedStatus: http.StatusConflict,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "Username already exists")
			},
		},
		{
			name:           "invalid JSON payload",
			requestBody:    "invalid-json",
			setupMock:      func(mock pgxmock.PgxPoolIface) {},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "Bad Request")
			},
		},
		{
			name: "database error during user check",
			requestBody: requests.Register{
				Username: "testuser",
				Password: "password123",
			},
			setupMock: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectQuery(`SELECT 1 FROM users WHERE username = \$1 LIMIT 1`).
					WithArgs("testuser").
					WillReturnError(assert.AnError)
			},
			expectedStatus: http.StatusInternalServerError,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "Internal Server Error")
			},
		},
		{
			name: "database error during insert",
			requestBody: requests.Register{
				Username: "testuser",
				Password: "password123",
			},
			setupMock: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectQuery(`SELECT 1 FROM users WHERE username = \$1 LIMIT 1`).
					WithArgs("testuser").
					WillReturnError(pgx.ErrNoRows)

				mock.ExpectExec(`INSERT INTO users`).
					WithArgs("testuser", pgxmock.AnyArg()).
					WillReturnError(assert.AnError)
			},
			expectedStatus: http.StatusInternalServerError,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "Internal Server Error")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, mock := setupUserHandler(t)
			defer mock.Close()

			tt.setupMock(mock)

			var body bytes.Buffer
			if str, ok := tt.requestBody.(string); ok {
				body.WriteString(str)
			} else {
				json.NewEncoder(&body).Encode(tt.requestBody)
			}

			req := httptest.NewRequest("POST", "/register", &body)
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			handler.Register(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.checkResponse != nil {
				tt.checkResponse(t, w)
			}
			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestUserHandler_Login(t *testing.T) {
	validPassword := "password123"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(validPassword), bcrypt.DefaultCost)
	userID := uuid.New()

	tests := []struct {
		name           string
		requestBody    interface{}
		setupMock      func(mock pgxmock.PgxPoolIface)
		expectedStatus int
		checkResponse  func(t *testing.T, w *httptest.ResponseRecorder)
	}{
		{
			name: "successful login",
			requestBody: requests.Login{
				Username: "validuser",
				Password: validPassword,
			},
			setupMock: func(mock pgxmock.PgxPoolIface) {
				// Fetch hashed password
				mock.ExpectQuery(`SELECT password FROM users WHERE username = \$1 LIMIT 1`).
					WithArgs("validuser").
					WillReturnRows(pgxmock.NewRows([]string{"password"}).AddRow(string(hashedPassword)))

				// Fetch user details
				mock.ExpectQuery(`SELECT id, username FROM users WHERE username = \$1`).
					WithArgs("validuser").
					WillReturnRows(pgxmock.NewRows([]string{"id", "username"}).AddRow(userID, "validuser"))
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				var response map[string]string
				err := json.Unmarshal(w.Body.Bytes(), &response)
				require.NoError(t, err)
				assert.Equal(t, "Login successful", response["message"])

				// Check cookies are set
				cookies := w.Result().Cookies()
				var jwtCookie, xsrfCookie *http.Cookie
				for _, cookie := range cookies {
					if cookie.Name == "JWT-Cookie" {
						jwtCookie = cookie
					}
					if cookie.Name == "XSRF-TOKEN" {
						xsrfCookie = cookie
					}
				}
				assert.NotNil(t, jwtCookie)
				assert.NotNil(t, xsrfCookie)
				assert.True(t, jwtCookie.HttpOnly)
				assert.False(t, xsrfCookie.HttpOnly)
			},
		},
		{
			name: "invalid password",
			requestBody: requests.Login{
				Username: "validuser",
				Password: "wrongpassword",
			},
			setupMock: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectQuery(`SELECT password FROM users WHERE username = \$1 LIMIT 1`).
					WithArgs("validuser").
					WillReturnRows(pgxmock.NewRows([]string{"password"}).AddRow(string(hashedPassword)))
			},
			expectedStatus: http.StatusUnauthorized,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "invalid username or password")
			},
		},
		{
			name: "user not found",
			requestBody: requests.Login{
				Username: "nonexistent",
				Password: "password123",
			},
			setupMock: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectQuery(`SELECT password FROM users WHERE username = \$1 LIMIT 1`).
					WithArgs("nonexistent").
					WillReturnError(pgx.ErrNoRows)
			},
			expectedStatus: http.StatusInternalServerError,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "Internal Server Error")
			},
		},
		{
			name:           "invalid JSON payload",
			requestBody:    "invalid-json",
			setupMock:      func(mock pgxmock.PgxPoolIface) {},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "Bad Request")
			},
		},
		{
			name: "database error during user fetch",
			requestBody: requests.Login{
				Username: "validuser",
				Password: validPassword,
			},
			setupMock: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectQuery(`SELECT password FROM users WHERE username = \$1 LIMIT 1`).
					WithArgs("validuser").
					WillReturnRows(pgxmock.NewRows([]string{"password"}).AddRow(string(hashedPassword)))

				mock.ExpectQuery(`SELECT id, username FROM users WHERE username = \$1`).
					WithArgs("validuser").
					WillReturnError(assert.AnError)
			},
			expectedStatus: http.StatusInternalServerError,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "Internal Server Error")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, mock := setupUserHandler(t)
			defer mock.Close()

			tt.setupMock(mock)

			var body bytes.Buffer
			if str, ok := tt.requestBody.(string); ok {
				body.WriteString(str)
			} else {
				json.NewEncoder(&body).Encode(tt.requestBody)
			}

			req := httptest.NewRequest("POST", "/login", &body)
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			handler.Login(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.checkResponse != nil {
				tt.checkResponse(t, w)
			}
			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestUserHandler_Status(t *testing.T) {
	jwtKey := []byte("test-jwt-secret")
	userID := uuid.New()
	username := "testuser"

	// Create valid JWT token
	claims := jwt.MapClaims{
		"sub":      userID.String(),
		"username": username,
		"exp":      time.Now().Add(time.Hour).Unix(),
	}
	validToken, _ := utils.SignJWT(jwtKey, claims)

	tests := []struct {
		name           string
		setupRequest   func() *http.Request
		expectedStatus int
		checkResponse  func(t *testing.T, w *httptest.ResponseRecorder)
	}{
		{
			name: "valid JWT token in header",
			setupRequest: func() *http.Request {
				req := httptest.NewRequest("GET", "/status", nil)
				req.Header.Set("Authorization", "Bearer "+validToken)
				return req
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				var response responses.AuthStatus
				err := json.Unmarshal(w.Body.Bytes(), &response)
				require.NoError(t, err)
				assert.True(t, response.LoggedIn)
				assert.Equal(t, userID.String(), response.UserID)
				assert.Equal(t, username, response.Username)
			},
		},
		{
			name: "valid JWT token in cookie",
			setupRequest: func() *http.Request {
				req := httptest.NewRequest("GET", "/status", nil)
				req.AddCookie(&http.Cookie{
					Name:  "JWT-Cookie",
					Value: validToken,
				})
				return req
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				var response responses.AuthStatus
				err := json.Unmarshal(w.Body.Bytes(), &response)
				require.NoError(t, err)
				assert.True(t, response.LoggedIn)
				assert.Equal(t, userID.String(), response.UserID)
				assert.Equal(t, username, response.Username)
			},
		},
		{
			name: "no JWT token",
			setupRequest: func() *http.Request {
				return httptest.NewRequest("GET", "/status", nil)
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				var response responses.AuthStatus
				err := json.Unmarshal(w.Body.Bytes(), &response)
				require.NoError(t, err)
				assert.False(t, response.LoggedIn)
				assert.Empty(t, response.UserID)
				assert.Empty(t, response.Username)
			},
		},
		{
			name: "invalid JWT token",
			setupRequest: func() *http.Request {
				req := httptest.NewRequest("GET", "/status", nil)
				req.Header.Set("Authorization", "Bearer invalid-token")
				return req
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				var response responses.AuthStatus
				err := json.Unmarshal(w.Body.Bytes(), &response)
				require.NoError(t, err)
				assert.False(t, response.LoggedIn)
			},
		},
		{
			name: "expired JWT token",
			setupRequest: func() *http.Request {
				expiredClaims := jwt.MapClaims{
					"sub":      userID.String(),
					"username": username,
					"exp":      time.Now().Add(-time.Hour).Unix(), // Expired
				}
				expiredToken, _ := utils.SignJWT(jwtKey, expiredClaims)

				req := httptest.NewRequest("GET", "/status", nil)
				req.Header.Set("Authorization", "Bearer "+expiredToken)
				return req
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				var response responses.AuthStatus
				err := json.Unmarshal(w.Body.Bytes(), &response)
				require.NoError(t, err)
				assert.False(t, response.LoggedIn)
			},
		},
		{
			name: "JWT token with missing claims",
			setupRequest: func() *http.Request {
				invalidClaims := jwt.MapClaims{
					"exp": time.Now().Add(time.Hour).Unix(),
					// Missing sub and username
				}
				invalidToken, _ := utils.SignJWT(jwtKey, invalidClaims)

				req := httptest.NewRequest("GET", "/status", nil)
				req.Header.Set("Authorization", "Bearer "+invalidToken)
				return req
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				var response responses.AuthStatus
				err := json.Unmarshal(w.Body.Bytes(), &response)
				require.NoError(t, err)
				assert.False(t, response.LoggedIn)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, mock := setupUserHandler(t)
			defer mock.Close()

			req := tt.setupRequest()
			w := httptest.NewRecorder()

			handler.Status(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
			if tt.checkResponse != nil {
				tt.checkResponse(t, w)
			}
		})
	}
}

func TestUserHandler_Integration(t *testing.T) {
	// Integration test that combines register -> login -> status
	handler, mock := setupUserHandler(t)
	defer mock.Close()

	username := "integrationuser"
	password := "password123"

	// Step 1: Register user
	t.Run("register", func(t *testing.T) {
		mock.ExpectQuery(`SELECT 1 FROM users WHERE username = \$1 LIMIT 1`).
			WithArgs(username).
			WillReturnError(pgx.ErrNoRows)

		mock.ExpectExec(`INSERT INTO users \(username, password\) VALUES \(\$1, \$2\)`).
			WithArgs(username, pgxmock.AnyArg()).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		regReq := requests.Register{
			Username: username,
			Password: password,
		}
		body, _ := json.Marshal(regReq)
		req := httptest.NewRequest("POST", "/register", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.Register(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	// Step 2: Login user
	var jwtCookie *http.Cookie
	t.Run("login", func(t *testing.T) {
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		userID := uuid.New()

		mock.ExpectQuery(`SELECT password FROM users WHERE username = \$1 LIMIT 1`).
			WithArgs(username).
			WillReturnRows(pgxmock.NewRows([]string{"password"}).AddRow(string(hashedPassword)))

		mock.ExpectQuery(`SELECT id, username FROM users WHERE username = \$1`).
			WithArgs(username).
			WillReturnRows(pgxmock.NewRows([]string{"id", "username"}).AddRow(userID, username))

		loginReq := requests.Login{
			Username: username,
			Password: password,
		}
		body, _ := json.Marshal(loginReq)
		req := httptest.NewRequest("POST", "/login", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.Login(w, req)
		assert.Equal(t, http.StatusOK, w.Code)

		// Extract JWT cookie for next request
		cookies := w.Result().Cookies()
		for _, cookie := range cookies {
			if cookie.Name == "JWT-Cookie" {
				jwtCookie = cookie
				break
			}
		}
		require.NotNil(t, jwtCookie)
	})

	// Step 3: Check status with JWT cookie
	t.Run("status_with_jwt", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/status", nil)
		req.AddCookie(jwtCookie)
		w := httptest.NewRecorder()

		handler.Status(w, req)
		assert.Equal(t, http.StatusOK, w.Code)

		var response responses.AuthStatus
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.True(t, response.LoggedIn)
		assert.Equal(t, username, response.Username)
	})

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestHashPassword(t *testing.T) {
	password := "testpassword123"

	hash, err := hashPassword(password)
	require.NoError(t, err)
	assert.NotEmpty(t, hash)
	assert.NotEqual(t, password, hash)

	// Verify the hash can be used to verify the password
	assert.True(t, verifyPassord(hash, password))
	assert.False(t, verifyPassord(hash, "wrongpassword"))
}

func TestVerifyPassword(t *testing.T) {
	password := "testpassword123"
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	tests := []struct {
		name     string
		hash     string
		password string
		expected bool
	}{
		{
			name:     "correct password",
			hash:     string(hash),
			password: password,
			expected: true,
		},
		{
			name:     "incorrect password",
			hash:     string(hash),
			password: "wrongpassword",
			expected: false,
		},
		{
			name:     "empty password",
			hash:     string(hash),
			password: "",
			expected: false,
		},
		{
			name:     "invalid hash",
			hash:     "invalid-hash",
			password: password,
			expected: false,
		},
		{
			name:     "empty hash",
			hash:     "",
			password: password,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := verifyPassord(tt.hash, tt.password)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestUserHandler_ErrorHandling(t *testing.T) {
	// Test various error scenarios
	handler, mock := setupUserHandler(t)
	defer mock.Close()

	t.Run("malformed request body", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/register", bytes.NewReader([]byte("{")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.Register(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("context cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		mock.ExpectQuery(`SELECT 1 FROM users WHERE username = \$1 LIMIT 1`).
			WithArgs("testuser").
			WillReturnError(context.Canceled)

		regReq := requests.Register{
			Username: "testuser",
			Password: "password123",
		}
		body, _ := json.Marshal(regReq)
		req := httptest.NewRequest("POST", "/register", bytes.NewReader(body))
		req = req.WithContext(ctx)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.Register(w, req)
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	assert.NoError(t, mock.ExpectationsWereMet())
}