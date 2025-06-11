package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
	"tofoss/org-go/pkg/utils"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJWTMiddleware(t *testing.T) {
	key := []byte("test-jwt-secret")
	userID := uuid.New()
	username := "testuser"

	// Create a valid JWT token
	claims := jwt.MapClaims{
		"sub":      userID.String(),
		"username": username,
		"exp":      time.Now().Add(time.Hour).Unix(),
	}
	validToken, err := utils.SignJWT(key, claims)
	require.NoError(t, err)

	// Test handler that checks context values
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contextUserID, contextUsername, err := utils.UserContext(r)
		if err != nil {
			http.Error(w, "Context error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		
		w.Header().Set("X-User-ID", contextUserID.String())
		w.Header().Set("X-Username", contextUsername)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	})

	middleware := JWTMiddleware(key)
	handler := middleware(testHandler)

	tests := []struct {
		name           string
		setupRequest   func() *http.Request
		expectedStatus int
		checkResponse  func(t *testing.T, w *httptest.ResponseRecorder)
	}{
		{
			name: "valid bearer token in header",
			setupRequest: func() *http.Request {
				req := httptest.NewRequest("GET", "/test", nil)
				req.Header.Set("Authorization", "Bearer "+validToken)
				return req
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Equal(t, userID.String(), w.Header().Get("X-User-ID"))
				assert.Equal(t, username, w.Header().Get("X-Username"))
				assert.Equal(t, "success", w.Body.String())
			},
		},
		{
			name: "valid token in cookie",
			setupRequest: func() *http.Request {
				req := httptest.NewRequest("GET", "/test", nil)
				req.AddCookie(&http.Cookie{
					Name:  "JWT-Cookie",
					Value: validToken,
				})
				return req
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Equal(t, userID.String(), w.Header().Get("X-User-ID"))
				assert.Equal(t, username, w.Header().Get("X-Username"))
				assert.Equal(t, "success", w.Body.String())
			},
		},
		{
			name: "missing token",
			setupRequest: func() *http.Request {
				return httptest.NewRequest("GET", "/test", nil)
			},
			expectedStatus: http.StatusUnauthorized,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "Unautorized")
			},
		},
		{
			name: "invalid token format",
			setupRequest: func() *http.Request {
				req := httptest.NewRequest("GET", "/test", nil)
				req.Header.Set("Authorization", "Bearer invalid-token")
				return req
			},
			expectedStatus: http.StatusUnauthorized,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "Unautorized")
			},
		},
		{
			name: "expired token",
			setupRequest: func() *http.Request {
				expiredClaims := jwt.MapClaims{
					"sub":      userID.String(),
					"username": username,
					"exp":      time.Now().Add(-time.Hour).Unix(), // Expired
				}
				expiredToken, _ := utils.SignJWT(key, expiredClaims)
				
				req := httptest.NewRequest("GET", "/test", nil)
				req.Header.Set("Authorization", "Bearer "+expiredToken)
				return req
			},
			expectedStatus: http.StatusUnauthorized,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "Unautorized")
			},
		},
		{
			name: "token with wrong key",
			setupRequest: func() *http.Request {
				wrongKey := []byte("wrong-secret")
				wrongToken, _ := utils.SignJWT(wrongKey, claims)
				
				req := httptest.NewRequest("GET", "/test", nil)
				req.Header.Set("Authorization", "Bearer "+wrongToken)
				return req
			},
			expectedStatus: http.StatusUnauthorized,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "Unautorized")
			},
		},
		{
			name: "token with missing claims",
			setupRequest: func() *http.Request {
				invalidClaims := jwt.MapClaims{
					"exp": time.Now().Add(time.Hour).Unix(),
					// Missing sub and username
				}
				invalidToken, _ := utils.SignJWT(key, invalidClaims)
				
				req := httptest.NewRequest("GET", "/test", nil)
				req.Header.Set("Authorization", "Bearer "+invalidToken)
				return req
			},
			expectedStatus: http.StatusUnauthorized,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "invalid claims")
			},
		},
		{
			name: "malformed authorization header",
			setupRequest: func() *http.Request {
				req := httptest.NewRequest("GET", "/test", nil)
				req.Header.Set("Authorization", "Basic "+validToken) // Wrong auth type
				return req
			},
			expectedStatus: http.StatusUnauthorized,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "Unautorized")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := tt.setupRequest()
			w := httptest.NewRecorder()
			
			handler.ServeHTTP(w, req)
			
			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.checkResponse != nil {
				tt.checkResponse(t, w)
			}
		})
	}
}

func TestJWTMiddleware_ContextPropagation(t *testing.T) {
	key := []byte("test-context-secret")
	userID := uuid.New()
	username := "contextuser"

	claims := jwt.MapClaims{
		"sub":      userID.String(),
		"username": username,
		"exp":      time.Now().Add(time.Hour).Unix(),
	}
	token, err := utils.SignJWT(key, claims)
	require.NoError(t, err)

	// Handler that verifies context values are correctly set
	contextChecker := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		
		// Check UserID context value
		contextUserID, ok := ctx.Value(utils.UserIDKey).(uuid.UUID)
		assert.True(t, ok, "UserID should be in context")
		assert.Equal(t, userID, contextUserID, "UserID should match")
		
		// Check Username context value
		contextUsername, ok := ctx.Value(utils.UsernameKey).(string)
		assert.True(t, ok, "Username should be in context")
		assert.Equal(t, username, contextUsername, "Username should match")
		
		// Test utility function
		utilUserID, utilUsername, err := utils.UserContext(r)
		require.NoError(t, err)
		assert.Equal(t, userID, utilUserID)
		assert.Equal(t, username, utilUsername)
		
		w.WriteHeader(http.StatusOK)
	})

	middleware := JWTMiddleware(key)
	handler := middleware(contextChecker)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestJWTMiddleware_HandlerChaining(t *testing.T) {
	key := []byte("test-chaining-secret")
	userID := uuid.New()
	username := "chainuser"

	claims := jwt.MapClaims{
		"sub":      userID.String(),
		"username": username,
		"exp":      time.Now().Add(time.Hour).Unix(),
	}
	token, err := utils.SignJWT(key, claims)
	require.NoError(t, err)

	// Counter to track middleware execution order
	executionOrder := []string{}

	// First middleware that adds to execution order
	firstMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			executionOrder = append(executionOrder, "first")
			next.ServeHTTP(w, r)
		})
	}

	// Third middleware that adds to execution order
	thirdMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			executionOrder = append(executionOrder, "third")
			next.ServeHTTP(w, r)
		})
	}

	// Final handler
	finalHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		executionOrder = append(executionOrder, "handler")
		w.WriteHeader(http.StatusOK)
	})

	// Chain middlewares: first -> JWT -> third -> handler
	handler := firstMiddleware(JWTMiddleware(key)(thirdMiddleware(finalHandler)))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, []string{"first", "third", "handler"}, executionOrder)
}

func TestJWTMiddleware_DifferentHTTPMethods(t *testing.T) {
	key := []byte("test-methods-secret")
	userID := uuid.New()
	username := "methoduser"

	claims := jwt.MapClaims{
		"sub":      userID.String(),
		"username": username,
		"exp":      time.Now().Add(time.Hour).Unix(),
	}
	token, err := utils.SignJWT(key, claims)
	require.NoError(t, err)

	handler := JWTMiddleware(key)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("method: " + r.Method))
	}))

	methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}

	for _, method := range methods {
		t.Run("method_"+method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/test", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code)
			if method != "HEAD" { // HEAD requests don't return body
				assert.Contains(t, w.Body.String(), method)
			}
		})
	}
}