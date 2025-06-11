package utils

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignJWT(t *testing.T) {
	tests := []struct {
		name    string
		key     []byte
		claims  jwt.MapClaims
		wantErr bool
	}{
		{
			name: "valid claims",
			key:  []byte("test-secret-key"),
			claims: jwt.MapClaims{
				"sub":      "test-user-id",
				"username": "testuser",
				"exp":      time.Now().Add(time.Hour).Unix(),
			},
			wantErr: false,
		},
		{
			name: "empty claims",
			key:  []byte("test-secret-key"),
			claims: jwt.MapClaims{},
			wantErr: false,
		},
		{
			name: "nil claims",
			key:  []byte("test-secret-key"),
			claims: nil,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := SignJWT(tt.key, tt.claims)
			
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			
			require.NoError(t, err)
			assert.NotEmpty(t, token)
			
			// Verify token can be parsed back
			parsedClaims, err := ParseJWT(tt.key, token)
			require.NoError(t, err)
			
			if tt.claims != nil {
				for key, value := range tt.claims {
					// Handle int64 to float64 conversion for numeric values in JWT
					if expectedInt64, ok := value.(int64); ok {
						if actualFloat64, ok := parsedClaims[key].(float64); ok {
							assert.Equal(t, float64(expectedInt64), actualFloat64)
						} else {
							assert.Equal(t, value, parsedClaims[key])
						}
					} else {
						assert.Equal(t, value, parsedClaims[key])
					}
				}
			}
		})
	}
}

func TestParseJWT(t *testing.T) {
	key := []byte("test-secret-key")
	validClaims := jwt.MapClaims{
		"sub":      "test-user-id",
		"username": "testuser",
		"exp":      time.Now().Add(time.Hour).Unix(),
	}
	validToken, _ := SignJWT(key, validClaims)

	tests := []struct {
		name      string
		key       []byte
		jwtString string
		wantErr   bool
	}{
		{
			name:      "valid token",
			key:       key,
			jwtString: validToken,
			wantErr:   false,
		},
		{
			name:      "invalid token format",
			key:       key,
			jwtString: "invalid.token.format",
			wantErr:   true,
		},
		{
			name:      "wrong key",
			key:       []byte("wrong-key"),
			jwtString: validToken,
			wantErr:   true,
		},
		{
			name:      "empty token",
			key:       key,
			jwtString: "",
			wantErr:   true,
		},
		{
			name:      "malformed token",
			key:       key,
			jwtString: "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.malformed",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims, err := ParseJWT(tt.key, tt.jwtString)
			
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, claims)
				return
			}
			
			require.NoError(t, err)
			assert.NotNil(t, claims)
		})
	}
}

func TestParseJWT_ExpiredToken(t *testing.T) {
	key := []byte("test-secret-key")
	expiredClaims := jwt.MapClaims{
		"sub":      "test-user-id",
		"username": "testuser",
		"exp":      time.Now().Add(-time.Hour).Unix(), // Expired 1 hour ago
	}
	expiredToken, _ := SignJWT(key, expiredClaims)

	claims, err := ParseJWT(key, expiredToken)
	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.Contains(t, err.Error(), "invalid token")
}

func TestExtractUserInfo(t *testing.T) {
	validUserID := uuid.New()

	tests := []struct {
		name      string
		claims    map[string]interface{}
		wantID    uuid.UUID
		wantUser  string
		wantErr   bool
	}{
		{
			name: "valid claims",
			claims: map[string]interface{}{
				"sub":      validUserID.String(),
				"username": "testuser",
			},
			wantID:   validUserID,
			wantUser: "testuser",
			wantErr:  false,
		},
		{
			name: "missing sub claim",
			claims: map[string]interface{}{
				"username": "testuser",
			},
			wantErr: true,
		},
		{
			name: "invalid sub format",
			claims: map[string]interface{}{
				"sub":      "invalid-uuid",
				"username": "testuser",
			},
			wantErr: true,
		},
		{
			name: "missing username claim",
			claims: map[string]interface{}{
				"sub": validUserID.String(),
			},
			wantErr: true,
		},
		{
			name: "non-string sub",
			claims: map[string]interface{}{
				"sub":      123,
				"username": "testuser",
			},
			wantErr: true,
		},
		{
			name: "non-string username",
			claims: map[string]interface{}{
				"sub":      validUserID.String(),
				"username": 123,
			},
			wantErr: true,
		},
		{
			name:    "nil claims",
			claims:  nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userID, username, err := ExtractUserInfo(tt.claims)
			
			if tt.wantErr {
				assert.Error(t, err)
				assert.Equal(t, uuid.Nil, userID)
				assert.Empty(t, username)
				return
			}
			
			require.NoError(t, err)
			assert.Equal(t, tt.wantID, userID)
			assert.Equal(t, tt.wantUser, username)
		})
	}
}

func TestParseHeaderJWTClaims(t *testing.T) {
	key := []byte("test-secret-key")
	validClaims := jwt.MapClaims{
		"sub":      uuid.New().String(),
		"username": "testuser",
		"exp":      time.Now().Add(time.Hour).Unix(),
	}
	validToken, _ := SignJWT(key, validClaims)

	tests := []struct {
		name        string
		setupReq    func() *http.Request
		wantErr     bool
		expectClaim string
	}{
		{
			name: "valid bearer token in header",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "/test", nil)
				req.Header.Set("Authorization", "Bearer "+validToken)
				return req
			},
			wantErr:     false,
			expectClaim: "testuser",
		},
		{
			name: "valid token in cookie",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "/test", nil)
				req.AddCookie(&http.Cookie{
					Name:  "JWT-Cookie",
					Value: validToken,
				})
				return req
			},
			wantErr:     false,
			expectClaim: "testuser",
		},
		{
			name: "no token in header or cookie",
			setupReq: func() *http.Request {
				return httptest.NewRequest("GET", "/test", nil)
			},
			wantErr: true,
		},
		{
			name: "invalid bearer token format",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "/test", nil)
				req.Header.Set("Authorization", "Basic invalid-token")
				return req
			},
			wantErr: true,
		},
		{
			name: "invalid token in header",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "/test", nil)
				req.Header.Set("Authorization", "Bearer invalid-token")
				return req
			},
			wantErr: true,
		},
		{
			name: "token with extra whitespace",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "/test", nil)
				req.Header.Set("Authorization", "Bearer  "+validToken+"  ")
				return req
			},
			wantErr:     false,
			expectClaim: "testuser",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := tt.setupReq()
			claims, err := ParseHeaderJWTClaims(req, key)
			
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, claims)
				return
			}
			
			require.NoError(t, err)
			assert.NotNil(t, claims)
			if tt.expectClaim != "" {
				assert.Equal(t, tt.expectClaim, claims["username"])
			}
		})
	}
}

func TestExtractBearerToken(t *testing.T) {
	tests := []struct {
		name       string
		authHeader string
		want       string
	}{
		{
			name:       "valid bearer token",
			authHeader: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			want:       "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
		},
		{
			name:       "bearer with extra spaces",
			authHeader: "Bearer  token-with-spaces  ",
			want:       " token-with-spaces  ",
		},
		{
			name:       "basic auth header",
			authHeader: "Basic dXNlcjpwYXNz",
			want:       "",
		},
		{
			name:       "empty header",
			authHeader: "",
			want:       "",
		},
		{
			name:       "only bearer",
			authHeader: "Bearer",
			want:       "",
		},
		{
			name:       "malformed bearer",
			authHeader: "BearerToken",
			want:       "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractBearerToken(tt.authHeader)
			assert.Equal(t, tt.want, got)
		})
	}
}

// Integration test combining multiple JWT functions
func TestJWTIntegration(t *testing.T) {
	key := []byte("integration-test-key")
	userID := uuid.New()
	username := "integrationuser"

	// Create claims
	claims := jwt.MapClaims{
		"sub":      userID.String(),
		"username": username,
		"exp":      time.Now().Add(time.Hour).Unix(),
	}

	// Sign token
	token, err := SignJWT(key, claims)
	require.NoError(t, err)

	// Parse token
	parsedClaims, err := ParseJWT(key, token)
	require.NoError(t, err)

	// Extract user info
	extractedID, extractedUsername, err := ExtractUserInfo(parsedClaims)
	require.NoError(t, err)

	// Verify everything matches
	assert.Equal(t, userID, extractedID)
	assert.Equal(t, username, extractedUsername)

	// Test with HTTP request
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	headerClaims, err := ParseHeaderJWTClaims(req, key)
	require.NoError(t, err)

	headerID, headerUsername, err := ExtractUserInfo(headerClaims)
	require.NoError(t, err)

	assert.Equal(t, userID, headerID)
	assert.Equal(t, username, headerUsername)
}