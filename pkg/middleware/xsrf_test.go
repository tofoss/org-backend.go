package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestXSRFProtection(t *testing.T) {
	// Test handler that just returns success
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	})

	middleware := XSRFProtection(testHandler)

	tests := []struct {
		name           string
		method         string
		setupRequest   func() *http.Request
		expectedStatus int
		expectedBody   string
	}{
		{
			name:   "GET request passes through",
			method: "GET",
			setupRequest: func() *http.Request {
				return httptest.NewRequest("GET", "/test", nil)
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "success",
		},
		{
			name:   "HEAD request passes through",
			method: "HEAD",
			setupRequest: func() *http.Request {
				return httptest.NewRequest("HEAD", "/test", nil)
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "", // HEAD requests don't return body
		},
		{
			name:   "POST with valid XSRF token",
			method: "POST",
			setupRequest: func() *http.Request {
				req := httptest.NewRequest("POST", "/test", strings.NewReader("data"))
				req.Header.Set("X-XSRF-TOKEN", "valid-token")
				req.AddCookie(&http.Cookie{
					Name:  "XSRF-TOKEN",
					Value: "valid-token",
				})
				return req
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "success",
		},
		{
			name:   "PUT with valid XSRF token",
			method: "PUT",
			setupRequest: func() *http.Request {
				req := httptest.NewRequest("PUT", "/test", strings.NewReader("data"))
				req.Header.Set("X-XSRF-TOKEN", "valid-token")
				req.AddCookie(&http.Cookie{
					Name:  "XSRF-TOKEN",
					Value: "valid-token",
				})
				return req
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "success",
		},
		{
			name:   "DELETE with valid XSRF token",
			method: "DELETE",
			setupRequest: func() *http.Request {
				req := httptest.NewRequest("DELETE", "/test", nil)
				req.Header.Set("X-XSRF-TOKEN", "valid-token")
				req.AddCookie(&http.Cookie{
					Name:  "XSRF-TOKEN",
					Value: "valid-token",
				})
				return req
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "success",
		},
		{
			name:   "PATCH with valid XSRF token",
			method: "PATCH",
			setupRequest: func() *http.Request {
				req := httptest.NewRequest("PATCH", "/test", strings.NewReader("data"))
				req.Header.Set("X-XSRF-TOKEN", "valid-token")
				req.AddCookie(&http.Cookie{
					Name:  "XSRF-TOKEN",
					Value: "valid-token",
				})
				return req
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "success",
		},
		{
			name:   "POST with missing XSRF header",
			method: "POST",
			setupRequest: func() *http.Request {
				req := httptest.NewRequest("POST", "/test", strings.NewReader("data"))
				req.AddCookie(&http.Cookie{
					Name:  "XSRF-TOKEN",
					Value: "valid-token",
				})
				return req
			},
			expectedStatus: http.StatusForbidden,
			expectedBody:   "XSRF token is missing",
		},
		{
			name:   "POST with empty XSRF header",
			method: "POST",
			setupRequest: func() *http.Request {
				req := httptest.NewRequest("POST", "/test", strings.NewReader("data"))
				req.Header.Set("X-XSRF-TOKEN", "")
				req.AddCookie(&http.Cookie{
					Name:  "XSRF-TOKEN",
					Value: "valid-token",
				})
				return req
			},
			expectedStatus: http.StatusForbidden,
			expectedBody:   "XSRF token is missing",
		},
		{
			name:   "POST with missing XSRF cookie",
			method: "POST",
			setupRequest: func() *http.Request {
				req := httptest.NewRequest("POST", "/test", strings.NewReader("data"))
				req.Header.Set("X-XSRF-TOKEN", "valid-token")
				return req
			},
			expectedStatus: http.StatusForbidden,
			expectedBody:   "Invalid XSRF token",
		},
		{
			name:   "POST with mismatched XSRF tokens",
			method: "POST",
			setupRequest: func() *http.Request {
				req := httptest.NewRequest("POST", "/test", strings.NewReader("data"))
				req.Header.Set("X-XSRF-TOKEN", "header-token")
				req.AddCookie(&http.Cookie{
					Name:  "XSRF-TOKEN",
					Value: "cookie-token",
				})
				return req
			},
			expectedStatus: http.StatusForbidden,
			expectedBody:   "Invalid XSRF token",
		},
		{
			name:   "POST with empty cookie value",
			method: "POST",
			setupRequest: func() *http.Request {
				req := httptest.NewRequest("POST", "/test", strings.NewReader("data"))
				req.Header.Set("X-XSRF-TOKEN", "valid-token")
				req.AddCookie(&http.Cookie{
					Name:  "XSRF-TOKEN",
					Value: "",
				})
				return req
			},
			expectedStatus: http.StatusForbidden,
			expectedBody:   "Invalid XSRF token",
		},
		{
			name:   "POST with case sensitive token comparison",
			method: "POST",
			setupRequest: func() *http.Request {
				req := httptest.NewRequest("POST", "/test", strings.NewReader("data"))
				req.Header.Set("X-XSRF-TOKEN", "Valid-Token")
				req.AddCookie(&http.Cookie{
					Name:  "XSRF-TOKEN",
					Value: "valid-token",
				})
				return req
			},
			expectedStatus: http.StatusForbidden,
			expectedBody:   "Invalid XSRF token",
		},
		{
			name:   "OPTIONS method requires XSRF protection",
			method: "OPTIONS",
			setupRequest: func() *http.Request {
				return httptest.NewRequest("OPTIONS", "/test", nil)
			},
			expectedStatus: http.StatusForbidden,
			expectedBody:   "XSRF token is missing",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := tt.setupRequest()
			w := httptest.NewRecorder()

			middleware.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.expectedBody != "" {
				assert.Contains(t, w.Body.String(), tt.expectedBody)
			}
		})
	}
}

func TestXSRFProtection_HandlerChaining(t *testing.T) {
	executionOrder := []string{}

	// First middleware
	firstMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			executionOrder = append(executionOrder, "first")
			next.ServeHTTP(w, r)
		})
	}

	// Third middleware
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

	// Chain: first -> XSRF -> third -> handler
	handler := firstMiddleware(XSRFProtection(thirdMiddleware(finalHandler)))

	t.Run("successful chain execution", func(t *testing.T) {
		executionOrder = []string{} // Reset

		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, []string{"first", "third", "handler"}, executionOrder)
	})

	t.Run("chain stops at XSRF failure", func(t *testing.T) {
		executionOrder = []string{} // Reset

		req := httptest.NewRequest("POST", "/test", strings.NewReader("data"))
		// No XSRF token provided
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
		// Should only execute first middleware, then XSRF stops the chain
		assert.Equal(t, []string{"first"}, executionOrder)
	})
}

func TestXSRFProtection_SpecialCharactersInToken(t *testing.T) {
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	})

	middleware := XSRFProtection(testHandler)

	specialTokens := []string{
		"token-with-dashes",
		"token_with_underscores",
		"token.with.dots",
		"token123with456numbers",
		"UPPERCASE_TOKEN",
		"MiXeD_CaSe-ToKeN",
		"very-long-token-with-many-characters-and-symbols_123.456",
		"!@#$%^&*()_+-=[]{}|;:,.<>?",
		"unicode-token-café-naïve",
		base64Token(),
	}

	for _, token := range specialTokens {
		t.Run("token_"+sanitizeTestName(token), func(t *testing.T) {
			req := httptest.NewRequest("POST", "/test", strings.NewReader("data"))
			req.Header.Set("X-XSRF-TOKEN", token)
			req.AddCookie(&http.Cookie{
				Name:  "XSRF-TOKEN",
				Value: token,
			})
			w := httptest.NewRecorder()

			middleware.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code)
			assert.Equal(t, "success", w.Body.String())
		})
	}
}

func TestXSRFProtection_EdgeCases(t *testing.T) {
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	})

	middleware := XSRFProtection(testHandler)

	tests := []struct {
		name           string
		setupRequest   func() *http.Request
		expectedStatus int
	}{
		{
			name: "multiple XSRF cookies - first one wins",
			setupRequest: func() *http.Request {
				req := httptest.NewRequest("POST", "/test", strings.NewReader("data"))
				req.Header.Set("X-XSRF-TOKEN", "first-token")
				req.AddCookie(&http.Cookie{Name: "XSRF-TOKEN", Value: "first-token"})
				req.AddCookie(&http.Cookie{Name: "XSRF-TOKEN", Value: "second-token"})
				return req
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "multiple XSRF headers - last one wins",
			setupRequest: func() *http.Request {
				req := httptest.NewRequest("POST", "/test", strings.NewReader("data"))
				req.Header.Add("X-XSRF-TOKEN", "first-header")
				req.Header.Add("X-XSRF-TOKEN", "second-header")
				req.AddCookie(&http.Cookie{Name: "XSRF-TOKEN", Value: "second-header"})
				return req
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "whitespace in token values",
			setupRequest: func() *http.Request {
				req := httptest.NewRequest("POST", "/test", strings.NewReader("data"))
				req.Header.Set("X-XSRF-TOKEN", " token-with-spaces ")
				req.AddCookie(&http.Cookie{Name: "XSRF-TOKEN", Value: " token-with-spaces "})
				return req
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "empty request body with XSRF protection",
			setupRequest: func() *http.Request {
				req := httptest.NewRequest("POST", "/test", nil)
				req.Header.Set("X-XSRF-TOKEN", "valid-token")
				req.AddCookie(&http.Cookie{Name: "XSRF-TOKEN", Value: "valid-token"})
				return req
			},
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := tt.setupRequest()
			w := httptest.NewRecorder()

			middleware.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
		})
	}
}

// Helper functions
func sanitizeTestName(s string) string {
	// Replace special characters with underscores for test names
	result := ""
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			result += string(r)
		} else {
			result += "_"
		}
	}
	if len(result) > 50 {
		result = result[:50]
	}
	return result
}

func base64Token() string {
	return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
}