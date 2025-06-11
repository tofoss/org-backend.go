package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCorsMiddleware(t *testing.T) {
	// Simple test handler
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	})

	// Wrap handler with CORS middleware
	handler := CorsMiddleware(testHandler)

	tests := []struct {
		name            string
		method          string
		origin          string
		requestHeaders  map[string]string
		expectedStatus  int
		expectedHeaders map[string]string
		expectedBody    string
	}{
		{
			name:           "simple GET request from allowed origin",
			method:         "GET",
			origin:         "http://localhost:5173",
			expectedStatus: http.StatusOK,
			expectedHeaders: map[string]string{
				"Access-Control-Allow-Origin":      "http://localhost:5173",
				"Access-Control-Allow-Credentials": "true",
			},
			expectedBody: "success",
		},
		{
			name:           "simple POST request from allowed origin",
			method:         "POST",
			origin:         "http://localhost:5173",
			expectedStatus: http.StatusOK,
			expectedHeaders: map[string]string{
				"Access-Control-Allow-Origin":      "http://localhost:5173",
				"Access-Control-Allow-Credentials": "true",
			},
			expectedBody: "success",
		},
		{
			name:           "preflight OPTIONS request",
			method:         "OPTIONS",
			origin:         "http://localhost:5173",
			requestHeaders: map[string]string{
				"Access-Control-Request-Method": "POST",
			},
			expectedStatus: http.StatusNoContent,
			expectedHeaders: map[string]string{
				"Access-Control-Allow-Origin":      "http://localhost:5173",
				"Access-Control-Allow-Methods":     "GET, POST, PUT, DELETE, OPTIONS",
				"Access-Control-Allow-Credentials": "true",
				"Access-Control-Max-Age":           "3600",
			},
			expectedBody: "",
		},
		{
			name:           "preflight with custom headers",
			method:         "OPTIONS",
			origin:         "http://localhost:5173",
			requestHeaders: map[string]string{
				"Access-Control-Request-Method":  "PUT",
				"Access-Control-Request-Headers": "Authorization, Content-Type",
			},
			expectedStatus: http.StatusNoContent,
			expectedHeaders: map[string]string{
				"Access-Control-Allow-Origin":      "http://localhost:5173",
				"Access-Control-Allow-Methods":     "GET, POST, PUT, DELETE, OPTIONS",
				"Access-Control-Allow-Headers":     "Authorization, Content-Type, X-Xsrf-Token",
				"Access-Control-Allow-Credentials": "true",
			},
			expectedBody: "",
		},
		{
			name:           "request from disallowed origin",
			method:         "GET",
			origin:         "http://malicious-site.com",
			expectedStatus: http.StatusOK,
			expectedHeaders: map[string]string{
				"Access-Control-Allow-Origin": "", // Should not be set for disallowed origin
			},
			expectedBody: "success",
		},
		{
			name:           "request without origin header",
			method:         "GET",
			expectedStatus: http.StatusOK,
			expectedBody:   "success",
		},
		{
			name:           "DELETE request from allowed origin",
			method:         "DELETE",
			origin:         "http://localhost:5173",
			expectedStatus: http.StatusOK,
			expectedHeaders: map[string]string{
				"Access-Control-Allow-Origin":      "http://localhost:5173",
				"Access-Control-Allow-Credentials": "true",
			},
			expectedBody: "success",
		},
		{
			name:           "PUT request from allowed origin",
			method:         "PUT",
			origin:         "http://localhost:5173",
			expectedStatus: http.StatusOK,
			expectedHeaders: map[string]string{
				"Access-Control-Allow-Origin":      "http://localhost:5173",
				"Access-Control-Allow-Credentials": "true",
			},
			expectedBody: "success",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/test", nil)
			
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			
			for key, value := range tt.requestHeaders {
				req.Header.Set(key, value)
			}
			
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			
			for headerName, expectedValue := range tt.expectedHeaders {
				if expectedValue == "" {
					// Check that header is not set
					assert.Empty(t, w.Header().Get(headerName), 
						"Header %s should not be set", headerName)
				} else {
					actualValue := w.Header().Get(headerName)
					assert.Contains(t, actualValue, expectedValue,
						"Header %s should contain %s, got %s", headerName, expectedValue, actualValue)
				}
			}
			
			if tt.expectedBody != "" {
				assert.Equal(t, tt.expectedBody, w.Body.String())
			}
		})
	}
}

func TestCorsOptions(t *testing.T) {
	// Test that the CORS options are configured correctly
	assert.Equal(t, []string{"http://localhost:5173"}, corsOptions.AllowedOrigins)
	assert.Equal(t, []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}, corsOptions.AllowedMethods)
	assert.Equal(t, []string{"Authorization", "Content-Type", "X-XSRF-TOKEN"}, corsOptions.AllowedHeaders)
	assert.True(t, corsOptions.AllowCredentials)
	assert.Equal(t, 3600, corsOptions.MaxAge)
}

func TestCorsMiddleware_HandlerChaining(t *testing.T) {
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

	// Chain: first -> CORS -> third -> handler
	handler := firstMiddleware(CorsMiddleware(thirdMiddleware(finalHandler)))

	t.Run("normal request execution chain", func(t *testing.T) {
		executionOrder = []string{} // Reset

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", "http://localhost:5173")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, []string{"first", "third", "handler"}, executionOrder)
	})

	t.Run("preflight request stops at CORS", func(t *testing.T) {
		executionOrder = []string{} // Reset

		req := httptest.NewRequest("OPTIONS", "/test", nil)
		req.Header.Set("Origin", "http://localhost:5173")
		req.Header.Set("Access-Control-Request-Method", "POST")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNoContent, w.Code)
		// Preflight requests should be handled by CORS middleware and not continue
		assert.Equal(t, []string{"first"}, executionOrder)
	})
}

func TestCorsMiddleware_SecurityHeaders(t *testing.T) {
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := CorsMiddleware(testHandler)

	t.Run("credentials allowed for trusted origin", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", "http://localhost:5173")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.Equal(t, "true", w.Header().Get("Access-Control-Allow-Credentials"))
	})

	t.Run("max age set for preflight cache", func(t *testing.T) {
		req := httptest.NewRequest("OPTIONS", "/test", nil)
		req.Header.Set("Origin", "http://localhost:5173")
		req.Header.Set("Access-Control-Request-Method", "POST")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.Equal(t, "3600", w.Header().Get("Access-Control-Max-Age"))
	})
}

func TestCorsMiddleware_AllowedHeaders(t *testing.T) {
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := CorsMiddleware(testHandler)

	allowedHeaders := []string{"Authorization", "Content-Type", "X-XSRF-TOKEN"}

	for _, header := range allowedHeaders {
		t.Run("header_"+header, func(t *testing.T) {
			req := httptest.NewRequest("OPTIONS", "/test", nil)
			req.Header.Set("Origin", "http://localhost:5173")
			req.Header.Set("Access-Control-Request-Method", "POST")
			req.Header.Set("Access-Control-Request-Headers", header)
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			assert.Equal(t, http.StatusNoContent, w.Code)
			allowedHeadersResponse := w.Header().Get("Access-Control-Allow-Headers")
			assert.Contains(t, allowedHeadersResponse, header)
		})
	}
}

func TestCorsMiddleware_AllowedMethods(t *testing.T) {
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := CorsMiddleware(testHandler)

	allowedMethods := []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}

	for _, method := range allowedMethods {
		t.Run("method_"+method, func(t *testing.T) {
			req := httptest.NewRequest("OPTIONS", "/test", nil)
			req.Header.Set("Origin", "http://localhost:5173")
			req.Header.Set("Access-Control-Request-Method", method)
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			assert.Equal(t, http.StatusNoContent, w.Code)
			allowedMethodsResponse := w.Header().Get("Access-Control-Allow-Methods")
			assert.Contains(t, allowedMethodsResponse, method)
		})
	}
}