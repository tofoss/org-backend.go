package middleware

import (
	"net/http"

	"tofoss/org-go/pkg/utils"

	"golang.org/x/net/xsrftoken"
)

func XSRFProtection(xsrfKey []byte) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet || r.Method == http.MethodHead {
				next.ServeHTTP(w, r)
				return
			}

			header := r.Header.Get("X-XSRF-TOKEN")
			if header == "" {
				http.Error(w, "XSRF token is missing", http.StatusForbidden)
				return
			}

			// Extract user ID from context (set by JWT middleware)
			userID, err := utils.GetUserID(r.Context())
			if err != nil {
				http.Error(w, "User not authenticated", http.StatusUnauthorized)
				return
			}

			// Use cryptographic validation instead of string comparison
			if !xsrftoken.Valid(header, string(xsrfKey), userID.String(), "") {
				http.Error(w, "Invalid XSRF token", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
