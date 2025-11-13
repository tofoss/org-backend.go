package middleware

import "net/http"

func XSRFProtection(next http.Handler) http.Handler {
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

		cookie, err := r.Cookie("XSRF-TOKEN")
		if err != nil || cookie.Value != header {
			http.Error(w, "Invalid XSRF token", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}
