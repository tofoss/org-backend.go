package middleware

import (
	"context"
	"net/http"
	"strings"
	"tofoss/org-go/pkg/utils"

	"github.com/google/uuid"
)

func JWTMiddleware(secret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var token string

			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				token = strings.TrimPrefix(authHeader, "Bearer ")
			}

			claims, err := utils.ParseJWT(secret, token)
			if err != nil {
				http.Error(w, "Unautorized", http.StatusUnauthorized)
				return
			}

			sub, ok := claims["sub"].(string)

			if !ok {
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}

			userID, err := uuid.Parse(sub)
			if err != nil {
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), "userID", userID)
			next.ServeHTTP(w, r.WithContext(ctx))

		})
	}
}
