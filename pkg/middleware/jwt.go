package middleware

import (
	"context"
	"net/http"
	"tofoss/org-go/pkg/utils"
)

func JWTMiddleware(key []byte) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, err := utils.ParseHeaderJWTClaims(r, key)
			if err != nil {
				http.Error(w, "Unautorized", http.StatusUnauthorized)
				return
			}

			userID, username, err := utils.ExtractUserInfo(claims)
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
			}

			ctx := context.WithValue(r.Context(), utils.UserIDKey, userID)
			ctx = context.WithValue(ctx, utils.UsernameKey, username)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
