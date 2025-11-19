package middleware

import (
	"os"
	"strings"

	"github.com/go-chi/cors"
)

func getAllowedOrigins() []string {
	origins := os.Getenv("CORS_ALLOWED_ORIGINS")
	if origins == "" {
		return []string{"http://localhost:5173"}
	}
	return strings.Split(origins, ",")
}

var corsOptions = cors.Options{
	AllowedOrigins:   getAllowedOrigins(),
	AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
	AllowedHeaders:   []string{"Authorization", "Content-Type", "X-XSRF-TOKEN"},
	AllowCredentials: true,
	MaxAge:           3600,
}

var CorsMiddleware = cors.Handler(corsOptions)
