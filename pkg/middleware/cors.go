package middleware

import (
	"github.com/go-chi/cors"
)

var corsOptions = cors.Options{
	AllowedOrigins:   []string{"http://localhost:5173"},
	AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
	AllowedHeaders:   []string{"Authorization", "Content-Type", "X-XSRF-TOKEN"},
	AllowCredentials: true,
	MaxAge:           3600,
}

var CorsMiddleware = cors.Handler(corsOptions)
