package server

import (
	"net/http"
	"tofoss/org-go/pkg/middleware"
	"tofoss/org-go/pkg/utils"

	"github.com/go-chi/chi/v5"
	chiMiddleware "github.com/go-chi/chi/v5/middleware"
)

func NewServer() *chi.Mux {
	secretKey, err := utils.GenerateHS512Key()

	if err != nil {
		panic(err)
	}

	public := chi.NewRouter()
	public.Use(middleware.CorsMiddleware)
	public.Use(chiMiddleware.Logger)

	public.Get("/", HomeHandler)

	protected := chi.NewRouter()
	protected.Use(middleware.JWTMiddleware(secretKey), middleware.CorsMiddleware, chiMiddleware.Logger)

	return public
}

func HomeHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Hello, world"))
}
