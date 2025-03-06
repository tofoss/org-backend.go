package server

import (
	"net/http"
	"os"
	repositories "tofoss/org-go/pkg/db/users"
	"tofoss/org-go/pkg/handlers"
	"tofoss/org-go/pkg/middleware"

	"github.com/go-chi/chi/v5"
	chiMiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
)

func NewServer(pool *pgxpool.Pool) *chi.Mux {
	jwtKey := []byte(os.Getenv("JWT_SECRET"))
	if len(jwtKey) == 0 {
		panic("JWT_SECRET is not set")
	}

	xsrfKey := []byte(os.Getenv("XSRF_SECRET"))
	if len(xsrfKey) == 0 {
		panic("XSRF_SECRET is not set")
	}

	userRepository := repositories.NewUserRepository(pool)

	userHandler := handlers.NewUserHandler(userRepository, jwtKey, xsrfKey)

	public := chi.NewRouter()

	public.Get("/", HomeHandler)

	protected := chi.NewRouter()
	protected.Use(
		middleware.JWTMiddleware(jwtKey),
		middleware.CorsMiddleware,
		chiMiddleware.Logger,
		middleware.XSRFProtection,
	)

	router := chi.NewRouter()
	router.Use(middleware.CorsMiddleware, chiMiddleware.Logger)
	router.Mount("/", public)
	router.Route("/users", func(r chi.Router) {
		r.Post("/register", userHandler.Register)
		r.Post("/login", userHandler.Login)
		r.Get("/status", userHandler.Status)
	})

	return router
}

func HomeHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Hello, world"))
}
