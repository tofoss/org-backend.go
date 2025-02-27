package server

import (
	"net/http"
	repositories "tofoss/org-go/pkg/db/users"
	"tofoss/org-go/pkg/handlers"
	"tofoss/org-go/pkg/middleware"
	"tofoss/org-go/pkg/utils"

	"github.com/go-chi/chi/v5"
	chiMiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
)

func NewServer(pool *pgxpool.Pool) *chi.Mux {
	jwtKey, err := utils.GenerateHS512Key()

	if err != nil {
		panic(err)
	}

	xsrfKey, err := utils.GenerateHS512Key()

	if err != nil {
		panic(err)
	}

	userRepository := repositories.NewUserRepository(pool)

	userHandler := handlers.NewUserHandler(userRepository, jwtKey, xsrfKey)

	public := chi.NewRouter()
	public.Use(middleware.CorsMiddleware)
	public.Use(chiMiddleware.Logger)

	public.Get("/", HomeHandler)
	public.Post("/users/register", userHandler.Register)

	protected := chi.NewRouter()
	protected.Use(middleware.JWTMiddleware(jwtKey), middleware.CorsMiddleware, chiMiddleware.Logger, middleware.XSRFProtection)

	return public
}

func HomeHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Hello, world"))
}
