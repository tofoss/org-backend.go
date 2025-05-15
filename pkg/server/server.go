package server

import (
	"os"
	"tofoss/org-go/pkg/db/repositories"
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
	noteRepository := repositories.NewNoteRepository(pool)

	userHandler := handlers.NewUserHandler(userRepository, jwtKey, xsrfKey)
	noteHandler := handlers.NewNoteHandler(noteRepository)

	router := chi.NewRouter()
	router.Use(middleware.CorsMiddleware, chiMiddleware.Logger)
	router.Route("/users", func(r chi.Router) {
		r.Post("/register", userHandler.Register)
		r.Post("/login", userHandler.Login)
		r.Get("/status", userHandler.Status)
	})
	router.Route("/notes", func(r chi.Router) {
		r.Use(middleware.JWTMiddleware(jwtKey), chiMiddleware.Logger)
		r.Get("/", noteHandler.FetchUsersNotes)
		r.Get("/{id}", noteHandler.FetchNote)
		r.Post("/", noteHandler.PostNote)
	})

	return router
}
