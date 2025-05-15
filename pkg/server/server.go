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
	notebookRepository := repositories.NewNotebookRepository(pool)
	sectionRepository := repositories.NewSectionRepository(pool)
	tagRepsoitory := repositories.NewTagRepository(pool)

	userHandler := handlers.NewUserHandler(userRepository, jwtKey, xsrfKey)
	noteHandler := handlers.NewNoteHandler(noteRepository)
	notebookHandler := handlers.NewNotebookHandler(notebookRepository)
	sectionHandler := handlers.NewSectionHandler(sectionRepository)
	tagHandler := handlers.NewTagHandler(tagRepsoitory)

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
	router.Route("/notebooks", func(r chi.Router) {
		r.Use(middleware.JWTMiddleware(jwtKey), chiMiddleware.Logger)
		r.Get("/{id}", notebookHandler.FetchNotebook)
		r.Post("/", notebookHandler.PostNotebook)
	})
	router.Route("/sections", func(r chi.Router) {
		r.Use(middleware.JWTMiddleware(jwtKey), chiMiddleware.Logger)
		r.Get("/{id}", sectionHandler.FetchSection)
		r.Post("/", sectionHandler.PostSection)
	})
	router.Route("/tags", func(r chi.Router) {
		r.Use(middleware.JWTMiddleware(jwtKey), chiMiddleware.Logger)
		r.Get("/{id}", tagHandler.FetchTag)
		r.Post("/", tagHandler.PostTag)
	})

	return router
}
