package server

import (
	"context"
	"log"
	"os"
	"tofoss/org-go/pkg/db/repositories"
	"tofoss/org-go/pkg/handlers"
	"tofoss/org-go/pkg/middleware"
	"tofoss/org-go/pkg/services"

	"github.com/go-chi/chi/v5"
	chiMiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Server holds the router and background services
type Server struct {
	Router   *chi.Mux
	jobQueue *services.RecipeJobQueue
}

// NewServer creates a new server with all routes and background services
func NewServer(ctx context.Context, pool *pgxpool.Pool) (*Server, error) {
	jwtKey := []byte(os.Getenv("JWT_SECRET"))
	if len(jwtKey) == 0 {
		panic("JWT_SECRET is not set")
	}

	xsrfKey := []byte(os.Getenv("XSRF_SECRET"))
	if len(xsrfKey) == 0 {
		panic("XSRF_SECRET is not set")
	}

	// Initialize repositories
	userRepository := repositories.NewUserRepository(pool)
	noteRepository := repositories.NewNoteRepository(pool)
	notebookRepository := repositories.NewNotebookRepository(pool)
	sectionRepository := repositories.NewSectionRepository(pool)
	tagRepository := repositories.NewTagRepository(pool)
	recipeRepository := repositories.NewRecipeRepository(pool)
	recipeJobRepository := repositories.NewRecipeJobRepository(pool)
	recipeCacheRepository := repositories.NewRecipeURLCacheRepository(pool)

	// Initialize services
	recipeProcessor, err := services.NewRecipeProcessor(
		recipeRepository,
		recipeJobRepository,
		noteRepository,
		recipeCacheRepository,
	)
	if err != nil {
		return nil, err
	}

	jobQueue := services.NewRecipeJobQueue(recipeJobRepository, recipeProcessor)

	// Initialize handlers
	userHandler := handlers.NewUserHandler(userRepository, jwtKey, xsrfKey)
	noteHandler := handlers.NewNoteHandler(noteRepository)
	notebookHandler := handlers.NewNotebookHandler(notebookRepository, noteRepository)
	sectionHandler := handlers.NewSectionHandler(sectionRepository, notebookRepository)
	tagHandler := handlers.NewTagHandler(tagRepository)
	recipeHandler := handlers.NewRecipeHandler(recipeRepository, recipeJobRepository, noteRepository)

	// Setup routes
	router := chi.NewRouter()
	router.Use(middleware.CorsMiddleware, chiMiddleware.Logger)
	
	router.Route("/users", func(r chi.Router) {
		r.Post("/register", userHandler.Register)
		r.Post("/login", userHandler.Login)
		r.Get("/status", userHandler.Status)
	})
	
	router.Route("/notes", func(r chi.Router) {
		r.Use(middleware.JWTMiddleware(jwtKey), middleware.XSRFProtection, chiMiddleware.Logger)
		r.Get("/", noteHandler.FetchUsersNotes)
		r.Get("/search", noteHandler.SearchNotes)
		r.Get("/{id}", noteHandler.FetchNote)
		r.Post("/", noteHandler.PostNote)
		r.Get("/{id}/tags", noteHandler.GetNoteTags)
		r.Put("/{id}/tags", noteHandler.AssignNoteTags)
		r.Delete("/{id}/tags/{tagId}", noteHandler.RemoveNoteTag)
		r.Get("/{id}/notebooks", noteHandler.GetNoteNotebooks)
		r.Put("/{noteId}/notebooks/{notebookId}/section", sectionHandler.AssignNoteToSection)
		r.Put("/{noteId}/notebooks/{notebookId}/position", sectionHandler.UpdateNotePosition)
	})
	
	router.Route("/notebooks", func(r chi.Router) {
		r.Use(middleware.JWTMiddleware(jwtKey), middleware.XSRFProtection, chiMiddleware.Logger)
		r.Get("/", notebookHandler.FetchUserNotebooks)
		r.Get("/{id}", notebookHandler.FetchNotebook)
		r.Post("/", notebookHandler.PostNotebook)
		r.Delete("/{id}", notebookHandler.DeleteNotebook)
		r.Get("/{id}/notes", notebookHandler.FetchNotebookNotes)
		r.Put("/{id}/notes/{noteId}", notebookHandler.AddNoteToNotebook)
		r.Delete("/{id}/notes/{noteId}", notebookHandler.RemoveNoteFromNotebook)
		r.Get("/{id}/sections", sectionHandler.ListNotebookSections)
		r.Get("/{id}/unsectioned", sectionHandler.GetUnsectionedNotes)
	})

	router.Route("/sections", func(r chi.Router) {
		r.Use(middleware.JWTMiddleware(jwtKey), middleware.XSRFProtection, chiMiddleware.Logger)
		r.Get("/{id}", sectionHandler.FetchSection)
		r.Post("/", sectionHandler.PostSection)
		r.Delete("/{id}", sectionHandler.DeleteSection)
		r.Put("/{id}/position", sectionHandler.UpdateSectionPosition)
		r.Patch("/{id}", sectionHandler.UpdateSectionName)
		r.Get("/{id}/notes", sectionHandler.GetSectionNotes)
	})

	router.Route("/tags", func(r chi.Router) {
		r.Use(middleware.JWTMiddleware(jwtKey), middleware.XSRFProtection, chiMiddleware.Logger)
		r.Get("/{id}", tagHandler.FetchTag)
		r.Post("/", tagHandler.PostTag)
		r.Get("/", tagHandler.FetchAll)
	})

	router.Route("/recipes", func(r chi.Router) {
		r.Use(middleware.JWTMiddleware(jwtKey), middleware.XSRFProtection, chiMiddleware.Logger)
		r.Post("/", recipeHandler.CreateRecipeFromURL)
		r.Get("/jobs/{id}", recipeHandler.GetRecipeJobStatus)
	})

	return &Server{
		Router:   router,
		jobQueue: jobQueue,
	}, nil
}

// Start starts the server's background services
func (s *Server) Start(ctx context.Context) {
	log.Printf("Starting server background services")
	s.jobQueue.Start(ctx)
}

// Stop gracefully stops the server's background services
func (s *Server) Stop() {
	log.Printf("Stopping server background services")
	s.jobQueue.Stop()
}
