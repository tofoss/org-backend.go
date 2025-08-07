package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
	"tofoss/org-go/pkg/db/repositories"
	"tofoss/org-go/pkg/handlers/errors"
	"tofoss/org-go/pkg/handlers/requests"
	"tofoss/org-go/pkg/handlers/responses"
	"tofoss/org-go/pkg/models"
	"tofoss/org-go/pkg/utils"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type RecipeHandler struct {
	recipeRepo    *repositories.RecipeRepository
	jobRepo       *repositories.RecipeJobRepository
	noteRepo      *repositories.NoteRepository
}

func NewRecipeHandler(
	recipeRepo *repositories.RecipeRepository,
	jobRepo *repositories.RecipeJobRepository,
	noteRepo *repositories.NoteRepository,
) RecipeHandler {
	return RecipeHandler{recipeRepo, jobRepo, noteRepo}
}

func (h *RecipeHandler) CreateRecipeFromURL(w http.ResponseWriter, r *http.Request) {
	userID, _, err := utils.UserContext(r)
	if err != nil {
		log.Printf("unable to create recipe, user not logged in: %v", err)
		errors.InternalServerError(w)
		return
	}

	var req requests.CreateRecipe
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		log.Printf("could not decode create recipe request: %v", err)
		errors.BadRequest(w)
		return
	}

	// Basic URL validation
	if err := h.validateURL(req.URL); err != nil {
		log.Printf("invalid URL provided: %s, error: %v", req.URL, err)
		errors.BadRequest(w)
		return
	}

	// Create job
	now := time.Now()
	job := models.RecipeJob{
		ID:        uuid.New(),
		UserID:    userID,
		URL:       req.URL,
		Status:    "pending",
		CreatedAt: now,
	}

	createdJob, err := h.jobRepo.Create(r.Context(), job)
	if err != nil {
		log.Printf("failed to create recipe job: %v", err)
		errors.InternalServerError(w)
		return
	}

	response := responses.CreateRecipeResponse{
		JobID: createdJob.ID.String(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(response)
}

func (h *RecipeHandler) GetRecipeJobStatus(w http.ResponseWriter, r *http.Request) {
	userID, _, err := utils.UserContext(r)
	if err != nil {
		log.Printf("unable to get recipe job status, user not logged in: %v", err)
		errors.InternalServerError(w)
		return
	}

	jobIDStr := chi.URLParam(r, "id")
	jobID, err := uuid.Parse(jobIDStr)
	if err != nil {
		log.Printf("invalid job ID: %s", jobIDStr)
		errors.BadRequest(w)
		return
	}

	job, err := h.jobRepo.FetchByID(r.Context(), jobID)
	if err != nil {
		if err == pgx.ErrNoRows {
			log.Printf("job %s not found", jobID)
			errors.NotFound(w, "job not found")
			return
		}
		log.Printf("failed to fetch job %s: %v", jobID, err)
		errors.InternalServerError(w)
		return
	}

	// Verify user owns this job
	if job.UserID != userID {
		log.Printf("user %s does not own job %s", userID, jobID)
		errors.Unauthenticated(w)
		return
	}

	response := responses.RecipeJobResponse{
		Job: job,
	}

	// If job is completed, fetch the recipe and note
	if job.Status == "completed" && job.RecipeID != nil && job.NoteID != nil {
		recipe, err := h.recipeRepo.FetchByID(r.Context(), *job.RecipeID)
		if err == nil {
			response.Recipe = &recipe
		}

		note, err := h.noteRepo.FetchNote(r.Context(), *job.NoteID)
		if err == nil {
			response.Note = &note
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// validateURL performs basic URL validation and security checks
func (h *RecipeHandler) validateURL(urlStr string) error {
	// Parse URL
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return err
	}

	// Require http/https scheme
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return fmt.Errorf("URL must use http or https scheme")
	}

	// Basic security: block localhost and private IP ranges
	hostname := strings.ToLower(parsedURL.Hostname())
	if hostname == "localhost" || 
		strings.HasPrefix(hostname, "127.") ||
		strings.HasPrefix(hostname, "192.168.") ||
		strings.HasPrefix(hostname, "10.") ||
		strings.Contains(hostname, "169.254.") {
		return fmt.Errorf("private/localhost URLs are not allowed")
	}

	return nil
}