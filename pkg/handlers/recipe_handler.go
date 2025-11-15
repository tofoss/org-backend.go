package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
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
	recipeRepo *repositories.RecipeRepository
	jobRepo    *repositories.RecipeJobRepository
	noteRepo   *repositories.NoteRepository
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

		// Use FetchUsersNote to ensure user owns the note (defense in depth)
		note, err := h.noteRepo.FetchUsersNote(r.Context(), *job.NoteID, userID)
		if err == nil {
			response.Note = &note
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// validateURL performs comprehensive URL validation and SSRF protection
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

	hostname := strings.ToLower(parsedURL.Hostname())

	// Block localhost aliases
	if hostname == "localhost" || hostname == "0.0.0.0" {
		return fmt.Errorf("private/localhost URLs are not allowed")
	}

	// Try to parse as IP address
	ip := net.ParseIP(hostname)
	if ip != nil {
		// Direct IP address - check if it's private
		if isPrivateIP(ip) {
			return fmt.Errorf("private IP addresses are not allowed")
		}
	} else {
		// Hostname - resolve it and check all IPs
		ips, err := net.LookupIP(hostname)
		if err != nil {
			return fmt.Errorf("failed to resolve hostname: %w", err)
		}

		for _, resolvedIP := range ips {
			if isPrivateIP(resolvedIP) {
				return fmt.Errorf("hostname resolves to private IP address")
			}
		}
	}

	return nil
}

// isPrivateIP checks if an IP address is private/internal
func isPrivateIP(ip net.IP) bool {
	// Loopback addresses
	if ip.IsLoopback() {
		return true
	}

	// Link-local addresses (169.254.0.0/16 for IPv4, fe80::/10 for IPv6)
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	// Check for private IPv4 ranges
	if ip4 := ip.To4(); ip4 != nil {
		// 10.0.0.0/8
		if ip4[0] == 10 {
			return true
		}
		// 172.16.0.0/12
		if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
			return true
		}
		// 192.168.0.0/16
		if ip4[0] == 192 && ip4[1] == 168 {
			return true
		}
		// 127.0.0.0/8 (loopback, but double-check)
		if ip4[0] == 127 {
			return true
		}
	}

	// Check for private IPv6 ranges
	if ip.To4() == nil {
		// Unique local addresses (fc00::/7)
		if len(ip) >= 2 && (ip[0]&0xfe) == 0xfc {
			return true
		}
	}

	return false
}

