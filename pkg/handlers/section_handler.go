package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"tofoss/org-go/pkg/db/repositories"
	"tofoss/org-go/pkg/handlers/errors"
	"tofoss/org-go/pkg/handlers/requests"
	"tofoss/org-go/pkg/models"
	"tofoss/org-go/pkg/utils"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type SectionHandler struct {
	repo         repositories.SectionRepositoryInterface
	notebookRepo repositories.NotebookRepositoryInterface
}

func NewSectionHandler(
	repo repositories.SectionRepositoryInterface,
	notebookRepo repositories.NotebookRepositoryInterface,
) SectionHandler {
	return SectionHandler{repo, notebookRepo}
}

// verifyOwnership checks if the user owns the notebook that contains the section
func (h *SectionHandler) verifyOwnership(
	ctx context.Context,
	userID uuid.UUID,
	sectionID uuid.UUID,
) error {
	// Get section to find its notebook
	section, err := h.repo.FetchSection(ctx, sectionID)
	if err != nil {
		if err == pgx.ErrNoRows {
			return fmt.Errorf("section not found")
		}
		return err
	}

	// Get notebook and verify ownership
	notebook, err := h.notebookRepo.FetchNotebook(ctx, section.NotebookID)
	if err != nil {
		if err == pgx.ErrNoRows {
			return fmt.Errorf("notebook not found")
		}
		return err
	}

	if notebook.UserID != userID {
		return fmt.Errorf("unauthorized: user does not own this notebook")
	}

	return nil
}

// verifyNotebookOwnership checks if the user owns the specified notebook
func (h *SectionHandler) verifyNotebookOwnership(
	ctx context.Context,
	userID uuid.UUID,
	notebookID uuid.UUID,
) error {
	notebook, err := h.notebookRepo.FetchNotebook(ctx, notebookID)
	if err != nil {
		if err == pgx.ErrNoRows {
			return fmt.Errorf("notebook not found")
		}
		return err
	}

	if notebook.UserID != userID {
		return fmt.Errorf("unauthorized: user does not own this notebook")
	}

	return nil
}

// FetchSection retrieves a single section by ID
func (h *SectionHandler) FetchSection(w http.ResponseWriter, r *http.Request) {
	userID, _, err := utils.UserContext(r)
	if err != nil {
		log.Printf("user context error: %v", err)
		errors.InternalServerError(w)
		return
	}

	sectionID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		log.Printf("invalid section ID: %v", err)
		errors.BadRequest(w)
		return
	}

	// Verify ownership
	if err := h.verifyOwnership(r.Context(), userID, sectionID); err != nil {
		log.Printf("ownership verification failed: %v", err)
		errors.Unauthenticated(w)
		return
	}

	section, err := h.repo.FetchSection(r.Context(), sectionID)
	if err != nil {
		log.Printf("failed to fetch section: %v", err)
		errors.InternalServerError(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(section)
}

// ListNotebookSections retrieves all sections in a notebook (ordered by position)
func (h *SectionHandler) ListNotebookSections(w http.ResponseWriter, r *http.Request) {
	userID, _, err := utils.UserContext(r)
	if err != nil {
		log.Printf("user context error: %v", err)
		errors.InternalServerError(w)
		return
	}

	notebookID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		log.Printf("invalid notebook ID: %v", err)
		errors.BadRequest(w)
		return
	}

	// Verify user owns notebook
	if err := h.verifyNotebookOwnership(r.Context(), userID, notebookID); err != nil {
		log.Printf("notebook ownership verification failed: %v", err)
		errors.Unauthenticated(w)
		return
	}

	sections, err := h.repo.FetchNotebookSections(r.Context(), notebookID)
	if err != nil {
		log.Printf("failed to fetch notebook sections: %v", err)
		errors.InternalServerError(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(sections)
}

// PostSection creates or updates a section
func (h *SectionHandler) PostSection(w http.ResponseWriter, r *http.Request) {
	userID, _, err := utils.UserContext(r)
	if err != nil {
		log.Printf("user context error: %v", err)
		errors.InternalServerError(w)
		return
	}

	var section models.Section
	if err := json.NewDecoder(r.Body).Decode(&section); err != nil {
		log.Printf("failed to decode request body: %v", err)
		errors.BadRequest(w)
		return
	}

	// Verify user owns the notebook
	if err := h.verifyNotebookOwnership(r.Context(), userID, section.NotebookID); err != nil {
		log.Printf("notebook ownership verification failed: %v", err)
		errors.Unauthenticated(w)
		return
	}

	// If updating existing section, verify ownership of section too
	if section.ID != uuid.Nil {
		if err := h.verifyOwnership(r.Context(), userID, section.ID); err != nil {
			log.Printf("section ownership verification failed: %v", err)
			errors.Unauthenticated(w)
			return
		}
	}

	saved, err := h.repo.Upsert(r.Context(), section)
	if err != nil {
		log.Printf("failed to upsert section: %v", err)
		errors.InternalServerError(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(saved)
}

// DeleteSection deletes a section (notes become unsectioned)
func (h *SectionHandler) DeleteSection(w http.ResponseWriter, r *http.Request) {
	userID, _, err := utils.UserContext(r)
	if err != nil {
		log.Printf("user context error: %v", err)
		errors.InternalServerError(w)
		return
	}

	sectionID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		log.Printf("invalid section ID: %v", err)
		errors.BadRequest(w)
		return
	}

	// Verify ownership
	if err := h.verifyOwnership(r.Context(), userID, sectionID); err != nil {
		log.Printf("ownership verification failed: %v", err)
		errors.Unauthenticated(w)
		return
	}

	if err := h.repo.DeleteSection(r.Context(), sectionID); err != nil {
		log.Printf("failed to delete section: %v", err)
		errors.InternalServerError(w)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// UpdateSectionPosition updates the position of a section for reordering
func (h *SectionHandler) UpdateSectionPosition(w http.ResponseWriter, r *http.Request) {
	userID, _, err := utils.UserContext(r)
	if err != nil {
		log.Printf("user context error: %v", err)
		errors.InternalServerError(w)
		return
	}

	sectionID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		log.Printf("invalid section ID: %v", err)
		errors.BadRequest(w)
		return
	}

	// Parse new position from request body
	var req struct {
		Position int `json:"position"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("failed to decode request body: %v", err)
		errors.BadRequest(w)
		return
	}

	// Verify ownership
	if err := h.verifyOwnership(r.Context(), userID, sectionID); err != nil {
		log.Printf("ownership verification failed: %v", err)
		errors.Unauthenticated(w)
		return
	}

	if err := h.repo.UpdateSectionPosition(r.Context(), sectionID, req.Position); err != nil {
		log.Printf("failed to update section position: %v", err)
		errors.InternalServerError(w)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// UpdateSectionName updates the name of a section
func (h *SectionHandler) UpdateSectionName(w http.ResponseWriter, r *http.Request) {
	userID, _, err := utils.UserContext(r)
	if err != nil {
		log.Printf("user context error: %v", err)
		errors.InternalServerError(w)
		return
	}

	sectionID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		log.Printf("invalid section ID: %v", err)
		errors.BadRequest(w)
		return
	}

	// Parse new name from request body
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("failed to decode request body: %v", err)
		errors.BadRequest(w)
		return
	}

	if req.Name == "" {
		log.Printf("section name cannot be empty")
		errors.BadRequest(w)
		return
	}

	// Verify ownership
	if err := h.verifyOwnership(r.Context(), userID, sectionID); err != nil {
		log.Printf("ownership verification failed: %v", err)
		errors.Unauthenticated(w)
		return
	}

	if err := h.repo.UpdateSectionName(r.Context(), sectionID, req.Name); err != nil {
		log.Printf("failed to update section name: %v", err)
		errors.InternalServerError(w)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// UpdateNotePosition updates the position of a note within its section for reordering
func (h *SectionHandler) UpdateNotePosition(w http.ResponseWriter, r *http.Request) {
	userID, _, err := utils.UserContext(r)
	if err != nil {
		log.Printf("user context error: %v", err)
		errors.InternalServerError(w)
		return
	}

	noteID, err := uuid.Parse(chi.URLParam(r, "noteId"))
	if err != nil {
		log.Printf("invalid note ID: %v", err)
		errors.BadRequest(w)
		return
	}

	notebookID, err := uuid.Parse(chi.URLParam(r, "notebookId"))
	if err != nil {
		log.Printf("invalid notebook ID: %v", err)
		errors.BadRequest(w)
		return
	}

	// Parse new position from request body
	var req struct {
		Position int `json:"position"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("failed to decode request body: %v", err)
		errors.BadRequest(w)
		return
	}

	// Verify user owns notebook
	if err := h.verifyNotebookOwnership(r.Context(), userID, notebookID); err != nil {
		log.Printf("notebook ownership verification failed: %v", err)
		errors.Unauthenticated(w)
		return
	}

	if err := h.repo.UpdateNotePosition(r.Context(), noteID, notebookID, req.Position); err != nil {
		log.Printf("failed to update note position: %v", err)
		errors.InternalServerError(w)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// AssignNoteToSection assigns a note to a section within a notebook
func (h *SectionHandler) AssignNoteToSection(w http.ResponseWriter, r *http.Request) {
	userID, _, err := utils.UserContext(r)
	if err != nil {
		log.Printf("user context error: %v", err)
		errors.InternalServerError(w)
		return
	}

	noteID, err := uuid.Parse(chi.URLParam(r, "noteId"))
	if err != nil {
		log.Printf("invalid note ID: %v", err)
		errors.BadRequest(w)
		return
	}

	notebookID, err := uuid.Parse(chi.URLParam(r, "notebookId"))
	if err != nil {
		log.Printf("invalid notebook ID: %v", err)
		errors.BadRequest(w)
		return
	}

	// Parse section ID from request body (can be null to unsection)
	var req requests.AssignToSection
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("failed to decode request body: %v", err)
		errors.BadRequest(w)
		return
	}

	// Verify user owns notebook
	if err := h.verifyNotebookOwnership(r.Context(), userID, notebookID); err != nil {
		log.Printf("notebook ownership verification failed: %v", err)
		errors.Unauthenticated(w)
		return
	}

	// If assigning to a section (not unsectioning), verify section ownership
	if req.SectionID != nil {
		if err := h.verifyOwnership(r.Context(), userID, *req.SectionID); err != nil {
			log.Printf("section ownership verification failed: %v", err)
			errors.Unauthenticated(w)
			return
		}
	}

	if err := h.repo.AssignNoteToSection(r.Context(), noteID, notebookID, req.SectionID); err != nil {
		log.Printf("failed to assign note to section: %v", err)
		errors.InternalServerError(w)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GetSectionNotes retrieves all notes in a section
func (h *SectionHandler) GetSectionNotes(w http.ResponseWriter, r *http.Request) {
	userID, _, err := utils.UserContext(r)
	if err != nil {
		log.Printf("user context error: %v", err)
		errors.InternalServerError(w)
		return
	}

	sectionID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		log.Printf("invalid section ID: %v", err)
		errors.BadRequest(w)
		return
	}

	// Verify ownership
	if err := h.verifyOwnership(r.Context(), userID, sectionID); err != nil {
		log.Printf("ownership verification failed: %v", err)
		errors.Unauthenticated(w)
		return
	}

	notes, err := h.repo.FetchSectionNotes(r.Context(), sectionID)
	if err != nil {
		log.Printf("failed to fetch section notes: %v", err)
		errors.InternalServerError(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(notes)
}

// GetUnsectionedNotes retrieves all notes in a notebook that don't belong to any section
func (h *SectionHandler) GetUnsectionedNotes(w http.ResponseWriter, r *http.Request) {
	userID, _, err := utils.UserContext(r)
	if err != nil {
		log.Printf("user context error: %v", err)
		errors.InternalServerError(w)
		return
	}

	notebookID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		log.Printf("invalid notebook ID: %v", err)
		errors.BadRequest(w)
		return
	}

	// Verify user owns notebook
	if err := h.verifyNotebookOwnership(r.Context(), userID, notebookID); err != nil {
		log.Printf("notebook ownership verification failed: %v", err)
		errors.Unauthenticated(w)
		return
	}

	notes, err := h.repo.FetchUnsectionedNotes(r.Context(), notebookID)
	if err != nil {
		log.Printf("failed to fetch unsectioned notes: %v", err)
		errors.InternalServerError(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(notes)
}
