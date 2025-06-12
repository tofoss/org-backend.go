package handlers

import (
	"encoding/json"
	"net/http"
	"time"
	"tofoss/org-go/pkg/db/repositories"
	"tofoss/org-go/pkg/handlers/errors"
	"tofoss/org-go/pkg/models"
	"tofoss/org-go/pkg/utils"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type NotebookHandler struct {
	repo     *repositories.NotebookRepository
	noteRepo *repositories.NoteRepository
}

func NewNotebookHandler(repo *repositories.NotebookRepository, noteRepo *repositories.NoteRepository) NotebookHandler {
	return NotebookHandler{repo: repo, noteRepo: noteRepo}
}

func (h *NotebookHandler) FetchNotebook(w http.ResponseWriter, r *http.Request) {
	userID, _, err := utils.UserContext(r)
	if err != nil {
		errors.InternalServerError(w)
		return
	}

	notebookID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		errors.BadRequest(w)
		return
	}

	notebook, err := h.repo.FetchNotebook(r.Context(), notebookID)
	if err != nil {
		if err == pgx.ErrNoRows {
			errors.NotFound(w, "notebook not found")
			return
		}
		errors.InternalServerError(w)
		return
	}

	if notebook.UserID != userID {
		errors.Unauthenticated(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(notebook)
}

func (h *NotebookHandler) PostNotebook(w http.ResponseWriter, r *http.Request) {
	var req models.Notebook
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errors.BadRequest(w)
		return
	}

	userID, _, err := utils.UserContext(r)
	if err != nil {
		errors.InternalServerError(w)
		return
	}

	now := time.Now()
	if req.ID == uuid.Nil {
		// Creating new notebook
		req.ID = uuid.New()
		req.CreatedAt = now
		req.UserID = userID
	} else {
		// Updating existing notebook - verify ownership first
		existing, err := h.repo.FetchNotebook(r.Context(), req.ID)
		if err != nil {
			if err == pgx.ErrNoRows {
				errors.NotFound(w, "notebook not found")
				return
			}
			errors.InternalServerError(w)
			return
		}

		if existing.UserID != userID {
			errors.Unauthenticated(w)
			return
		}

		// Preserve original creation data and user ownership
		req.CreatedAt = existing.CreatedAt
		req.UserID = existing.UserID
	}
	req.UpdatedAt = now

	notebook, err := h.repo.Upsert(r.Context(), req)
	if err != nil {
		errors.InternalServerError(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(notebook)
}

func (h *NotebookHandler) FetchUserNotebooks(w http.ResponseWriter, r *http.Request) {
	userID, _, err := utils.UserContext(r)
	if err != nil {
		errors.InternalServerError(w)
		return
	}

	notebooks, err := h.repo.FetchUserNotebooks(r.Context(), userID)
	if err != nil {
		errors.InternalServerError(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(notebooks)
}

func (h *NotebookHandler) DeleteNotebook(w http.ResponseWriter, r *http.Request) {
	userID, _, err := utils.UserContext(r)
	if err != nil {
		errors.InternalServerError(w)
		return
	}

	notebookID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		errors.BadRequest(w)
		return
	}

	notebook, err := h.repo.FetchNotebook(r.Context(), notebookID)
	if err != nil {
		if err == pgx.ErrNoRows {
			errors.NotFound(w, "notebook not found")
			return
		}
		errors.InternalServerError(w)
		return
	}

	if notebook.UserID != userID {
		errors.Unauthenticated(w)
		return
	}

	err = h.repo.Delete(r.Context(), notebookID)
	if err != nil {
		errors.InternalServerError(w)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *NotebookHandler) FetchNotebookNotes(w http.ResponseWriter, r *http.Request) {
	userID, _, err := utils.UserContext(r)
	if err != nil {
		errors.InternalServerError(w)
		return
	}

	notebookID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		errors.BadRequest(w)
		return
	}

	notebook, err := h.repo.FetchNotebook(r.Context(), notebookID)
	if err != nil {
		if err == pgx.ErrNoRows {
			errors.NotFound(w, "notebook not found")
			return
		}
		errors.InternalServerError(w)
		return
	}

	if notebook.UserID != userID {
		errors.Unauthenticated(w)
		return
	}

	notes, err := h.repo.FetchNotebookNotes(r.Context(), notebookID)
	if err != nil {
		errors.InternalServerError(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(notes)
}

func (h *NotebookHandler) AddNoteToNotebook(w http.ResponseWriter, r *http.Request) {
	userID, _, err := utils.UserContext(r)
	if err != nil {
		errors.InternalServerError(w)
		return
	}

	notebookID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		errors.BadRequest(w)
		return
	}

	noteID, err := uuid.Parse(chi.URLParam(r, "noteId"))
	if err != nil {
		errors.BadRequest(w)
		return
	}

	// Verify user owns the notebook
	notebook, err := h.repo.FetchNotebook(r.Context(), notebookID)
	if err != nil {
		if err == pgx.ErrNoRows {
			errors.NotFound(w, "notebook not found")
			return
		}
		errors.InternalServerError(w)
		return
	}

	if notebook.UserID != userID {
		errors.Unauthenticated(w)
		return
	}

	// Verify user owns the note
	_, err = h.noteRepo.FetchUsersNote(r.Context(), noteID, userID)
	if err != nil {
		if err == pgx.ErrNoRows {
			errors.NotFound(w, "note not found or access denied")
			return
		}
		errors.InternalServerError(w)
		return
	}

	err = h.repo.AddNoteToNotebook(r.Context(), noteID, notebookID)
	if err != nil {
		errors.InternalServerError(w)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func (h *NotebookHandler) RemoveNoteFromNotebook(w http.ResponseWriter, r *http.Request) {
	userID, _, err := utils.UserContext(r)
	if err != nil {
		errors.InternalServerError(w)
		return
	}

	notebookID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		errors.BadRequest(w)
		return
	}

	noteID, err := uuid.Parse(chi.URLParam(r, "noteId"))
	if err != nil {
		errors.BadRequest(w)
		return
	}

	// Verify user owns the notebook
	notebook, err := h.repo.FetchNotebook(r.Context(), notebookID)
	if err != nil {
		if err == pgx.ErrNoRows {
			errors.NotFound(w, "notebook not found")
			return
		}
		errors.InternalServerError(w)
		return
	}

	if notebook.UserID != userID {
		errors.Unauthenticated(w)
		return
	}

	// Verify user owns the note
	_, err = h.noteRepo.FetchUsersNote(r.Context(), noteID, userID)
	if err != nil {
		if err == pgx.ErrNoRows {
			errors.NotFound(w, "note not found or access denied")
			return
		}
		errors.InternalServerError(w)
		return
	}

	err = h.repo.RemoveNoteFromNotebook(r.Context(), noteID, notebookID)
	if err != nil {
		errors.InternalServerError(w)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
