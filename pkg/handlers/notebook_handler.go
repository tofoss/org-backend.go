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
	repo *repositories.NotebookRepository
}

func NewNotebookHandler(repo *repositories.NotebookRepository) NotebookHandler {
	return NotebookHandler{repo: repo}
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
		req.ID = uuid.New()
		req.CreatedAt = now
	}
	req.UpdatedAt = now
	req.UserID = userID

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

	err = h.repo.RemoveNoteFromNotebook(r.Context(), noteID, notebookID)
	if err != nil {
		errors.InternalServerError(w)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
