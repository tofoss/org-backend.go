package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
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

type NoteHandler struct {
	repo *repositories.NoteRepository
}

func NewNoteHandler(
	repo *repositories.NoteRepository,
) NoteHandler {
	return NoteHandler{repo}
}

func (h *NoteHandler) FetchNote(w http.ResponseWriter, r *http.Request) {
	userID, _, err := utils.UserContext(r)
	if err != nil {
		log.Printf("unable to note, user not logged in: %v", err)
		errors.InternalServerError(w)
		return
	}

	noteID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		log.Printf("unable to parse note id: %v", err)
		errors.BadRequest(w)
		return
	}

	note, err := h.repo.FetchNote(r.Context(), noteID)
	if err != nil {
		if err == pgx.ErrNoRows {
			log.Printf("note %s not found %v", noteID, err)
			errors.NotFound(w, "note not found")
			return
		}
		log.Printf("unable to fetch note %s: %v", noteID, err)
		errors.InternalServerError(w)
		return
	}

	if !note.Published && note.UserID != userID {
		log.Printf(
			"%s does not have access to note %s which is not published",
			userID,
			noteID,
		)
		errors.Unauthenticated(w)
		return
	}

	response := responses.FetchNoteResponse{
		Note:    note,
		IsEditable: userID == note.UserID,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func (h *NoteHandler) FetchUsersNotes(w http.ResponseWriter, r *http.Request) {
	userID, _, err := utils.UserContext(r)
	if err != nil {
		log.Printf("unable to fetch users notes: %v", err)
		errors.InternalServerError(w)
	}

	notes, err := h.repo.FetchUsersNotes(r.Context(), userID)
	if err != nil {
		log.Printf("unable to fetch users notes: %v", err)
		errors.InternalServerError(w)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(notes)
}

func (h *NoteHandler) PostNote(w http.ResponseWriter, r *http.Request) {
	var req requests.Note
	err := json.NewDecoder(r.Body).Decode(&req)

	if err != nil {
		log.Printf("could not decode request, %v", err)
		errors.BadRequest(w)
		return
	}

	userID, _, err := utils.UserContext(r)
	if err != nil {
		log.Printf("unable to fetch users notes: %v", err)
		errors.InternalServerError(w)
	}

	var note *models.Note
	if req.ID == uuid.Nil {
		note, err = h.createNote(req, userID, r.Context())
	} else {
		note, err = h.updateNote(req, userID, r.Context())
	}

	if err != nil {
		log.Printf("could not upsert note: %v", err)
		errors.InternalServerError(w)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(note)
}

func (h *NoteHandler) createNote(
	req requests.Note,
	userID uuid.UUID,
	ctx context.Context,
) (*models.Note, error) {
	now := time.Now()
	var publishedAt *time.Time

	if req.Published {
		publishedAt = &now
	}

	note := models.Note{
		ID:          uuid.New(),
		UserID:      userID,
		Title:       "",
		Content:     req.Content,
		CreatedAt:   now,
		UpdatedAt:   now,
		PublishedAt: publishedAt,
		Published:   req.Published,
	}

	result, err := h.repo.Upsert(ctx, note)

	if err != nil {
		return nil, err
	}

	return &result, nil
}

func (h *NoteHandler) updateNote(
	req requests.Note,
	userID uuid.UUID,
	ctx context.Context,
) (*models.Note, error) {
	original, err := h.repo.FetchUsersNote(ctx, req.ID, userID)

	if err != nil {
		return nil, fmt.Errorf("unable to upsert note, invalid credentials, %v", err)
	}

	now := time.Now()
	var publishedAt *time.Time

	if req.Published && original.Published {
		publishedAt = original.PublishedAt
	} else if req.Published {
		publishedAt = &now
	}

	update := original
	update.Content = req.Content
	update.UpdatedAt = now
	update.PublishedAt = publishedAt
	update.Published = req.Published

	result, err := h.repo.Upsert(ctx, update)

	if err != nil {
		return nil, err
	}

	return &result, nil
}
