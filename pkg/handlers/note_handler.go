package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
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

	note, err := h.repo.FetchNoteWithTags(r.Context(), noteID)
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
		Note:       note,
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

// SearchNotes searches notes using full-text search
func (h *NoteHandler) SearchNotes(w http.ResponseWriter, r *http.Request) {
	userID, _, err := utils.UserContext(r)
	if err != nil {
		log.Printf("unable to search notes, user not logged in: %v", err)
		errors.InternalServerError(w)
		return
	}

	// Get query parameters
	query := r.URL.Query().Get("q")
	if query == "" {
		// If no query provided, return empty results
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode([]models.Note{})
		return
	}

	// Parse pagination parameters with defaults
	limit := 50
	offset := 0

	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if parsedLimit, err := strconv.Atoi(limitStr); err == nil && parsedLimit > 0 && parsedLimit <= 100 {
			limit = parsedLimit
		}
	}

	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if parsedOffset, err := strconv.Atoi(offsetStr); err == nil && parsedOffset >= 0 {
			offset = parsedOffset
		}
	}

	notes, err := h.repo.SearchNotes(r.Context(), userID, query, limit, offset)
	if err != nil {
		log.Printf("unable to search notes: %v", err)
		errors.InternalServerError(w)
		return
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

	// Generate title from content if not provided
	title := req.Title
	if title == "" {
		title = utils.GenerateTitleFromContent(req.Content)
	}

	note := models.Note{
		ID:          uuid.New(),
		UserID:      userID,
		Title:       title,
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

	// Generate title from content if title is empty (either from request or original)
	title := req.Title
	if title == "" && original.Title == "" {
		title = utils.GenerateTitleFromContent(req.Content)
	} else if title == "" {
		title = original.Title // Preserve existing title
	}

	update := original
	update.Title = title
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

// GetNoteTags retrieves all tags for a specific note
func (h *NoteHandler) GetNoteTags(w http.ResponseWriter, r *http.Request) {
	userID, _, err := utils.UserContext(r)
	if err != nil {
		log.Printf("unable to get note tags, user not logged in: %v", err)
		errors.InternalServerError(w)
		return
	}

	noteID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		log.Printf("unable to parse note id: %v", err)
		errors.BadRequest(w)
		return
	}

	// Verify user has access to this note
	note, err := h.repo.FetchUsersNote(r.Context(), noteID, userID)
	if err != nil {
		if err == pgx.ErrNoRows {
			log.Printf("note %s not found or user %s doesn't have access", noteID, userID)
			errors.NotFound(w, "note not found")
			return
		}
		log.Printf("unable to fetch note %s: %v", noteID, err)
		errors.InternalServerError(w)
		return
	}

	tags, err := h.repo.GetTagsForNote(r.Context(), note.ID)
	if err != nil {
		log.Printf("unable to fetch tags for note %s: %v", noteID, err)
		errors.InternalServerError(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(tags)
}

// AssignNoteTags assigns tags to a note
func (h *NoteHandler) AssignNoteTags(w http.ResponseWriter, r *http.Request) {
	userID, _, err := utils.UserContext(r)
	if err != nil {
		log.Printf("unable to assign note tags, user not logged in: %v", err)
		errors.InternalServerError(w)
		return
	}

	noteID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		log.Printf("unable to parse note id: %v", err)
		errors.BadRequest(w)
		return
	}

	var req requests.AssignTags
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("could not decode assign tags request: %v", err)
		errors.BadRequest(w)
		return
	}

	// Verify user has access to this note
	_, err = h.repo.FetchUsersNote(r.Context(), noteID, userID)
	if err != nil {
		if err == pgx.ErrNoRows {
			log.Printf("note %s not found or user %s doesn't have access", noteID, userID)
			errors.NotFound(w, "note not found")
			return
		}
		log.Printf("unable to fetch note %s: %v", noteID, err)
		errors.InternalServerError(w)
		return
	}

	err = h.repo.AssignTagsToNote(r.Context(), noteID, req.TagIDs)
	if err != nil {
		log.Printf("unable to assign tags to note %s: %v", noteID, err)
		errors.InternalServerError(w)
		return
	}

	// Return the updated tags
	tags, err := h.repo.GetTagsForNote(r.Context(), noteID)
	if err != nil {
		log.Printf("unable to fetch updated tags for note %s: %v", noteID, err)
		errors.InternalServerError(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(tags)
}

// RemoveNoteTag removes a specific tag from a note
func (h *NoteHandler) RemoveNoteTag(w http.ResponseWriter, r *http.Request) {
	userID, _, err := utils.UserContext(r)
	if err != nil {
		log.Printf("unable to remove note tag, user not logged in: %v", err)
		errors.InternalServerError(w)
		return
	}

	noteID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		log.Printf("unable to parse note id: %v", err)
		errors.BadRequest(w)
		return
	}

	tagID, err := uuid.Parse(chi.URLParam(r, "tagId"))
	if err != nil {
		log.Printf("unable to parse tag id: %v", err)
		errors.BadRequest(w)
		return
	}

	// Verify user has access to this note
	_, err = h.repo.FetchUsersNote(r.Context(), noteID, userID)
	if err != nil {
		if err == pgx.ErrNoRows {
			log.Printf("note %s not found or user %s doesn't have access", noteID, userID)
			errors.NotFound(w, "note not found")
			return
		}
		log.Printf("unable to fetch note %s: %v", noteID, err)
		errors.InternalServerError(w)
		return
	}

	err = h.repo.RemoveTagFromNote(r.Context(), noteID, tagID)
	if err != nil {
		log.Printf("unable to remove tag %s from note %s: %v", tagID, noteID, err)
		errors.InternalServerError(w)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GetNoteNotebooks retrieves all notebooks that contain a specific note
func (h *NoteHandler) GetNoteNotebooks(w http.ResponseWriter, r *http.Request) {
	userID, _, err := utils.UserContext(r)
	if err != nil {
		log.Printf("unable to get note notebooks, user not logged in: %v", err)
		errors.InternalServerError(w)
		return
	}

	noteID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		log.Printf("unable to parse note id: %v", err)
		errors.BadRequest(w)
		return
	}

	// Verify user has access to this note
	_, err = h.repo.FetchUsersNote(r.Context(), noteID, userID)
	if err != nil {
		if err == pgx.ErrNoRows {
			log.Printf("note %s not found or user %s doesn't have access", noteID, userID)
			errors.NotFound(w, "note not found")
			return
		}
		log.Printf("unable to fetch note %s: %v", noteID, err)
		errors.InternalServerError(w)
		return
	}

	notebooks, err := h.repo.GetNotebooksForNote(r.Context(), noteID)
	if err != nil {
		log.Printf("unable to fetch notebooks for note %s: %v", noteID, err)
		errors.InternalServerError(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(notebooks)
}
