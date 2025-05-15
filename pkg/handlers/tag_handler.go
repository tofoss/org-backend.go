package handlers

import (
	"encoding/json"
	"net/http"
	"tofoss/org-go/pkg/db/repositories"
	"tofoss/org-go/pkg/handlers/errors"
	"tofoss/org-go/pkg/models"
	"tofoss/org-go/pkg/utils"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type TagHandler struct {
	repo *repositories.TagRepository
}

func NewTagHandler(repo *repositories.TagRepository) TagHandler {
	return TagHandler{repo}
}

func (h *TagHandler) FetchTag(w http.ResponseWriter, r *http.Request) {
	_, _, err := utils.UserContext(r)
	if err != nil {
		errors.InternalServerError(w)
		return
	}
	tagID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		errors.BadRequest(w)
		return
	}
	tag, err := h.repo.FetchTag(r.Context(), tagID)
	if err != nil {
		errors.InternalServerError(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(tag)
}

func (h *TagHandler) PostTag(w http.ResponseWriter, r *http.Request) {
	_, _, err := utils.UserContext(r)
	if err != nil {
		errors.InternalServerError(w)
		return
	}
	var tag models.Tag
	if err := json.NewDecoder(r.Body).Decode(&tag); err != nil {
		errors.BadRequest(w)
		return
	}
	saved, err := h.repo.Upsert(r.Context(), tag)
	if err != nil {
		errors.InternalServerError(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(saved)
}
