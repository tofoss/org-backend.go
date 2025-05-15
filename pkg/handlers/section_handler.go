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

type SectionHandler struct {
	repo *repositories.SectionRepository
}

func NewSectionHandler(repo *repositories.SectionRepository) SectionHandler {
	return SectionHandler{repo}
}

func (h *SectionHandler) FetchSection(w http.ResponseWriter, r *http.Request) {
	_, _, err := utils.UserContext(r)
	if err != nil {
		errors.InternalServerError(w)
		return
	}
	sectionID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		errors.BadRequest(w)
		return
	}
	section, err := h.repo.FetchSection(r.Context(), sectionID)
	if err != nil {
		errors.InternalServerError(w)
		return
	}
	// TODO: Sjekk om section hører til en notebook som bruker eier
	/*
		if section.UserID != userID {
			errors.Unauthenticated(w)
			return
		}
	*/
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(section)
}

func (h *SectionHandler) PostSection(w http.ResponseWriter, r *http.Request) {
	_, _, err := utils.UserContext(r)
	if err != nil {
		errors.InternalServerError(w)
		return
	}
	var section models.Section
	if err := json.NewDecoder(r.Body).Decode(&section); err != nil {
		errors.BadRequest(w)
		return
	}
	//section.UserID = userID
	saved, err := h.repo.Upsert(r.Context(), section)
	if err != nil {
		errors.InternalServerError(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(saved)
}
