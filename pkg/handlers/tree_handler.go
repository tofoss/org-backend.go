package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"tofoss/org-go/pkg/db/repositories"
	"tofoss/org-go/pkg/handlers/errors"
	"tofoss/org-go/pkg/utils"
)

type TreeHandler struct {
	repo repositories.TreeRepositoryInterface
}

func NewTreeHandler(repo repositories.TreeRepositoryInterface) TreeHandler {
	return TreeHandler{repo: repo}
}

func (h *TreeHandler) GetTree(w http.ResponseWriter, r *http.Request) {
	userID, _, err := utils.UserContext(r)
	if err != nil {
		log.Printf("unable to get tree, user not logged in: %v", err)
		errors.InternalServerError(w)
		return
	}

	treeData, err := h.repo.GetTree(r.Context(), userID)
	if err != nil {
		log.Printf("unable to fetch tree data: %v", err)
		errors.InternalServerError(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(treeData)
}
