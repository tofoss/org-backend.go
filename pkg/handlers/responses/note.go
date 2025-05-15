package responses

import "tofoss/org-go/pkg/models"

type FetchNoteResponse struct {
	models.Note
	IsEditable bool `json:"isEditable"`
}
