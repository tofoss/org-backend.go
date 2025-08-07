package responses

import (
	"tofoss/org-go/pkg/models"
)

type CreateRecipeResponse struct {
	JobID string `json:"jobId"`
}

type RecipeJobResponse struct {
	Job    models.RecipeJob `json:"job"`
	Recipe *models.Recipe   `json:"recipe,omitempty"`
	Note   *models.Note     `json:"note,omitempty"`
}