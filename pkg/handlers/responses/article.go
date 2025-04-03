package responses

import "tofoss/org-go/pkg/models"

type FetchArticleResponse struct {
	models.Article
	IsEditable bool `json:"isEditable"`
}
