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

type ArticleHandler struct {
	repo *repositories.ArticleRepository
}

func NewArticleHandler(
	repo *repositories.ArticleRepository,
) ArticleHandler {
	return ArticleHandler{repo}
}

func (h *ArticleHandler) FetchArticle(w http.ResponseWriter, r *http.Request) {
	userID, _, err := utils.UserContext(r)
	if err != nil {
		log.Printf("unable to article, user not logged in: %v", err)
		errors.InternalServerError(w)
		return
	}

	articleID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		log.Printf("unable to parse article id: %v", err)
		errors.BadRequest(w)
		return
	}

	article, err := h.repo.FetchArticle(r.Context(), articleID)
	if err != nil {
		if err == pgx.ErrNoRows {
			log.Printf("article %s not found %v", articleID, err)
			errors.NotFound(w, "article not found")
			return
		}
		log.Printf("unable to fetch article %s: %v", articleID, err)
		errors.InternalServerError(w)
		return
	}

	if !article.Published && article.UserID != userID {
		log.Printf(
			"%s does not have access to article %s which is not published",
			userID,
			articleID,
		)
		errors.Unauthenticated(w)
		return
	}

	response := responses.FetchArticleResponse{
		Article:    article,
		IsEditable: userID == article.UserID,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func (h *ArticleHandler) FetchUsersArticles(w http.ResponseWriter, r *http.Request) {
	userID, _, err := utils.UserContext(r)
	if err != nil {
		log.Printf("unable to fetch users articles: %v", err)
		errors.InternalServerError(w)
	}

	articles, err := h.repo.FetchUsersArticles(r.Context(), userID)
	if err != nil {
		log.Printf("unable to fetch users articles: %v", err)
		errors.InternalServerError(w)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(articles)
}

func (h *ArticleHandler) PostArticle(w http.ResponseWriter, r *http.Request) {
	var req requests.Article
	err := json.NewDecoder(r.Body).Decode(&req)

	if err != nil {
		log.Printf("could not decode request, %v", err)
		errors.BadRequest(w)
		return
	}

	userID, _, err := utils.UserContext(r)
	if err != nil {
		log.Printf("unable to fetch users articles: %v", err)
		errors.InternalServerError(w)
	}

	var article *models.Article
	if req.ID == uuid.Nil {
		article, err = h.createArticle(req, userID, r.Context())
	} else {
		article, err = h.updateArticle(req, userID, r.Context())
	}

	if err != nil {
		log.Printf("could not upsert article: %v", err)
		errors.InternalServerError(w)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(article)
}

func (h *ArticleHandler) createArticle(
	req requests.Article,
	userID uuid.UUID,
	ctx context.Context,
) (*models.Article, error) {
	now := time.Now()
	var publishedAt *time.Time

	if req.Published {
		publishedAt = &now
	}

	article := models.Article{
		ID:          uuid.New(),
		UserID:      userID,
		Title:       "",
		Content:     req.Content,
		CreatedAt:   now,
		UpdatedAt:   now,
		PublishedAt: publishedAt,
		Published:   req.Published,
	}

	result, err := h.repo.Upsert(ctx, article)

	if err != nil {
		return nil, err
	}

	return &result, nil
}

func (h *ArticleHandler) updateArticle(
	req requests.Article,
	userID uuid.UUID,
	ctx context.Context,
) (*models.Article, error) {
	original, err := h.repo.FetchUsersArticle(ctx, req.ID, userID)

	if err != nil {
		return nil, fmt.Errorf("unable to upsert article, invalid credentials, %v", err)
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
