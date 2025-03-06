package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"tofoss/org-go/pkg/db/repositories"
	"tofoss/org-go/pkg/handlers/errors"
	"tofoss/org-go/pkg/utils"
)

type ArticleHandler struct {
	repo *repositories.ArticleRepository
}

func NewArticleHandler(
	repo *repositories.ArticleRepository,
) ArticleHandler {
	return ArticleHandler{repo}
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

/*
articleHandler :: Connection -> AuthResult User -> Req.ArticleRequest -> Handler Article
articleHandler conn authResult req = auth authResult $ handleArticleReq conn req

handleArticleReq :: Connection -> Req.ArticleRequest -> User -> Handler Article
handleArticleReq conn req user = case Req.articleId req of
  Just id -> updateArticle conn req user id
  Nothing -> createArticle conn req user

createArticle :: Connection -> Req.ArticleRequest -> User -> Handler Article
createArticle conn req user = do
  currentTime <- liftIO getCurrentTime
  id <- liftIO nextRandom

  let article =
        Article
          { articleId = id,
            articlePublished = Req.articlePublished req,
            articlePublishedAt = if Req.articlePublished req then Just currentTime else Nothing,
            articleUpdatedAt = currentTime,
            articleCreatedAt = currentTime,
            articleContent = Req.articleContent req,
            articleTitle = "title",
            articleUserId = userId user
          }

  maybeArticle <- liftIO $ upsertArticle conn article
  unwrap maybeArticle

updateArticle :: Connection -> Req.ArticleRequest -> User -> UUID -> Handler Article
updateArticle conn req user id = do
  article <- liftIO $ fetchArticle conn id (userId user)
  updateArticle' conn req article

updateArticle' :: Connection -> Req.ArticleRequest -> Maybe Article -> Handler Article
updateArticle' _ _ Nothing = throwError err403 {errBody = "Could not update article - Invalid credentials"}
updateArticle' conn req (Just article) = do
  currentTime <- liftIO getCurrentTime

  let updatedArticle =
        article
          { articlePublished = Req.articlePublished req,
            articlePublishedAt = publishedAt article req currentTime,
            articleUpdatedAt = currentTime,
            articleContent = Req.articleContent req,
            articleTitle = "title"
          }

  maybeArticle <- liftIO $ upsertArticle conn updatedArticle
  unwrap maybeArticle

publishedAt :: Article -> Req.ArticleRequest -> UTCTime -> Maybe UTCTime
publishedAt article req now
  | articlePublished article == Req.articlePublished req = articlePublishedAt article
  | Req.articlePublished req = Just now
  | otherwise = articlePublishedAt article

unwrap :: Maybe a -> Handler a
unwrap (Just x) = return x
unwrap Nothing = throwError err500 {errBody = "Internal server error - failed to fetch article"}
*/
