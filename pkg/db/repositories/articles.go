package repositories

import (
	"context"
	"tofoss/org-go/pkg/models"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type ArticleRepository struct {
	pool *pgxpool.Pool
}

func NewArticleRepository(pool *pgxpool.Pool) *ArticleRepository {
	return &ArticleRepository{pool: pool}
}

func (r *ArticleRepository) Upsert(
	ctx context.Context,
	article models.Article,
) (models.Article, error) {
	query := `
		INSERT INTO articles (id, user_id, title, content, created_at, updated_at, published_at, published) 
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8) 
        ON CONFLICT (id) DO UPDATE SET 
			user_id = EXCLUDED.user_id, 
			title = EXCLUDED.title, 
			content = EXCLUDED.content, 
			updated_at = EXCLUDED.updated_at, 
			published_at = EXCLUDED.published_at,
			published = EXCLUDED.published 
        RETURNING id, user_id, title, content, created_at, updated_at, published_at, published`

	rows, err := r.pool.Query(ctx, query,
		article.ID,
		article.UserID,
		article.Title,
		article.Content,
		article.CreatedAt,
		article.UpdatedAt,
		article.PublishedAt,
		article.Published,
	)

	if err != nil {
		return models.Article{}, err
	}

	defer rows.Close()

	res, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[models.Article])

	return res, err

}

func (r *ArticleRepository) FetchArticle(
	ctx context.Context,
	articleID uuid.UUID,
	userID uuid.UUID,
) (models.Article, error) {
	query := "select id, user_id, title, content, created_at, updated_at, published_at, published from articles where id = $1 and user_id = $2"

	rows, err := r.pool.Query(ctx, query, articleID, userID)

	if err != nil {
		return models.Article{}, err
	}

	defer rows.Close()

	res, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[models.Article])

	return res, err
}

func (r *ArticleRepository) FetchUsersArticles(
	ctx context.Context,
	userID uuid.UUID,
) ([]models.Article, error) {
	query := "select id, user_id, title, content, created_at, updated_at, published_at, published from articles where user_id = $1"

	rows, err := r.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	articles, err := pgx.CollectRows(rows, pgx.RowToStructByName[models.Article])

	return articles, err
}
