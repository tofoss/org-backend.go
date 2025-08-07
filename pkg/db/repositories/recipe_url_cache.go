package repositories

import (
	"context"
	"time"
	"tofoss/org-go/pkg/models"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type RecipeURLCacheRepository struct {
	pool *pgxpool.Pool
}

func NewRecipeURLCacheRepository(pool *pgxpool.Pool) *RecipeURLCacheRepository {
	return &RecipeURLCacheRepository{pool: pool}
}

func (r *RecipeURLCacheRepository) Create(
	ctx context.Context,
	cache models.RecipeURLCache,
) error {
	query := `
		INSERT INTO recipe_url_cache (url_hash, original_url, recipe_id, created_at, last_accessed) 
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (url_hash) DO UPDATE SET
			last_accessed = EXCLUDED.last_accessed`

	_, err := r.pool.Exec(ctx, query,
		cache.URLHash,
		cache.OriginalURL,
		cache.RecipeID,
		cache.CreatedAt,
		cache.LastAccessed,
	)
	return err
}

func (r *RecipeURLCacheRepository) GetByURLHash(
	ctx context.Context,
	urlHash string,
) (models.RecipeURLCache, error) {
	query := `
		SELECT url_hash, original_url, recipe_id, created_at, last_accessed 
		FROM recipe_url_cache 
		WHERE url_hash = $1`

	rows, err := r.pool.Query(ctx, query, urlHash)
	if err != nil {
		return models.RecipeURLCache{}, err
	}
	defer rows.Close()

	if !rows.Next() {
		return models.RecipeURLCache{}, pgx.ErrNoRows
	}

	var cache models.RecipeURLCache
	err = rows.Scan(
		&cache.URLHash,
		&cache.OriginalURL,
		&cache.RecipeID,
		&cache.CreatedAt,
		&cache.LastAccessed,
	)
	return cache, err
}

func (r *RecipeURLCacheRepository) UpdateLastAccessed(
	ctx context.Context,
	urlHash string,
) error {
	query := `
		UPDATE recipe_url_cache 
		SET last_accessed = $2 
		WHERE url_hash = $1`

	_, err := r.pool.Exec(ctx, query, urlHash, time.Now())
	return err
}

func (r *RecipeURLCacheRepository) DeleteOldEntries(
	ctx context.Context,
	olderThan time.Time,
) (int64, error) {
	query := `
		DELETE FROM recipe_url_cache 
		WHERE created_at < $1`

	result, err := r.pool.Exec(ctx, query, olderThan)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected(), nil
}