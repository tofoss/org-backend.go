package repositories

import (
	"context"
	"tofoss/org-go/pkg/models"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type TagRepository struct {
	pool *pgxpool.Pool
}

func NewTagRepository(pool *pgxpool.Pool) *TagRepository {
	return &TagRepository{pool: pool}
}

func (r *TagRepository) Upsert(
	ctx context.Context,
	tagName string,
) (models.Tag, error) {
	query := `
		INSERT INTO tags (name)
		VALUES ($1)
		ON CONFLICT (name) DO NOTHING
		RETURNING id, name
	`

	rows, err := r.pool.Query(ctx, query, tagName)
	if err != nil {
		return models.Tag{}, err
	}
	defer rows.Close()

	return pgx.CollectOneRow(rows, pgx.RowToStructByName[models.Tag])
}

func (r *TagRepository) FetchTag(
	ctx context.Context,
	id uuid.UUID,
) (models.Tag, error) {
	query := `SELECT id, name FROM tags WHERE id = $1`

	rows, err := r.pool.Query(ctx, query, id)
	if err != nil {
		return models.Tag{}, err
	}
	defer rows.Close()

	return pgx.CollectOneRow(rows, pgx.RowToStructByName[models.Tag])
}

func (r *TagRepository) FetchAll(
	ctx context.Context,
) ([]models.Tag, error) {
	query := `SELECT id, name FROM tags`

	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return []models.Tag{}, err
	}
	defer rows.Close()

	return pgx.CollectRows(rows, pgx.RowToStructByName[models.Tag])
}
