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
	tag models.Tag,
) (models.Tag, error) {
	query := `
		INSERT INTO tags (id, name)
		VALUES ($1, $2)
		ON CONFLICT (id) DO UPDATE SET
			name = EXCLUDED.name
		RETURNING id, name
	`

	rows, err := r.pool.Query(ctx, query,
		tag.ID,
		tag.Name,
	)
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
