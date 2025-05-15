package repositories

import (
	"context"
	"tofoss/org-go/pkg/models"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type SectionRepository struct {
	pool *pgxpool.Pool
}

func NewSectionRepository(pool *pgxpool.Pool) *SectionRepository {
	return &SectionRepository{pool: pool}
}

func (r *SectionRepository) Upsert(
	ctx context.Context,
	section models.Section,
) (models.Section, error) {
	query := `
		INSERT INTO sections (id, notebook_id, name, position, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (id) DO UPDATE SET
			notebook_id = EXCLUDED.notebook_id,
			name = EXCLUDED.name,
			position = EXCLUDED.position,
			updated_at = EXCLUDED.updated_at
		RETURNING id, notebook_id, name, position, created_at, updated_at
	`

	rows, err := r.pool.Query(ctx, query,
		section.ID,
		section.NotebookID,
		section.Name,
		section.Position,
		section.CreatedAt,
		section.UpdatedAt,
	)
	if err != nil {
		return models.Section{}, err
	}
	defer rows.Close()

	return pgx.CollectOneRow(rows, pgx.RowToStructByName[models.Section])
}

func (r *SectionRepository) FetchSection(
	ctx context.Context,
	id uuid.UUID,
) (models.Section, error) {
	query := `
		SELECT id, notebook_id, name, position, created_at, updated_at
		FROM sections WHERE id = $1
	`

	rows, err := r.pool.Query(ctx, query, id)
	if err != nil {
		return models.Section{}, err
	}
	defer rows.Close()

	return pgx.CollectOneRow(rows, pgx.RowToStructByName[models.Section])
}
