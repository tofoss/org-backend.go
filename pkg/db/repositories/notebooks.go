package repositories

import (
	"context"
	"tofoss/org-go/pkg/models"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type NotebookRepository struct {
	pool *pgxpool.Pool
}

func NewNotebookRepository(pool *pgxpool.Pool) *NotebookRepository {
	return &NotebookRepository{pool: pool}
}

func (r *NotebookRepository) Upsert(
	ctx context.Context,
	notebook models.Notebook,
) (models.Notebook, error) {
	query := `
		INSERT INTO notebooks (id, user_id, name, description, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (id) DO UPDATE SET
			user_id = EXCLUDED.user_id,
			name = EXCLUDED.name,
			description = EXCLUDED.description,
			updated_at = EXCLUDED.updated_at
		RETURNING id, user_id, name, description, created_at, updated_at
	`

	rows, err := r.pool.Query(ctx, query,
		notebook.ID,
		notebook.UserID,
		notebook.Name,
		notebook.Description,
		notebook.CreatedAt,
		notebook.UpdatedAt,
	)
	if err != nil {
		return models.Notebook{}, err
	}
	defer rows.Close()

	return pgx.CollectOneRow(rows, pgx.RowToStructByName[models.Notebook])
}

func (r *NotebookRepository) FetchNotebook(
	ctx context.Context,
	id uuid.UUID,
) (models.Notebook, error) {
	query := `
		SELECT id, user_id, name, description, created_at, updated_at
		FROM notebooks WHERE id = $1
	`

	rows, err := r.pool.Query(ctx, query, id)
	if err != nil {
		return models.Notebook{}, err
	}
	defer rows.Close()

	return pgx.CollectOneRow(rows, pgx.RowToStructByName[models.Notebook])
}
