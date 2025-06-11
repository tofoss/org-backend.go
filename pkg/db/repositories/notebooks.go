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

func (r *NotebookRepository) FetchUserNotebooks(
	ctx context.Context,
	userID uuid.UUID,
) ([]models.Notebook, error) {
	query := `
		SELECT id, user_id, name, description, created_at, updated_at
		FROM notebooks WHERE user_id = $1
		ORDER BY updated_at DESC
	`

	rows, err := r.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return pgx.CollectRows(rows, pgx.RowToStructByName[models.Notebook])
}

func (r *NotebookRepository) Delete(
	ctx context.Context,
	id uuid.UUID,
) error {
	query := `DELETE FROM notebooks WHERE id = $1`
	_, err := r.pool.Exec(ctx, query, id)
	return err
}

func (r *NotebookRepository) AddNoteToNotebook(
	ctx context.Context,
	noteID, notebookID uuid.UUID,
) error {
	query := `
		INSERT INTO note_notebooks (note_id, notebook_id) 
		VALUES ($1, $2) 
		ON CONFLICT (note_id, notebook_id) DO NOTHING
	`
	_, err := r.pool.Exec(ctx, query, noteID, notebookID)
	return err
}

func (r *NotebookRepository) RemoveNoteFromNotebook(
	ctx context.Context,
	noteID, notebookID uuid.UUID,
) error {
	query := `DELETE FROM note_notebooks WHERE note_id = $1 AND notebook_id = $2`
	_, err := r.pool.Exec(ctx, query, noteID, notebookID)
	return err
}

func (r *NotebookRepository) FetchNotebookNotes(
	ctx context.Context,
	notebookID uuid.UUID,
) ([]models.Note, error) {
	query := `
		SELECT n.id, n.user_id, n.title, n.content, n.created_at, n.updated_at, n.published_at, n.published
		FROM notes n
		INNER JOIN note_notebooks nn ON n.id = nn.note_id
		WHERE nn.notebook_id = $1
		ORDER BY n.updated_at DESC
	`

	rows, err := r.pool.Query(ctx, query, notebookID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return pgx.CollectRows(rows, pgx.RowToStructByName[models.Note])
}
