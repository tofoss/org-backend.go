package repositories

import (
	"context"
	"tofoss/org-go/pkg/models"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type NoteRepository struct {
	pool *pgxpool.Pool
}

func NewNoteRepository(pool *pgxpool.Pool) *NoteRepository {
	return &NoteRepository{pool: pool}
}

func (r *NoteRepository) Upsert(
	ctx context.Context,
	note models.Note,
) (models.Note, error) {
	query := `
		INSERT INTO notes (id, user_id, title, content, created_at, updated_at, published_at, published) 
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
		note.ID,
		note.UserID,
		note.Title,
		note.Content,
		note.CreatedAt,
		note.UpdatedAt,
		note.PublishedAt,
		note.Published,
	)

	if err != nil {
		return models.Note{}, err
	}

	defer rows.Close()

	res, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[models.Note])

	return res, err

}

func (r *NoteRepository) FetchNote(
	ctx context.Context,
	noteID uuid.UUID,
) (models.Note, error) {
	query := "select id, user_id, title, content, created_at, updated_at, published_at, published from notes where id = $1"

	rows, err := r.pool.Query(ctx, query, noteID)

	if err != nil {
		return models.Note{}, err
	}

	defer rows.Close()

	res, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[models.Note])

	return res, err
}

func (r *NoteRepository) FetchUsersNote(
	ctx context.Context,
	noteID uuid.UUID,
	userID uuid.UUID,
) (models.Note, error) {
	query := "select id, user_id, title, content, created_at, updated_at, published_at, published from notes where id = $1 and user_id = $2"

	rows, err := r.pool.Query(ctx, query, noteID, userID)

	if err != nil {
		return models.Note{}, err
	}

	defer rows.Close()

	res, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[models.Note])

	return res, err
}

func (r *NoteRepository) FetchUsersNotes(
	ctx context.Context,
	userID uuid.UUID,
) ([]models.Note, error) {
	query := "select id, user_id, title, content, created_at, updated_at, published_at, published from notes where user_id = $1"

	rows, err := r.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	notes, err := pgx.CollectRows(rows, pgx.RowToStructByName[models.Note])

	return notes, err
}
