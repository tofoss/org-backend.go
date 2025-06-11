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

	if err != nil {
		return nil, err
	}

	// Extract note IDs for bulk tag fetching
	noteIDs := make([]uuid.UUID, len(notes))
	for i, note := range notes {
		noteIDs[i] = note.ID
	}

	// Fetch all tags for all notes in a single query
	tagsMap, err := r.GetTagsForNotes(ctx, noteIDs)
	if err != nil {
		return nil, err
	}

	// Assign tags to notes using map lookup
	for i := range notes {
		notes[i].Tags = tagsMap[notes[i].ID]
	}

	return notes, nil
}

// GetTagsForNote retrieves all tags associated with a note
func (r *NoteRepository) GetTagsForNote(
	ctx context.Context,
	noteID uuid.UUID,
) ([]models.Tag, error) {
	query := `
		SELECT t.id, t.name 
		FROM tags t 
		JOIN note_tags nt ON t.id = nt.tag_id 
		WHERE nt.note_id = $1
		ORDER BY t.name
	`

	rows, err := r.pool.Query(ctx, query, noteID)
	if err != nil {
		return []models.Tag{}, err
	}
	defer rows.Close()

	return pgx.CollectRows(rows, pgx.RowToStructByName[models.Tag])
}

// GetTagsForNotes retrieves all tags for multiple notes in a single query
func (r *NoteRepository) GetTagsForNotes(
	ctx context.Context,
	noteIDs []uuid.UUID,
) (map[uuid.UUID][]models.Tag, error) {
	if len(noteIDs) == 0 {
		return make(map[uuid.UUID][]models.Tag), nil
	}

	query := `
		SELECT nt.note_id, t.id, t.name 
		FROM tags t 
		JOIN note_tags nt ON t.id = nt.tag_id 
		WHERE nt.note_id = ANY($1)
		ORDER BY nt.note_id, t.name
	`

	rows, err := r.pool.Query(ctx, query, noteIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// Create map to group tags by note ID
	tagsMap := make(map[uuid.UUID][]models.Tag)
	
	// Initialize empty slices for all note IDs
	for _, noteID := range noteIDs {
		tagsMap[noteID] = []models.Tag{}
	}

	// Process query results
	for rows.Next() {
		var noteID uuid.UUID
		var tag models.Tag
		
		err := rows.Scan(&noteID, &tag.ID, &tag.Name)
		if err != nil {
			return nil, err
		}
		
		tagsMap[noteID] = append(tagsMap[noteID], tag)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return tagsMap, nil
}

// AssignTagsToNote assigns tags to a note, replacing any existing tags
func (r *NoteRepository) AssignTagsToNote(
	ctx context.Context,
	noteID uuid.UUID,
	tagIDs []uuid.UUID,
) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// Remove existing tags
	_, err = tx.Exec(ctx, "DELETE FROM note_tags WHERE note_id = $1", noteID)
	if err != nil {
		return err
	}

	// Add new tags
	for _, tagID := range tagIDs {
		_, err = tx.Exec(ctx, "INSERT INTO note_tags (note_id, tag_id) VALUES ($1, $2)", noteID, tagID)
		if err != nil {
			return err
		}
	}

	return tx.Commit(ctx)
}

// RemoveTagFromNote removes a specific tag from a note
func (r *NoteRepository) RemoveTagFromNote(
	ctx context.Context,
	noteID uuid.UUID,
	tagID uuid.UUID,
) error {
	_, err := r.pool.Exec(ctx, "DELETE FROM note_tags WHERE note_id = $1 AND tag_id = $2", noteID, tagID)
	return err
}

// FetchNoteWithTags retrieves a note with its associated tags
func (r *NoteRepository) FetchNoteWithTags(
	ctx context.Context,
	noteID uuid.UUID,
) (models.Note, error) {
	note, err := r.FetchNote(ctx, noteID)
	if err != nil {
		return models.Note{}, err
	}

	tags, err := r.GetTagsForNote(ctx, noteID)
	if err != nil {
		return models.Note{}, err
	}

	note.Tags = tags
	return note, nil
}

// FetchUsersNoteWithTags retrieves a user's note with its associated tags
func (r *NoteRepository) FetchUsersNoteWithTags(
	ctx context.Context,
	noteID uuid.UUID,
	userID uuid.UUID,
) (models.Note, error) {
	note, err := r.FetchUsersNote(ctx, noteID, userID)
	if err != nil {
		return models.Note{}, err
	}

	tags, err := r.GetTagsForNote(ctx, noteID)
	if err != nil {
		return models.Note{}, err
	}

	note.Tags = tags
	return note, nil
}
