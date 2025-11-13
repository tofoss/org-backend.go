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
	// Generate new ID if not provided (creating new section)
	if section.ID == uuid.Nil {
		section.ID = uuid.New()
	}

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

// FetchNotebookSections retrieves all sections in a notebook, ordered by position
func (r *SectionRepository) FetchNotebookSections(
	ctx context.Context,
	notebookID uuid.UUID,
) ([]models.Section, error) {
	query := `
		SELECT id, notebook_id, name, position, created_at, updated_at
		FROM sections
		WHERE notebook_id = $1
		ORDER BY position ASC
	`

	rows, err := r.pool.Query(ctx, query, notebookID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return pgx.CollectRows(rows, pgx.RowToStructByName[models.Section])
}

// DeleteSection deletes a section. Notes in the section become unsectioned (section_id set to NULL)
func (r *SectionRepository) DeleteSection(
	ctx context.Context,
	id uuid.UUID,
) error {
	query := `DELETE FROM sections WHERE id = $1`
	_, err := r.pool.Exec(ctx, query, id)
	return err
}

// UpdateSectionPosition updates the position of a section for reordering
func (r *SectionRepository) UpdateSectionPosition(
	ctx context.Context,
	id uuid.UUID,
	newPosition int,
) error {
	// Get current section and its notebook
	currentSection, err := r.FetchSection(ctx, id)
	if err != nil {
		return err
	}

	// Begin transaction
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	oldPosition := currentSection.Position

	// If moving section down (increasing position), shift sections between old and new position up
	if newPosition > oldPosition {
		shiftQuery := `
			UPDATE sections
			SET position = position - 1
			WHERE notebook_id = $1 AND position > $2 AND position <= $3
		`
		_, err = tx.Exec(ctx, shiftQuery, currentSection.NotebookID, oldPosition, newPosition)
		if err != nil {
			return err
		}
	} else if newPosition < oldPosition {
		// If moving section up (decreasing position), shift sections between new and old position down
		shiftQuery := `
			UPDATE sections
			SET position = position + 1
			WHERE notebook_id = $1 AND position >= $2 AND position < $3
		`
		_, err = tx.Exec(ctx, shiftQuery, currentSection.NotebookID, newPosition, oldPosition)
		if err != nil {
			return err
		}
	}

	// Update target section position
	updateQuery := `UPDATE sections SET position = $1, updated_at = NOW() WHERE id = $2`
	_, err = tx.Exec(ctx, updateQuery, newPosition, id)
	if err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// UpdateSectionName updates the name of a section
func (r *SectionRepository) UpdateSectionName(
	ctx context.Context,
	id uuid.UUID,
	name string,
) error {
	query := `UPDATE sections SET name = $1, updated_at = NOW() WHERE id = $2`
	_, err := r.pool.Exec(ctx, query, name, id)
	return err
}

// AssignNoteToSection assigns a note to a section within a notebook context
func (r *SectionRepository) AssignNoteToSection(
	ctx context.Context,
	noteID uuid.UUID,
	notebookID uuid.UUID,
	sectionID *uuid.UUID, // Can be nil to unassign (make unsectioned)
) error {
	query := `
		INSERT INTO note_notebooks (note_id, notebook_id, section_id)
		VALUES ($1, $2, $3)
		ON CONFLICT (note_id, notebook_id)
		DO UPDATE SET section_id = $3
	`
	_, err := r.pool.Exec(ctx, query, noteID, notebookID, sectionID)
	return err
}

// FetchSectionNotes retrieves all notes in a specific section
func (r *SectionRepository) FetchSectionNotes(
	ctx context.Context,
	sectionID uuid.UUID,
) ([]models.Note, error) {
	query := `
		SELECT n.id, n.user_id, n.title, n.content, n.created_at, n.updated_at, n.published_at, n.published
		FROM notes n
		JOIN note_notebooks nn ON n.id = nn.note_id
		WHERE nn.section_id = $1
		ORDER BY nn.position ASC
	`

	rows, err := r.pool.Query(ctx, query, sectionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return pgx.CollectRows(rows, pgx.RowToStructByName[models.Note])
}

// FetchUnsectionedNotes retrieves all notes in a notebook that don't belong to any section
func (r *SectionRepository) FetchUnsectionedNotes(
	ctx context.Context,
	notebookID uuid.UUID,
) ([]models.Note, error) {
	query := `
		SELECT n.id, n.user_id, n.title, n.content, n.created_at, n.updated_at, n.published_at, n.published
		FROM notes n
		JOIN note_notebooks nn ON n.id = nn.note_id
		WHERE nn.notebook_id = $1 AND nn.section_id IS NULL
		ORDER BY nn.position ASC
	`

	rows, err := r.pool.Query(ctx, query, notebookID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return pgx.CollectRows(rows, pgx.RowToStructByName[models.Note])
}

// UpdateNotePosition updates the position of a note within its section for reordering
func (r *SectionRepository) UpdateNotePosition(
	ctx context.Context,
	noteID uuid.UUID,
	notebookID uuid.UUID,
	newPosition int,
) error {
	// Get current note position and section
	var oldPosition int
	var sectionID *uuid.UUID
	query := `SELECT position, section_id FROM note_notebooks WHERE note_id = $1 AND notebook_id = $2`
	err := r.pool.QueryRow(ctx, query, noteID, notebookID).Scan(&oldPosition, &sectionID)
	if err != nil {
		return err
	}

	// Begin transaction
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// If moving note down (increasing position), shift notes between old and new position up
	if newPosition > oldPosition {
		shiftQuery := `
			UPDATE note_notebooks
			SET position = position - 1
			WHERE notebook_id = $1
			  AND (section_id = $2 OR (section_id IS NULL AND $2 IS NULL))
			  AND position > $3 AND position <= $4
		`
		_, err = tx.Exec(ctx, shiftQuery, notebookID, sectionID, oldPosition, newPosition)
		if err != nil {
			return err
		}
	} else if newPosition < oldPosition {
		// If moving note up (decreasing position), shift notes between new and old position down
		shiftQuery := `
			UPDATE note_notebooks
			SET position = position + 1
			WHERE notebook_id = $1
			  AND (section_id = $2 OR (section_id IS NULL AND $2 IS NULL))
			  AND position >= $3 AND position < $4
		`
		_, err = tx.Exec(ctx, shiftQuery, notebookID, sectionID, newPosition, oldPosition)
		if err != nil {
			return err
		}
	}

	// Update target note position
	updateQuery := `UPDATE note_notebooks SET position = $1 WHERE note_id = $2 AND notebook_id = $3`
	_, err = tx.Exec(ctx, updateQuery, newPosition, noteID, notebookID)
	if err != nil {
		return err
	}

	return tx.Commit(ctx)
}
