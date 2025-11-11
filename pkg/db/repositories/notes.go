package repositories

import (
	"context"
	"encoding/json"
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
		INSERT INTO notes (id, user_id, title, content, created_at, updated_at, published_at, published, tsv)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8,
			setweight(to_tsvector('english', coalesce($3, '')), 'A') ||
			setweight(to_tsvector('english', coalesce($4, '')), 'B') ||
			setweight(to_tsvector('english', coalesce((
				SELECT string_agg(t.name, ' ')
				FROM tags t
				JOIN note_tags nt ON t.id = nt.tag_id
				WHERE nt.note_id = $1
			), '')), 'A')
		)
        ON CONFLICT (id) DO UPDATE SET
			user_id = EXCLUDED.user_id,
			title = EXCLUDED.title,
			content = EXCLUDED.content,
			updated_at = EXCLUDED.updated_at,
			published_at = EXCLUDED.published_at,
			published = EXCLUDED.published,
			tsv = EXCLUDED.tsv
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

	// Recalculate tsv to include new tags
	updateTSVQuery := `
		UPDATE notes
		SET tsv = (
			setweight(to_tsvector('english', coalesce(title, '')), 'A') ||
			setweight(to_tsvector('english', coalesce(content, '')), 'B') ||
			setweight(to_tsvector('english', coalesce((
				SELECT string_agg(t.name, ' ')
				FROM tags t
				JOIN note_tags nt ON t.id = nt.tag_id
				WHERE nt.note_id = notes.id
			), '')), 'A')
		)
		WHERE id = $1
	`
	_, err = tx.Exec(ctx, updateTSVQuery, noteID)
	if err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// RemoveTagFromNote removes a specific tag from a note
func (r *NoteRepository) RemoveTagFromNote(
	ctx context.Context,
	noteID uuid.UUID,
	tagID uuid.UUID,
) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// Remove tag
	_, err = tx.Exec(ctx, "DELETE FROM note_tags WHERE note_id = $1 AND tag_id = $2", noteID, tagID)
	if err != nil {
		return err
	}

	// Recalculate tsv to reflect removed tag
	updateTSVQuery := `
		UPDATE notes
		SET tsv = (
			setweight(to_tsvector('english', coalesce(title, '')), 'A') ||
			setweight(to_tsvector('english', coalesce(content, '')), 'B') ||
			setweight(to_tsvector('english', coalesce((
				SELECT string_agg(t.name, ' ')
				FROM tags t
				JOIN note_tags nt ON t.id = nt.tag_id
				WHERE nt.note_id = notes.id
			), '')), 'A')
		)
		WHERE id = $1
	`
	_, err = tx.Exec(ctx, updateTSVQuery, noteID)
	if err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// SearchNotes searches notes by text query using full-text search
func (r *NoteRepository) SearchNotes(
	ctx context.Context,
	userID uuid.UUID,
	query string,
	limit int,
	offset int,
) ([]models.Note, error) {
	sqlQuery := `
		SELECT id, user_id, title, content, created_at, updated_at, published_at, published,
		       ts_rank(tsv, plainto_tsquery('english', $2)) as rank
		FROM notes
		WHERE user_id = $1
		  AND ($2 = '' OR tsv @@ plainto_tsquery('english', $2))
		ORDER BY rank DESC, updated_at DESC
		LIMIT $3 OFFSET $4
	`

	rows, err := r.pool.Query(ctx, sqlQuery, userID, query, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var notes []models.Note
	for rows.Next() {
		var note models.Note
		var rank float32
		err := rows.Scan(
			&note.ID, &note.UserID, &note.Title, &note.Content,
			&note.CreatedAt, &note.UpdatedAt, &note.PublishedAt, &note.Published,
			&rank,
		)
		if err != nil {
			return nil, err
		}
		notes = append(notes, note)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Fetch tags for all notes
	if len(notes) > 0 {
		noteIDs := make([]uuid.UUID, len(notes))
		for i, note := range notes {
			noteIDs[i] = note.ID
		}
		tagsMap, err := r.GetTagsForNotes(ctx, noteIDs)
		if err != nil {
			return nil, err
		}
		for i := range notes {
			notes[i].Tags = tagsMap[notes[i].ID]
		}
	}

	return notes, nil
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

// GetNotebooksForNote retrieves all notebooks that contain a specific note
func (r *NoteRepository) GetNotebooksForNote(
	ctx context.Context,
	noteID uuid.UUID,
) ([]models.Notebook, error) {
	query := `
		SELECT n.id, n.user_id, n.name, n.description, n.created_at, n.updated_at 
		FROM notebooks n 
		JOIN note_notebooks nn ON n.id = nn.notebook_id 
		WHERE nn.note_id = $1
		ORDER BY n.name
	`

	rows, err := r.pool.Query(ctx, query, noteID)
	if err != nil {
		return []models.Notebook{}, err
	}
	defer rows.Close()

	return pgx.CollectRows(rows, pgx.RowToStructByName[models.Notebook])
}

// GetRecipesForNote retrieves all recipes associated with a note
func (r *NoteRepository) GetRecipesForNote(
	ctx context.Context,
	noteID uuid.UUID,
) ([]models.Recipe, error) {
	query := `
		SELECT r.id, r.name, r.summary, r.servings, r.prep_time, r.source_url, r.ingredients, r.steps, r.created_at, r.updated_at
		FROM recipes r 
		JOIN note_recipes nr ON r.id = nr.recipe_id 
		WHERE nr.note_id = $1
		ORDER BY r.name
	`

	rows, err := r.pool.Query(ctx, query, noteID)
	if err != nil {
		return []models.Recipe{}, err
	}
	defer rows.Close()

	return r.scanRecipes(rows)
}

// GetRecipesForNotes retrieves all recipes for multiple notes in a single query
func (r *NoteRepository) GetRecipesForNotes(
	ctx context.Context,
	noteIDs []uuid.UUID,
) (map[uuid.UUID][]models.Recipe, error) {
	if len(noteIDs) == 0 {
		return make(map[uuid.UUID][]models.Recipe), nil
	}

	query := `
		SELECT nr.note_id, r.id, r.name, r.summary, r.servings, r.prep_time, r.source_url, r.ingredients, r.steps, r.created_at, r.updated_at
		FROM recipes r 
		JOIN note_recipes nr ON r.id = nr.recipe_id 
		WHERE nr.note_id = ANY($1)
		ORDER BY nr.note_id, r.name
	`

	rows, err := r.pool.Query(ctx, query, noteIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// Create map to group recipes by note ID
	recipesMap := make(map[uuid.UUID][]models.Recipe)
	
	// Initialize empty slices for all note IDs
	for _, noteID := range noteIDs {
		recipesMap[noteID] = []models.Recipe{}
	}

	// Process query results
	for rows.Next() {
		var noteID uuid.UUID
		var recipe models.Recipe
		var ingredientsJSON []byte
		var stepsJSON []byte
		
		err := rows.Scan(
			&noteID,
			&recipe.ID,
			&recipe.Name,
			&recipe.Summary,
			&recipe.Servings,
			&recipe.PrepTime,
			&recipe.SourceURL,
			&ingredientsJSON,
			&stepsJSON,
			&recipe.CreatedAt,
			&recipe.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}

		// Unmarshal JSON fields
		if err := r.unmarshalRecipeJSON(&recipe, ingredientsJSON, stepsJSON); err != nil {
			return nil, err
		}
		
		recipesMap[noteID] = append(recipesMap[noteID], recipe)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return recipesMap, nil
}

// AssignRecipesToNote assigns recipes to a note, replacing any existing recipe relationships
func (r *NoteRepository) AssignRecipesToNote(
	ctx context.Context,
	noteID uuid.UUID,
	recipeIDs []uuid.UUID,
) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// Remove existing recipe relationships
	_, err = tx.Exec(ctx, "DELETE FROM note_recipes WHERE note_id = $1", noteID)
	if err != nil {
		return err
	}

	// Add new recipe relationships
	for _, recipeID := range recipeIDs {
		_, err = tx.Exec(ctx, "INSERT INTO note_recipes (note_id, recipe_id) VALUES ($1, $2)", noteID, recipeID)
		if err != nil {
			return err
		}
	}

	return tx.Commit(ctx)
}

// RemoveRecipeFromNote removes a specific recipe from a note
func (r *NoteRepository) RemoveRecipeFromNote(
	ctx context.Context,
	noteID uuid.UUID,
	recipeID uuid.UUID,
) error {
	_, err := r.pool.Exec(ctx, "DELETE FROM note_recipes WHERE note_id = $1 AND recipe_id = $2", noteID, recipeID)
	return err
}

// FetchNoteWithRecipes retrieves a note with its associated recipes
func (r *NoteRepository) FetchNoteWithRecipes(
	ctx context.Context,
	noteID uuid.UUID,
) (models.Note, error) {
	note, err := r.FetchNote(ctx, noteID)
	if err != nil {
		return models.Note{}, err
	}

	recipes, err := r.GetRecipesForNote(ctx, noteID)
	if err != nil {
		return models.Note{}, err
	}

	// Add recipes to note (we'll need to add a Recipes field to the Note model)
	// For now, this method exists for future use
	_ = recipes

	return note, nil
}

// Helper methods for recipe JSON handling
func (r *NoteRepository) scanRecipes(rows pgx.Rows) ([]models.Recipe, error) {
	var recipes []models.Recipe

	for rows.Next() {
		var recipe models.Recipe
		var ingredientsJSON []byte
		var stepsJSON []byte

		err := rows.Scan(
			&recipe.ID,
			&recipe.Name,
			&recipe.Summary,
			&recipe.Servings,
			&recipe.PrepTime,
			&recipe.SourceURL,
			&ingredientsJSON,
			&stepsJSON,
			&recipe.CreatedAt,
			&recipe.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}

		if err := r.unmarshalRecipeJSON(&recipe, ingredientsJSON, stepsJSON); err != nil {
			return nil, err
		}

		recipes = append(recipes, recipe)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return recipes, nil
}

func (r *NoteRepository) unmarshalRecipeJSON(recipe *models.Recipe, ingredientsJSON, stepsJSON []byte) error {
	if err := json.Unmarshal(ingredientsJSON, &recipe.Ingredients); err != nil {
		return err
	}

	if err := json.Unmarshal(stepsJSON, &recipe.Steps); err != nil {
		return err
	}

	return nil
}
