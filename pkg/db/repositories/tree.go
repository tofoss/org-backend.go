package repositories

import (
	"context"
	"tofoss/org-go/pkg/models"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type TreeRepository struct {
	pool *pgxpool.Pool
}

func NewTreeRepository(pool *pgxpool.Pool) *TreeRepository {
	return &TreeRepository{pool: pool}
}

// GetTree fetches the complete tree structure for a user
func (r *TreeRepository) GetTree(ctx context.Context, userID uuid.UUID) (models.TreeData, error) {
	// Fetch all notebooks for user
	notebooksQuery := `
		SELECT id, name
		FROM notebooks
		WHERE user_id = $1
		ORDER BY updated_at DESC
	`
	notebookRows, err := r.pool.Query(ctx, notebooksQuery, userID)
	if err != nil {
		return models.TreeData{}, err
	}
	defer notebookRows.Close()

	var notebookIDs []uuid.UUID
	notebooksMap := make(map[uuid.UUID]*models.TreeNotebook)

	for notebookRows.Next() {
		var id uuid.UUID
		var name string
		if err := notebookRows.Scan(&id, &name); err != nil {
			return models.TreeData{}, err
		}
		notebookIDs = append(notebookIDs, id)
		notebooksMap[id] = &models.TreeNotebook{
			ID:          id,
			Title:       name,
			Sections:    []models.TreeSection{},
			Unsectioned: []models.TreeNote{},
		}
	}

	if len(notebookIDs) > 0 {
		// Fetch all sections for these notebooks
		sectionsQuery := `
			SELECT id, notebook_id, name
			FROM sections
			WHERE notebook_id = ANY($1)
			ORDER BY position ASC
		`
		sectionRows, err := r.pool.Query(ctx, sectionsQuery, notebookIDs)
		if err != nil {
			return models.TreeData{}, err
		}
		defer sectionRows.Close()

		var sectionIDs []uuid.UUID
		sectionToNotebook := make(map[uuid.UUID]uuid.UUID)

		for sectionRows.Next() {
			var id, notebookID uuid.UUID
			var name string
			if err := sectionRows.Scan(&id, &notebookID, &name); err != nil {
				return models.TreeData{}, err
			}
			sectionIDs = append(sectionIDs, id)
			section := models.TreeSection{
				ID:    id,
				Title: name,
				Notes: []models.TreeNote{},
			}
			sectionToNotebook[id] = notebookID
			notebooksMap[notebookID].Sections = append(notebooksMap[notebookID].Sections, section)
		}

		// Fetch all notes in sections
		if len(sectionIDs) > 0 {
			sectionNotesQuery := `
				SELECT n.id, n.title, nn.section_id
				FROM notes n
				JOIN note_notebooks nn ON n.id = nn.note_id
				WHERE nn.section_id = ANY($1)
				ORDER BY nn.position ASC
			`
			noteRows, err := r.pool.Query(ctx, sectionNotesQuery, sectionIDs)
			if err != nil {
				return models.TreeData{}, err
			}
			defer noteRows.Close()

			// Build map of section notes
			sectionNotesMap := make(map[uuid.UUID][]models.TreeNote)
			for noteRows.Next() {
				var noteID uuid.UUID
				var title string
				var sectionID uuid.UUID
				if err := noteRows.Scan(&noteID, &title, &sectionID); err != nil {
					return models.TreeData{}, err
				}
				sectionNotesMap[sectionID] = append(sectionNotesMap[sectionID], models.TreeNote{
					ID:    noteID,
					Title: title,
				})
			}

			// Update sections with their notes
			for notebookID, notebook := range notebooksMap {
				for i := range notebook.Sections {
					notebook.Sections[i].Notes = sectionNotesMap[notebook.Sections[i].ID]
					if notebook.Sections[i].Notes == nil {
						notebook.Sections[i].Notes = []models.TreeNote{}
					}
				}
				notebooksMap[notebookID] = notebook
			}
		}

		// Fetch unsectioned notes for each notebook
		unsectionedQuery := `
			SELECT n.id, n.title, nn.notebook_id
			FROM notes n
			JOIN note_notebooks nn ON n.id = nn.note_id
			WHERE nn.notebook_id = ANY($1) AND nn.section_id IS NULL
			ORDER BY nn.position ASC
		`
		unsectionedRows, err := r.pool.Query(ctx, unsectionedQuery, notebookIDs)
		if err != nil {
			return models.TreeData{}, err
		}
		defer unsectionedRows.Close()

		for unsectionedRows.Next() {
			var noteID, notebookID uuid.UUID
			var title string
			if err := unsectionedRows.Scan(&noteID, &title, &notebookID); err != nil {
				return models.TreeData{}, err
			}
			notebooksMap[notebookID].Unsectioned = append(notebooksMap[notebookID].Unsectioned, models.TreeNote{
				ID:    noteID,
				Title: title,
			})
		}
	}

	// Fetch unassigned notes (notes not in any notebook)
	unassignedQuery := `
		SELECT n.id, n.title
		FROM notes n
		WHERE n.user_id = $1
		AND NOT EXISTS (
			SELECT 1 FROM note_notebooks nn WHERE nn.note_id = n.id
		)
		ORDER BY n.updated_at DESC
	`
	unassignedRows, err := r.pool.Query(ctx, unassignedQuery, userID)
	if err != nil {
		return models.TreeData{}, err
	}
	defer unassignedRows.Close()

	var unassigned []models.TreeNote
	for unassignedRows.Next() {
		var id uuid.UUID
		var title string
		if err := unassignedRows.Scan(&id, &title); err != nil {
			return models.TreeData{}, err
		}
		unassigned = append(unassigned, models.TreeNote{ID: id, Title: title})
	}

	// Build response
	var notebooks []models.TreeNotebook
	for _, id := range notebookIDs {
		notebooks = append(notebooks, *notebooksMap[id])
	}

	if notebooks == nil {
		notebooks = []models.TreeNotebook{}
	}
	if unassigned == nil {
		unassigned = []models.TreeNote{}
	}

	return models.TreeData{
		Notebooks:  notebooks,
		Unassigned: unassigned,
	}, nil
}
