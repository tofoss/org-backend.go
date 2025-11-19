package handlers

import (
	"encoding/json"
	"net/http"
	"tofoss/org-go/pkg/handlers/errors"
	"tofoss/org-go/pkg/utils"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TreeNote represents a minimal note for the tree view
type TreeNote struct {
	ID    uuid.UUID `json:"id"`
	Title string    `json:"title"`
}

// TreeSection represents a section with its notes for the tree view
type TreeSection struct {
	ID    uuid.UUID  `json:"id"`
	Title string     `json:"title"`
	Notes []TreeNote `json:"notes"`
}

// TreeNotebook represents a notebook with sections and unsectioned notes for the tree view
type TreeNotebook struct {
	ID          uuid.UUID     `json:"id"`
	Title       string        `json:"title"`
	Sections    []TreeSection `json:"sections"`
	Unsectioned []TreeNote    `json:"unsectioned"`
}

// TreeData represents the complete tree structure
type TreeData struct {
	Notebooks  []TreeNotebook `json:"notebooks"`
	Unassigned []TreeNote     `json:"unassigned"`
}

type TreeHandler struct {
	pool *pgxpool.Pool
}

func NewTreeHandler(pool *pgxpool.Pool) TreeHandler {
	return TreeHandler{pool: pool}
}

func (h *TreeHandler) GetTree(w http.ResponseWriter, r *http.Request) {
	userID, _, err := utils.UserContext(r)
	if err != nil {
		errors.InternalServerError(w)
		return
	}

	ctx := r.Context()

	// Fetch all notebooks for user
	notebooksQuery := `
		SELECT id, name
		FROM notebooks
		WHERE user_id = $1
		ORDER BY updated_at DESC
	`
	notebookRows, err := h.pool.Query(ctx, notebooksQuery, userID)
	if err != nil {
		errors.InternalServerError(w)
		return
	}
	defer notebookRows.Close()

	var notebookIDs []uuid.UUID
	notebooksMap := make(map[uuid.UUID]*TreeNotebook)

	for notebookRows.Next() {
		var id uuid.UUID
		var name string
		if err := notebookRows.Scan(&id, &name); err != nil {
			errors.InternalServerError(w)
			return
		}
		notebookIDs = append(notebookIDs, id)
		notebooksMap[id] = &TreeNotebook{
			ID:          id,
			Title:       name,
			Sections:    []TreeSection{},
			Unsectioned: []TreeNote{},
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
		sectionRows, err := h.pool.Query(ctx, sectionsQuery, notebookIDs)
		if err != nil {
			errors.InternalServerError(w)
			return
		}
		defer sectionRows.Close()

		var sectionIDs []uuid.UUID
		sectionsMap := make(map[uuid.UUID]*TreeSection)
		sectionToNotebook := make(map[uuid.UUID]uuid.UUID)

		for sectionRows.Next() {
			var id, notebookID uuid.UUID
			var name string
			if err := sectionRows.Scan(&id, &notebookID, &name); err != nil {
				errors.InternalServerError(w)
				return
			}
			sectionIDs = append(sectionIDs, id)
			section := &TreeSection{
				ID:    id,
				Title: name,
				Notes: []TreeNote{},
			}
			sectionsMap[id] = section
			sectionToNotebook[id] = notebookID
			notebooksMap[notebookID].Sections = append(notebooksMap[notebookID].Sections, *section)
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
			noteRows, err := h.pool.Query(ctx, sectionNotesQuery, sectionIDs)
			if err != nil {
				errors.InternalServerError(w)
				return
			}
			defer noteRows.Close()

			// Build map of section notes
			sectionNotesMap := make(map[uuid.UUID][]TreeNote)
			for noteRows.Next() {
				var noteID uuid.UUID
				var title string
				var sectionID uuid.UUID
				if err := noteRows.Scan(&noteID, &title, &sectionID); err != nil {
					errors.InternalServerError(w)
					return
				}
				sectionNotesMap[sectionID] = append(sectionNotesMap[sectionID], TreeNote{
					ID:    noteID,
					Title: title,
				})
			}

			// Update sections with their notes
			for notebookID, notebook := range notebooksMap {
				for i := range notebook.Sections {
					notebook.Sections[i].Notes = sectionNotesMap[notebook.Sections[i].ID]
					if notebook.Sections[i].Notes == nil {
						notebook.Sections[i].Notes = []TreeNote{}
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
		unsectionedRows, err := h.pool.Query(ctx, unsectionedQuery, notebookIDs)
		if err != nil {
			errors.InternalServerError(w)
			return
		}
		defer unsectionedRows.Close()

		for unsectionedRows.Next() {
			var noteID, notebookID uuid.UUID
			var title string
			if err := unsectionedRows.Scan(&noteID, &title, &notebookID); err != nil {
				errors.InternalServerError(w)
				return
			}
			notebooksMap[notebookID].Unsectioned = append(notebooksMap[notebookID].Unsectioned, TreeNote{
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
	unassignedRows, err := h.pool.Query(ctx, unassignedQuery, userID)
	if err != nil {
		errors.InternalServerError(w)
		return
	}
	defer unassignedRows.Close()

	var unassigned []TreeNote
	for unassignedRows.Next() {
		var id uuid.UUID
		var title string
		if err := unassignedRows.Scan(&id, &title); err != nil {
			errors.InternalServerError(w)
			return
		}
		unassigned = append(unassigned, TreeNote{ID: id, Title: title})
	}

	// Build response
	var notebooks []TreeNotebook
	for _, id := range notebookIDs {
		notebooks = append(notebooks, *notebooksMap[id])
	}

	if notebooks == nil {
		notebooks = []TreeNotebook{}
	}
	if unassigned == nil {
		unassigned = []TreeNote{}
	}

	response := TreeData{
		Notebooks:  notebooks,
		Unassigned: unassigned,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}
