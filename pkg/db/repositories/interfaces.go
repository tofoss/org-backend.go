package repositories

import (
	"context"
	"tofoss/org-go/pkg/models"

	"github.com/google/uuid"
)

// NoteRepositoryInterface defines the contract for note data access
type NoteRepositoryInterface interface {
	Upsert(ctx context.Context, note models.Note) (models.Note, error)
	FetchNote(ctx context.Context, noteID uuid.UUID) (models.Note, error)
	FetchUsersNote(ctx context.Context, noteID uuid.UUID, userID uuid.UUID) (models.Note, error)
	FetchUsersNotes(ctx context.Context, userID uuid.UUID) ([]models.Note, error)
	FetchNoteWithTags(ctx context.Context, noteID uuid.UUID) (models.Note, error)
	FetchUsersNoteWithTags(ctx context.Context, noteID uuid.UUID, userID uuid.UUID) (models.Note, error)
	SearchNotes(ctx context.Context, userID uuid.UUID, query string, limit int, offset int) ([]models.Note, error)
	GetTagsForNote(ctx context.Context, noteID uuid.UUID) ([]models.Tag, error)
	GetTagsForNotes(ctx context.Context, noteIDs []uuid.UUID) (map[uuid.UUID][]models.Tag, error)
	AssignTagsToNote(ctx context.Context, noteID uuid.UUID, tagIDs []uuid.UUID) error
	RemoveTagFromNote(ctx context.Context, noteID uuid.UUID, tagID uuid.UUID) error
	GetNotebooksForNote(ctx context.Context, noteID uuid.UUID) ([]models.Notebook, error)
	GetRecipesForNote(ctx context.Context, noteID uuid.UUID) ([]models.Recipe, error)
	GetRecipesForNotes(ctx context.Context, noteIDs []uuid.UUID) (map[uuid.UUID][]models.Recipe, error)
	AssignRecipesToNote(ctx context.Context, noteID uuid.UUID, recipeIDs []uuid.UUID) error
	RemoveRecipeFromNote(ctx context.Context, noteID uuid.UUID, recipeID uuid.UUID) error
	FetchNoteWithRecipes(ctx context.Context, noteID uuid.UUID) (models.Note, error)
}

// Ensure NoteRepository implements the interface
var _ NoteRepositoryInterface = (*NoteRepository)(nil)
