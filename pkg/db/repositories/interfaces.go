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
	DeleteNote(ctx context.Context, noteID uuid.UUID) error
}

// Ensure NoteRepository implements the interface
var _ NoteRepositoryInterface = (*NoteRepository)(nil)

// SectionRepositoryInterface defines the contract for section data access
type SectionRepositoryInterface interface {
	Upsert(ctx context.Context, section models.Section) (models.Section, error)
	FetchSection(ctx context.Context, id uuid.UUID) (models.Section, error)
	FetchNotebookSections(ctx context.Context, notebookID uuid.UUID) ([]models.Section, error)
	DeleteSection(ctx context.Context, id uuid.UUID) error
	UpdateSectionPosition(ctx context.Context, id uuid.UUID, newPosition int) error
	UpdateSectionName(ctx context.Context, id uuid.UUID, name string) error
	AssignNoteToSection(ctx context.Context, noteID, notebookID uuid.UUID, sectionID *uuid.UUID) error
	UpdateNotePosition(ctx context.Context, noteID, notebookID uuid.UUID, newPosition int) error
	FetchSectionNotes(ctx context.Context, sectionID uuid.UUID) ([]models.Note, error)
	FetchUnsectionedNotes(ctx context.Context, notebookID uuid.UUID) ([]models.Note, error)
}

// Ensure SectionRepository implements the interface
var _ SectionRepositoryInterface = (*SectionRepository)(nil)

// NotebookRepositoryInterface defines the contract for notebook data access
type NotebookRepositoryInterface interface {
	Upsert(ctx context.Context, notebook models.Notebook) (models.Notebook, error)
	FetchNotebook(ctx context.Context, id uuid.UUID) (models.Notebook, error)
	FetchUserNotebooks(ctx context.Context, userID uuid.UUID) ([]models.Notebook, error)
	Delete(ctx context.Context, id uuid.UUID) error
	AddNoteToNotebook(ctx context.Context, noteID, notebookID uuid.UUID) error
	RemoveNoteFromNotebook(ctx context.Context, noteID, notebookID uuid.UUID) error
	FetchNotebookNotes(ctx context.Context, notebookID uuid.UUID) ([]models.Note, error)
}

// Ensure NotebookRepository implements the interface
var _ NotebookRepositoryInterface = (*NotebookRepository)(nil)

type FileRepositoryInterface interface {
	Insert(ctx context.Context, file models.FileMetadata) (models.FileMetadata, error)
	FetchFileForUser(ctx context.Context, id, userID uuid.UUID) (models.FileMetadata, error)
}

var _ FileRepositoryInterface = (*FileRepository)(nil)

// TreeRepositoryInterface defines the contract for tree data access
type TreeRepositoryInterface interface {
	GetTree(ctx context.Context, userID uuid.UUID) (models.TreeData, error)
}

// Ensure TreeRepository implements the interface
var _ TreeRepositoryInterface = (*TreeRepository)(nil)

// InviteCodeRepositoryInterface defines the contract for invite code data access
type InviteCodeRepositoryInterface interface {
	GetByCode(ctx context.Context, code uuid.UUID) (*models.InviteCode, error)
	IsValid(ctx context.Context, code uuid.UUID) (bool, error)
	MarkUsed(ctx context.Context, code uuid.UUID, userID uuid.UUID) error
}

// Ensure InviteCodeRepository implements the interface
var _ InviteCodeRepositoryInterface = (*InviteCodeRepository)(nil)
