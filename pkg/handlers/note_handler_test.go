package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"tofoss/org-go/pkg/db/repositories"
	"tofoss/org-go/pkg/models"
	"tofoss/org-go/pkg/utils"

	"github.com/google/uuid"
)

// mockNoteRepository is a mock implementation of NoteRepositoryInterface for testing
type mockNoteRepository struct {
	searchNotesFunc func(ctx context.Context, userID uuid.UUID, query string, limit int, offset int) ([]models.Note, error)
}

// DeleteNote implements repositories.NoteRepositoryInterface.
func (m *mockNoteRepository) DeleteNote(ctx context.Context, noteID uuid.UUID) error {
	panic("unimplemented")
}

// Implement all interface methods - most will panic if called unexpectedly
func (m *mockNoteRepository) Upsert(ctx context.Context, note models.Note) (models.Note, error) {
	panic("Upsert not mocked")
}

func (m *mockNoteRepository) FetchNote(ctx context.Context, noteID uuid.UUID) (models.Note, error) {
	panic("FetchNote not mocked")
}

func (m *mockNoteRepository) FetchUsersNote(ctx context.Context, noteID uuid.UUID, userID uuid.UUID) (models.Note, error) {
	panic("FetchUsersNote not mocked")
}

func (m *mockNoteRepository) FetchUsersNotes(ctx context.Context, userID uuid.UUID) ([]models.Note, error) {
	panic("FetchUsersNotes not mocked")
}

func (m *mockNoteRepository) FetchNoteWithTags(ctx context.Context, noteID uuid.UUID) (models.Note, error) {
	panic("FetchNoteWithTags not mocked")
}

func (m *mockNoteRepository) FetchUsersNoteWithTags(ctx context.Context, noteID uuid.UUID, userID uuid.UUID) (models.Note, error) {
	panic("FetchUsersNoteWithTags not mocked")
}

func (m *mockNoteRepository) SearchNotes(ctx context.Context, userID uuid.UUID, query string, limit int, offset int) ([]models.Note, error) {
	if m.searchNotesFunc != nil {
		return m.searchNotesFunc(ctx, userID, query, limit, offset)
	}
	return nil, errors.New("SearchNotes not mocked")
}

func (m *mockNoteRepository) GetTagsForNote(ctx context.Context, noteID uuid.UUID) ([]models.Tag, error) {
	panic("GetTagsForNote not mocked")
}

func (m *mockNoteRepository) GetTagsForNotes(ctx context.Context, noteIDs []uuid.UUID) (map[uuid.UUID][]models.Tag, error) {
	panic("GetTagsForNotes not mocked")
}

func (m *mockNoteRepository) AssignTagsToNote(ctx context.Context, noteID uuid.UUID, tagIDs []uuid.UUID) error {
	panic("AssignTagsToNote not mocked")
}

func (m *mockNoteRepository) RemoveTagFromNote(ctx context.Context, noteID uuid.UUID, tagID uuid.UUID) error {
	panic("RemoveTagFromNote not mocked")
}

func (m *mockNoteRepository) GetNotebooksForNote(ctx context.Context, noteID uuid.UUID) ([]models.Notebook, error) {
	panic("GetNotebooksForNote not mocked")
}

func (m *mockNoteRepository) GetRecipesForNote(ctx context.Context, noteID uuid.UUID) ([]models.Recipe, error) {
	panic("GetRecipesForNote not mocked")
}

func (m *mockNoteRepository) GetRecipesForNotes(ctx context.Context, noteIDs []uuid.UUID) (map[uuid.UUID][]models.Recipe, error) {
	panic("GetRecipesForNotes not mocked")
}

func (m *mockNoteRepository) AssignRecipesToNote(ctx context.Context, noteID uuid.UUID, recipeIDs []uuid.UUID) error {
	panic("AssignRecipesToNote not mocked")
}

func (m *mockNoteRepository) RemoveRecipeFromNote(ctx context.Context, noteID uuid.UUID, recipeID uuid.UUID) error {
	panic("RemoveRecipeFromNote not mocked")
}

func (m *mockNoteRepository) FetchNoteWithRecipes(ctx context.Context, noteID uuid.UUID) (models.Note, error) {
	panic("FetchNoteWithRecipes not mocked")
}

// Ensure mockNoteRepository implements the interface
var _ repositories.NoteRepositoryInterface = (*mockNoteRepository)(nil)

func TestSearchNotes(t *testing.T) {
	// Test user ID
	testUserID := uuid.New()

	tests := []struct {
		name           string
		queryParams    string
		mockResponse   []models.Note
		mockError      error
		expectedStatus int
		expectedCount  int
		validateResult func(t *testing.T, notes []models.Note)
		checkMockCalls func(t *testing.T, query string, limit int, offset int)
	}{
		{
			name:        "Empty query returns all notes",
			queryParams: "",
			mockResponse: []models.Note{
				{ID: uuid.New(), Title: "Note 1", Content: "Content 1"},
				{ID: uuid.New(), Title: "Note 2", Content: "Content 2"},
			},
			expectedStatus: http.StatusOK,
			expectedCount:  2,
			checkMockCalls: func(t *testing.T, query string, limit int, offset int) {
				if query != "" {
					t.Errorf("Expected empty query, got '%s'", query)
				}
				if limit != 50 {
					t.Errorf("Expected default limit 50, got %d", limit)
				}
				if offset != 0 {
					t.Errorf("Expected default offset 0, got %d", offset)
				}
			},
		},
		{
			name:        "Valid query with default pagination",
			queryParams: "?q=recipe",
			mockResponse: []models.Note{
				{
					ID:      uuid.New(),
					UserID:  testUserID,
					Title:   "Chicken Recipe",
					Content: "A delicious chicken recipe",
					Tags: []models.Tag{
						{ID: uuid.New(), Name: "recipe"},
					},
				},
			},
			expectedStatus: http.StatusOK,
			expectedCount:  1,
			checkMockCalls: func(t *testing.T, query string, limit int, offset int) {
				if query != "recipe" {
					t.Errorf("Expected query 'recipe', got '%s'", query)
				}
				if limit != 50 {
					t.Errorf("Expected default limit 50, got %d", limit)
				}
				if offset != 0 {
					t.Errorf("Expected default offset 0, got %d", offset)
				}
			},
		},
		{
			name:        "Custom pagination parameters",
			queryParams: "?q=test&limit=10&offset=20",
			mockResponse: []models.Note{
				{ID: uuid.New(), Title: "Test 1", Content: "Content 1"},
				{ID: uuid.New(), Title: "Test 2", Content: "Content 2"},
			},
			expectedStatus: http.StatusOK,
			expectedCount:  2,
			checkMockCalls: func(t *testing.T, query string, limit int, offset int) {
				if query != "test" {
					t.Errorf("Expected query 'test', got '%s'", query)
				}
				if limit != 10 {
					t.Errorf("Expected limit 10, got %d", limit)
				}
				if offset != 20 {
					t.Errorf("Expected offset 20, got %d", offset)
				}
			},
		},
		{
			name:           "Invalid limit uses default",
			queryParams:    "?q=test&limit=200",
			mockResponse:   []models.Note{{ID: uuid.New(), Title: "Test", Content: "Content"}},
			expectedStatus: http.StatusOK,
			expectedCount:  1,
			checkMockCalls: func(t *testing.T, query string, limit int, offset int) {
				// limit > 100 should be rejected and use default
				if limit != 50 {
					t.Errorf("Expected default limit 50 for invalid value, got %d", limit)
				}
			},
		},
		{
			name:           "Repository error returns 500",
			queryParams:    "?q=error",
			mockResponse:   nil,
			mockError:      errors.New("database error"),
			expectedStatus: http.StatusInternalServerError,
			expectedCount:  0,
		},
		{
			name:           "No results found returns empty array",
			queryParams:    "?q=nonexistent",
			mockResponse:   []models.Note{},
			expectedStatus: http.StatusOK,
			expectedCount:  0,
		},
		{
			name:        "Search returns notes with tags",
			queryParams: "?q=quick",
			mockResponse: []models.Note{
				{
					ID:      uuid.New(),
					UserID:  testUserID,
					Title:   "Fast Recipe",
					Content: "A quick meal",
					Tags: []models.Tag{
						{ID: uuid.New(), Name: "quick-meals"},
						{ID: uuid.New(), Name: "dinner"},
					},
				},
			},
			expectedStatus: http.StatusOK,
			expectedCount:  1,
			validateResult: func(t *testing.T, notes []models.Note) {
				if len(notes) != 1 {
					t.Fatalf("Expected 1 note, got %d", len(notes))
				}
				if len(notes[0].Tags) != 2 {
					t.Errorf("Expected 2 tags, got %d", len(notes[0].Tags))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Track mock calls
			var capturedQuery string
			var capturedLimit int
			var capturedOffset int
			mockCalled := false

			// Create mock repository
			mockRepo := &mockNoteRepository{
				searchNotesFunc: func(ctx context.Context, userID uuid.UUID, query string, limit int, offset int) ([]models.Note, error) {
					mockCalled = true
					capturedQuery = query
					capturedLimit = limit
					capturedOffset = offset
					return tt.mockResponse, tt.mockError
				},
			}

			// Create handler with mock
			handler := NewNoteHandler(mockRepo)

			// Create request
			req := httptest.NewRequest(http.MethodGet, "/notes/search"+tt.queryParams, nil)

			// Add user context (simulating JWT middleware)
			ctx := context.WithValue(req.Context(), utils.UserIDKey, testUserID)
			ctx = context.WithValue(ctx, utils.UsernameKey, "testuser")
			req = req.WithContext(ctx)

			// Create response recorder
			w := httptest.NewRecorder()

			// Call handler
			handler.SearchNotes(w, req)

			// Check status code
			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			// For successful responses, validate the result
			if tt.expectedStatus == http.StatusOK {
				var notes []models.Note
				if err := json.NewDecoder(w.Body).Decode(&notes); err != nil {
					t.Fatalf("Failed to decode response: %v", err)
				}

				if len(notes) != tt.expectedCount {
					t.Errorf("Expected %d notes, got %d", tt.expectedCount, len(notes))
				}

				// Run custom validation if provided
				if tt.validateResult != nil {
					tt.validateResult(t, notes)
				}

				// Check mock was called correctly
				if mockCalled && tt.checkMockCalls != nil {
					tt.checkMockCalls(t, capturedQuery, capturedLimit, capturedOffset)
				}
			}
		})
	}
}

func TestSearchNotesWithoutAuth(t *testing.T) {
	mockRepo := &mockNoteRepository{}
	handler := NewNoteHandler(mockRepo)

	req := httptest.NewRequest(http.MethodGet, "/notes/search?q=test", nil)
	// No user context added - simulating missing auth

	w := httptest.NewRecorder()
	handler.SearchNotes(w, req)

	// Should return 500 (internal server error) when user context is missing
	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status %d for missing auth, got %d", http.StatusInternalServerError, w.Code)
	}
}
