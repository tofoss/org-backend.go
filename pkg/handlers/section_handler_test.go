package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
	"tofoss/org-go/pkg/db/repositories"
	"tofoss/org-go/pkg/handlers/requests"
	"tofoss/org-go/pkg/models"
	"tofoss/org-go/pkg/utils"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// mockSectionRepository is a mock implementation of SectionRepository for testing
type mockSectionRepository struct {
	fetchSectionFunc         func(ctx context.Context, id uuid.UUID) (models.Section, error)
	fetchNotebookSectionsFunc func(ctx context.Context, notebookID uuid.UUID) ([]models.Section, error)
	upsertFunc               func(ctx context.Context, section models.Section) (models.Section, error)
	deleteSectionFunc        func(ctx context.Context, id uuid.UUID) error
	updateSectionPositionFunc func(ctx context.Context, id uuid.UUID, newPosition int) error
	updateSectionNameFunc    func(ctx context.Context, id uuid.UUID, name string) error
	assignNoteToSectionFunc  func(ctx context.Context, noteID, notebookID uuid.UUID, sectionID *uuid.UUID) error
	fetchSectionNotesFunc    func(ctx context.Context, sectionID uuid.UUID) ([]models.Note, error)
	fetchUnsectionedNotesFunc func(ctx context.Context, notebookID uuid.UUID) ([]models.Note, error)
}

func (m *mockSectionRepository) FetchSection(ctx context.Context, id uuid.UUID) (models.Section, error) {
	if m.fetchSectionFunc != nil {
		return m.fetchSectionFunc(ctx, id)
	}
	panic("FetchSection not mocked")
}

func (m *mockSectionRepository) FetchNotebookSections(ctx context.Context, notebookID uuid.UUID) ([]models.Section, error) {
	if m.fetchNotebookSectionsFunc != nil {
		return m.fetchNotebookSectionsFunc(ctx, notebookID)
	}
	panic("FetchNotebookSections not mocked")
}

func (m *mockSectionRepository) Upsert(ctx context.Context, section models.Section) (models.Section, error) {
	if m.upsertFunc != nil {
		return m.upsertFunc(ctx, section)
	}
	panic("Upsert not mocked")
}

func (m *mockSectionRepository) DeleteSection(ctx context.Context, id uuid.UUID) error {
	if m.deleteSectionFunc != nil {
		return m.deleteSectionFunc(ctx, id)
	}
	panic("DeleteSection not mocked")
}

func (m *mockSectionRepository) UpdateSectionPosition(ctx context.Context, id uuid.UUID, newPosition int) error {
	if m.updateSectionPositionFunc != nil {
		return m.updateSectionPositionFunc(ctx, id, newPosition)
	}
	panic("UpdateSectionPosition not mocked")
}

func (m *mockSectionRepository) UpdateSectionName(ctx context.Context, id uuid.UUID, name string) error {
	if m.updateSectionNameFunc != nil {
		return m.updateSectionNameFunc(ctx, id, name)
	}
	panic("UpdateSectionName not mocked")
}

func (m *mockSectionRepository) AssignNoteToSection(ctx context.Context, noteID, notebookID uuid.UUID, sectionID *uuid.UUID) error {
	if m.assignNoteToSectionFunc != nil {
		return m.assignNoteToSectionFunc(ctx, noteID, notebookID, sectionID)
	}
	panic("AssignNoteToSection not mocked")
}

func (m *mockSectionRepository) FetchSectionNotes(ctx context.Context, sectionID uuid.UUID) ([]models.Note, error) {
	if m.fetchSectionNotesFunc != nil {
		return m.fetchSectionNotesFunc(ctx, sectionID)
	}
	panic("FetchSectionNotes not mocked")
}

func (m *mockSectionRepository) FetchUnsectionedNotes(ctx context.Context, notebookID uuid.UUID) ([]models.Note, error) {
	if m.fetchUnsectionedNotesFunc != nil {
		return m.fetchUnsectionedNotesFunc(ctx, notebookID)
	}
	panic("FetchUnsectionedNotes not mocked")
}

// mockNotebookRepository is a mock implementation for notebook ownership verification
type mockNotebookRepository struct {
	fetchNotebookFunc func(ctx context.Context, id uuid.UUID) (models.Notebook, error)
}

func (m *mockNotebookRepository) FetchNotebook(ctx context.Context, id uuid.UUID) (models.Notebook, error) {
	if m.fetchNotebookFunc != nil {
		return m.fetchNotebookFunc(ctx, id)
	}
	panic("FetchNotebook not mocked")
}

func (m *mockNotebookRepository) Upsert(ctx context.Context, notebook models.Notebook) (models.Notebook, error) {
	panic("Upsert not mocked")
}

func (m *mockNotebookRepository) FetchUserNotebooks(ctx context.Context, userID uuid.UUID) ([]models.Notebook, error) {
	panic("FetchUserNotebooks not mocked")
}

func (m *mockNotebookRepository) Delete(ctx context.Context, id uuid.UUID) error {
	panic("Delete not mocked")
}

func (m *mockNotebookRepository) AddNoteToNotebook(ctx context.Context, noteID, notebookID uuid.UUID) error {
	panic("AddNoteToNotebook not mocked")
}

func (m *mockNotebookRepository) RemoveNoteFromNotebook(ctx context.Context, noteID, notebookID uuid.UUID) error {
	panic("RemoveNoteFromNotebook not mocked")
}

func (m *mockNotebookRepository) FetchNotebookNotes(ctx context.Context, notebookID uuid.UUID) ([]models.Note, error) {
	panic("FetchNotebookNotes not mocked")
}

// Ensure mocks implement the interfaces
var _ repositories.NotebookRepositoryInterface = (*mockNotebookRepository)(nil)

// Test FetchSection
func TestFetchSection(t *testing.T) {
	testUserID := uuid.New()
	testNotebookID := uuid.New()
	testSectionID := uuid.New()
	anotherUserID := uuid.New()

	tests := []struct {
		name               string
		sectionID          string
		mockSection        models.Section
		mockSectionError   error
		mockNotebook       models.Notebook
		mockNotebookError  error
		expectedStatus     int
		expectSectionFetch bool
	}{
		{
			name:      "Successfully fetch section with ownership",
			sectionID: testSectionID.String(),
			mockSection: models.Section{
				ID:         testSectionID,
				NotebookID: testNotebookID,
				Name:       "Introduction",
				Position:   0,
				CreatedAt:  time.Now(),
				UpdatedAt:  time.Now(),
			},
			mockNotebook: models.Notebook{
				ID:     testNotebookID,
				UserID: testUserID,
				Name:   "Test Notebook",
			},
			expectedStatus:     http.StatusOK,
			expectSectionFetch: true,
		},
		{
			name:      "Unauthorized - different user owns notebook",
			sectionID: testSectionID.String(),
			mockSection: models.Section{
				ID:         testSectionID,
				NotebookID: testNotebookID,
				Name:       "Introduction",
			},
			mockNotebook: models.Notebook{
				ID:     testNotebookID,
				UserID: anotherUserID, // Different user
				Name:   "Test Notebook",
			},
			expectedStatus:     http.StatusForbidden,
			expectSectionFetch: false,
		},
		{
			name:             "Section not found",
			sectionID:        testSectionID.String(),
			mockSectionError: pgx.ErrNoRows,
			expectedStatus:   http.StatusForbidden,
		},
		{
			name:      "Invalid section ID",
			sectionID: "invalid-uuid",
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sectionFetched := false
			mockSectionRepo := &mockSectionRepository{
				fetchSectionFunc: func(ctx context.Context, id uuid.UUID) (models.Section, error) {
					sectionFetched = true
					if tt.mockSectionError != nil {
						return models.Section{}, tt.mockSectionError
					}
					return tt.mockSection, nil
				},
			}

			mockNotebookRepo := &mockNotebookRepository{
				fetchNotebookFunc: func(ctx context.Context, id uuid.UUID) (models.Notebook, error) {
					if tt.mockNotebookError != nil {
						return models.Notebook{}, tt.mockNotebookError
					}
					return tt.mockNotebook, nil
				},
			}

			handler := NewSectionHandler(mockSectionRepo, mockNotebookRepo)

			// Create request with chi URL params
			req := httptest.NewRequest(http.MethodGet, "/sections/"+tt.sectionID, nil)
			rctx := chi.NewRouteContext()
			rctx.URLParams.Add("id", tt.sectionID)
			req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

			// Add user context
			ctx := context.WithValue(req.Context(), utils.UserIDKey, testUserID)
			ctx = context.WithValue(ctx, utils.UsernameKey, "testuser")
			req = req.WithContext(ctx)

			w := httptest.NewRecorder()
			handler.FetchSection(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if tt.expectSectionFetch && !sectionFetched {
				t.Error("Expected section to be fetched twice (ownership + actual fetch)")
			}

			if tt.expectedStatus == http.StatusOK {
				var section models.Section
				if err := json.NewDecoder(w.Body).Decode(&section); err != nil {
					t.Fatalf("Failed to decode response: %v", err)
				}
				if section.ID != testSectionID {
					t.Errorf("Expected section ID %s, got %s", testSectionID, section.ID)
				}
			}
		})
	}
}

// Test ListNotebookSections
func TestListNotebookSections(t *testing.T) {
	testUserID := uuid.New()
	testNotebookID := uuid.New()
	anotherUserID := uuid.New()

	tests := []struct {
		name             string
		notebookID       string
		mockNotebook     models.Notebook
		mockSections     []models.Section
		mockSectionsErr  error
		expectedStatus   int
		expectedCount    int
	}{
		{
			name:       "Successfully list sections",
			notebookID: testNotebookID.String(),
			mockNotebook: models.Notebook{
				ID:     testNotebookID,
				UserID: testUserID,
			},
			mockSections: []models.Section{
				{ID: uuid.New(), NotebookID: testNotebookID, Name: "Section 1", Position: 0},
				{ID: uuid.New(), NotebookID: testNotebookID, Name: "Section 2", Position: 1},
				{ID: uuid.New(), NotebookID: testNotebookID, Name: "Section 3", Position: 2},
			},
			expectedStatus: http.StatusOK,
			expectedCount:  3,
		},
		{
			name:       "Empty sections list",
			notebookID: testNotebookID.String(),
			mockNotebook: models.Notebook{
				ID:     testNotebookID,
				UserID: testUserID,
			},
			mockSections:   []models.Section{},
			expectedStatus: http.StatusOK,
			expectedCount:  0,
		},
		{
			name:       "Unauthorized - different user",
			notebookID: testNotebookID.String(),
			mockNotebook: models.Notebook{
				ID:     testNotebookID,
				UserID: anotherUserID,
			},
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "Invalid notebook ID",
			notebookID:     "invalid-uuid",
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSectionRepo := &mockSectionRepository{
				fetchNotebookSectionsFunc: func(ctx context.Context, notebookID uuid.UUID) ([]models.Section, error) {
					if tt.mockSectionsErr != nil {
						return nil, tt.mockSectionsErr
					}
					return tt.mockSections, nil
				},
			}

			mockNotebookRepo := &mockNotebookRepository{
				fetchNotebookFunc: func(ctx context.Context, id uuid.UUID) (models.Notebook, error) {
					return tt.mockNotebook, nil
				},
			}

			handler := NewSectionHandler(mockSectionRepo, mockNotebookRepo)

			req := httptest.NewRequest(http.MethodGet, "/notebooks/"+tt.notebookID+"/sections", nil)
			rctx := chi.NewRouteContext()
			rctx.URLParams.Add("id", tt.notebookID)
			req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

			ctx := context.WithValue(req.Context(), utils.UserIDKey, testUserID)
			ctx = context.WithValue(ctx, utils.UsernameKey, "testuser")
			req = req.WithContext(ctx)

			w := httptest.NewRecorder()
			handler.ListNotebookSections(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if tt.expectedStatus == http.StatusOK {
				var sections []models.Section
				if err := json.NewDecoder(w.Body).Decode(&sections); err != nil {
					t.Fatalf("Failed to decode response: %v", err)
				}
				if len(sections) != tt.expectedCount {
					t.Errorf("Expected %d sections, got %d", tt.expectedCount, len(sections))
				}
			}
		})
	}
}

// Test PostSection
func TestPostSection(t *testing.T) {
	testUserID := uuid.New()
	testNotebookID := uuid.New()
	testSectionID := uuid.New()
	anotherUserID := uuid.New()

	tests := []struct {
		name           string
		requestBody    models.Section
		mockNotebook   models.Notebook
		mockUpserted   models.Section
		mockUpsertErr  error
		expectedStatus int
	}{
		{
			name: "Successfully create new section",
			requestBody: models.Section{
				NotebookID: testNotebookID,
				Name:       "New Section",
				Position:   0,
			},
			mockNotebook: models.Notebook{
				ID:     testNotebookID,
				UserID: testUserID,
			},
			mockUpserted: models.Section{
				ID:         uuid.New(),
				NotebookID: testNotebookID,
				Name:       "New Section",
				Position:   0,
				CreatedAt:  time.Now(),
				UpdatedAt:  time.Now(),
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "Successfully update existing section",
			requestBody: models.Section{
				ID:         testSectionID,
				NotebookID: testNotebookID,
				Name:       "Updated Section",
				Position:   1,
			},
			mockNotebook: models.Notebook{
				ID:     testNotebookID,
				UserID: testUserID,
			},
			mockUpserted: models.Section{
				ID:         testSectionID,
				NotebookID: testNotebookID,
				Name:       "Updated Section",
				Position:   1,
				UpdatedAt:  time.Now(),
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "Unauthorized - different user owns notebook",
			requestBody: models.Section{
				NotebookID: testNotebookID,
				Name:       "New Section",
			},
			mockNotebook: models.Notebook{
				ID:     testNotebookID,
				UserID: anotherUserID,
			},
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSectionRepo := &mockSectionRepository{
				fetchSectionFunc: func(ctx context.Context, id uuid.UUID) (models.Section, error) {
					// For update case
					return models.Section{
						ID:         id,
						NotebookID: testNotebookID,
					}, nil
				},
				upsertFunc: func(ctx context.Context, section models.Section) (models.Section, error) {
					if tt.mockUpsertErr != nil {
						return models.Section{}, tt.mockUpsertErr
					}
					return tt.mockUpserted, nil
				},
			}

			mockNotebookRepo := &mockNotebookRepository{
				fetchNotebookFunc: func(ctx context.Context, id uuid.UUID) (models.Notebook, error) {
					return tt.mockNotebook, nil
				},
			}

			handler := NewSectionHandler(mockSectionRepo, mockNotebookRepo)

			body, _ := json.Marshal(tt.requestBody)
			req := httptest.NewRequest(http.MethodPost, "/sections", bytes.NewReader(body))

			ctx := context.WithValue(req.Context(), utils.UserIDKey, testUserID)
			ctx = context.WithValue(ctx, utils.UsernameKey, "testuser")
			req = req.WithContext(ctx)

			w := httptest.NewRecorder()
			handler.PostSection(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if tt.expectedStatus == http.StatusOK {
				var section models.Section
				if err := json.NewDecoder(w.Body).Decode(&section); err != nil {
					t.Fatalf("Failed to decode response: %v", err)
				}
				if section.Name != tt.mockUpserted.Name {
					t.Errorf("Expected section name %s, got %s", tt.mockUpserted.Name, section.Name)
				}
			}
		})
	}
}

// Test DeleteSection
func TestDeleteSection(t *testing.T) {
	testUserID := uuid.New()
	testNotebookID := uuid.New()
	testSectionID := uuid.New()
	anotherUserID := uuid.New()

	tests := []struct {
		name             string
		sectionID        string
		mockSection      models.Section
		mockNotebook     models.Notebook
		mockDeleteErr    error
		expectedStatus   int
	}{
		{
			name:      "Successfully delete section",
			sectionID: testSectionID.String(),
			mockSection: models.Section{
				ID:         testSectionID,
				NotebookID: testNotebookID,
			},
			mockNotebook: models.Notebook{
				ID:     testNotebookID,
				UserID: testUserID,
			},
			expectedStatus: http.StatusNoContent,
		},
		{
			name:      "Unauthorized - different user",
			sectionID: testSectionID.String(),
			mockSection: models.Section{
				ID:         testSectionID,
				NotebookID: testNotebookID,
			},
			mockNotebook: models.Notebook{
				ID:     testNotebookID,
				UserID: anotherUserID,
			},
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "Invalid section ID",
			sectionID:      "invalid-uuid",
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSectionRepo := &mockSectionRepository{
				fetchSectionFunc: func(ctx context.Context, id uuid.UUID) (models.Section, error) {
					return tt.mockSection, nil
				},
				deleteSectionFunc: func(ctx context.Context, id uuid.UUID) error {
					return tt.mockDeleteErr
				},
			}

			mockNotebookRepo := &mockNotebookRepository{
				fetchNotebookFunc: func(ctx context.Context, id uuid.UUID) (models.Notebook, error) {
					return tt.mockNotebook, nil
				},
			}

			handler := NewSectionHandler(mockSectionRepo, mockNotebookRepo)

			req := httptest.NewRequest(http.MethodDelete, "/sections/"+tt.sectionID, nil)
			rctx := chi.NewRouteContext()
			rctx.URLParams.Add("id", tt.sectionID)
			req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

			ctx := context.WithValue(req.Context(), utils.UserIDKey, testUserID)
			ctx = context.WithValue(ctx, utils.UsernameKey, "testuser")
			req = req.WithContext(ctx)

			w := httptest.NewRecorder()
			handler.DeleteSection(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}
		})
	}
}

// Test UpdateSectionPosition
func TestUpdateSectionPosition(t *testing.T) {
	testUserID := uuid.New()
	testNotebookID := uuid.New()
	testSectionID := uuid.New()

	tests := []struct {
		name           string
		sectionID      string
		newPosition    int
		mockSection    models.Section
		mockNotebook   models.Notebook
		mockUpdateErr  error
		expectedStatus int
	}{
		{
			name:        "Successfully update position",
			sectionID:   testSectionID.String(),
			newPosition: 2,
			mockSection: models.Section{
				ID:         testSectionID,
				NotebookID: testNotebookID,
				Position:   0,
			},
			mockNotebook: models.Notebook{
				ID:     testNotebookID,
				UserID: testUserID,
			},
			expectedStatus: http.StatusNoContent,
		},
		{
			name:        "Repository error",
			sectionID:   testSectionID.String(),
			newPosition: 1,
			mockSection: models.Section{
				ID:         testSectionID,
				NotebookID: testNotebookID,
			},
			mockNotebook: models.Notebook{
				ID:     testNotebookID,
				UserID: testUserID,
			},
			mockUpdateErr:  errors.New("database error"),
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSectionRepo := &mockSectionRepository{
				fetchSectionFunc: func(ctx context.Context, id uuid.UUID) (models.Section, error) {
					return tt.mockSection, nil
				},
				updateSectionPositionFunc: func(ctx context.Context, id uuid.UUID, newPosition int) error {
					if newPosition != tt.newPosition {
						t.Errorf("Expected position %d, got %d", tt.newPosition, newPosition)
					}
					return tt.mockUpdateErr
				},
			}

			mockNotebookRepo := &mockNotebookRepository{
				fetchNotebookFunc: func(ctx context.Context, id uuid.UUID) (models.Notebook, error) {
					return tt.mockNotebook, nil
				},
			}

			handler := NewSectionHandler(mockSectionRepo, mockNotebookRepo)

			reqBody := map[string]int{"position": tt.newPosition}
			body, _ := json.Marshal(reqBody)
			req := httptest.NewRequest(http.MethodPut, "/sections/"+tt.sectionID+"/position", bytes.NewReader(body))
			rctx := chi.NewRouteContext()
			rctx.URLParams.Add("id", tt.sectionID)
			req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

			ctx := context.WithValue(req.Context(), utils.UserIDKey, testUserID)
			ctx = context.WithValue(ctx, utils.UsernameKey, "testuser")
			req = req.WithContext(ctx)

			w := httptest.NewRecorder()
			handler.UpdateSectionPosition(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}
		})
	}
}

// Test UpdateSectionName
func TestUpdateSectionName(t *testing.T) {
	testUserID := uuid.New()
	testNotebookID := uuid.New()
	testSectionID := uuid.New()

	tests := []struct {
		name           string
		sectionID      string
		newName        string
		mockSection    models.Section
		mockNotebook   models.Notebook
		expectedStatus int
	}{
		{
			name:      "Successfully update name",
			sectionID: testSectionID.String(),
			newName:   "Updated Name",
			mockSection: models.Section{
				ID:         testSectionID,
				NotebookID: testNotebookID,
				Name:       "Old Name",
			},
			mockNotebook: models.Notebook{
				ID:     testNotebookID,
				UserID: testUserID,
			},
			expectedStatus: http.StatusNoContent,
		},
		{
			name:      "Empty name returns bad request",
			sectionID: testSectionID.String(),
			newName:   "",
			mockSection: models.Section{
				ID:         testSectionID,
				NotebookID: testNotebookID,
			},
			mockNotebook: models.Notebook{
				ID:     testNotebookID,
				UserID: testUserID,
			},
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSectionRepo := &mockSectionRepository{
				fetchSectionFunc: func(ctx context.Context, id uuid.UUID) (models.Section, error) {
					return tt.mockSection, nil
				},
				updateSectionNameFunc: func(ctx context.Context, id uuid.UUID, name string) error {
					if name != tt.newName {
						t.Errorf("Expected name %s, got %s", tt.newName, name)
					}
					return nil
				},
			}

			mockNotebookRepo := &mockNotebookRepository{
				fetchNotebookFunc: func(ctx context.Context, id uuid.UUID) (models.Notebook, error) {
					return tt.mockNotebook, nil
				},
			}

			handler := NewSectionHandler(mockSectionRepo, mockNotebookRepo)

			reqBody := map[string]string{"name": tt.newName}
			body, _ := json.Marshal(reqBody)
			req := httptest.NewRequest(http.MethodPatch, "/sections/"+tt.sectionID, bytes.NewReader(body))
			rctx := chi.NewRouteContext()
			rctx.URLParams.Add("id", tt.sectionID)
			req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

			ctx := context.WithValue(req.Context(), utils.UserIDKey, testUserID)
			ctx = context.WithValue(ctx, utils.UsernameKey, "testuser")
			req = req.WithContext(ctx)

			w := httptest.NewRecorder()
			handler.UpdateSectionName(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}
		})
	}
}

// Test AssignNoteToSection
func TestAssignNoteToSection(t *testing.T) {
	testUserID := uuid.New()
	testNotebookID := uuid.New()
	testNoteID := uuid.New()
	testSectionID := uuid.New()

	tests := []struct {
		name           string
		noteID         string
		notebookID     string
		sectionID      *uuid.UUID
		mockNotebook   models.Notebook
		mockSection    models.Section
		expectedStatus int
	}{
		{
			name:       "Successfully assign note to section",
			noteID:     testNoteID.String(),
			notebookID: testNotebookID.String(),
			sectionID:  &testSectionID,
			mockNotebook: models.Notebook{
				ID:     testNotebookID,
				UserID: testUserID,
			},
			mockSection: models.Section{
				ID:         testSectionID,
				NotebookID: testNotebookID,
			},
			expectedStatus: http.StatusNoContent,
		},
		{
			name:       "Successfully unsection note (nil section ID)",
			noteID:     testNoteID.String(),
			notebookID: testNotebookID.String(),
			sectionID:  nil,
			mockNotebook: models.Notebook{
				ID:     testNotebookID,
				UserID: testUserID,
			},
			expectedStatus: http.StatusNoContent,
		},
		{
			name:       "Invalid note ID",
			noteID:     "invalid-uuid",
			notebookID: testNotebookID.String(),
			sectionID:  &testSectionID,
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSectionRepo := &mockSectionRepository{
				fetchSectionFunc: func(ctx context.Context, id uuid.UUID) (models.Section, error) {
					return tt.mockSection, nil
				},
				assignNoteToSectionFunc: func(ctx context.Context, noteID, notebookID uuid.UUID, sectionID *uuid.UUID) error {
					if sectionID != nil && tt.sectionID != nil && *sectionID != *tt.sectionID {
						t.Errorf("Expected section ID %s, got %s", *tt.sectionID, *sectionID)
					}
					if sectionID == nil && tt.sectionID != nil {
						t.Error("Expected section ID to be provided, got nil")
					}
					return nil
				},
			}

			mockNotebookRepo := &mockNotebookRepository{
				fetchNotebookFunc: func(ctx context.Context, id uuid.UUID) (models.Notebook, error) {
					return tt.mockNotebook, nil
				},
			}

			handler := NewSectionHandler(mockSectionRepo, mockNotebookRepo)

			reqBody := requests.AssignToSection{SectionID: tt.sectionID}
			body, _ := json.Marshal(reqBody)
			req := httptest.NewRequest(http.MethodPut, "/notes/"+tt.noteID+"/notebooks/"+tt.notebookID+"/section", bytes.NewReader(body))
			rctx := chi.NewRouteContext()
			rctx.URLParams.Add("noteId", tt.noteID)
			rctx.URLParams.Add("notebookId", tt.notebookID)
			req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

			ctx := context.WithValue(req.Context(), utils.UserIDKey, testUserID)
			ctx = context.WithValue(ctx, utils.UsernameKey, "testuser")
			req = req.WithContext(ctx)

			w := httptest.NewRecorder()
			handler.AssignNoteToSection(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}
		})
	}
}

// Test GetSectionNotes
func TestGetSectionNotes(t *testing.T) {
	testUserID := uuid.New()
	testNotebookID := uuid.New()
	testSectionID := uuid.New()

	tests := []struct {
		name          string
		sectionID     string
		mockSection   models.Section
		mockNotebook  models.Notebook
		mockNotes     []models.Note
		expectedStatus int
		expectedCount int
	}{
		{
			name:      "Successfully get section notes",
			sectionID: testSectionID.String(),
			mockSection: models.Section{
				ID:         testSectionID,
				NotebookID: testNotebookID,
			},
			mockNotebook: models.Notebook{
				ID:     testNotebookID,
				UserID: testUserID,
			},
			mockNotes: []models.Note{
				{ID: uuid.New(), Title: "Note 1", Content: "Content 1"},
				{ID: uuid.New(), Title: "Note 2", Content: "Content 2"},
			},
			expectedStatus: http.StatusOK,
			expectedCount:  2,
		},
		{
			name:      "Empty notes list",
			sectionID: testSectionID.String(),
			mockSection: models.Section{
				ID:         testSectionID,
				NotebookID: testNotebookID,
			},
			mockNotebook: models.Notebook{
				ID:     testNotebookID,
				UserID: testUserID,
			},
			mockNotes:      []models.Note{},
			expectedStatus: http.StatusOK,
			expectedCount:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSectionRepo := &mockSectionRepository{
				fetchSectionFunc: func(ctx context.Context, id uuid.UUID) (models.Section, error) {
					return tt.mockSection, nil
				},
				fetchSectionNotesFunc: func(ctx context.Context, sectionID uuid.UUID) ([]models.Note, error) {
					return tt.mockNotes, nil
				},
			}

			mockNotebookRepo := &mockNotebookRepository{
				fetchNotebookFunc: func(ctx context.Context, id uuid.UUID) (models.Notebook, error) {
					return tt.mockNotebook, nil
				},
			}

			handler := NewSectionHandler(mockSectionRepo, mockNotebookRepo)

			req := httptest.NewRequest(http.MethodGet, "/sections/"+tt.sectionID+"/notes", nil)
			rctx := chi.NewRouteContext()
			rctx.URLParams.Add("id", tt.sectionID)
			req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

			ctx := context.WithValue(req.Context(), utils.UserIDKey, testUserID)
			ctx = context.WithValue(ctx, utils.UsernameKey, "testuser")
			req = req.WithContext(ctx)

			w := httptest.NewRecorder()
			handler.GetSectionNotes(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if tt.expectedStatus == http.StatusOK {
				var notes []models.Note
				if err := json.NewDecoder(w.Body).Decode(&notes); err != nil {
					t.Fatalf("Failed to decode response: %v", err)
				}
				if len(notes) != tt.expectedCount {
					t.Errorf("Expected %d notes, got %d", tt.expectedCount, len(notes))
				}
			}
		})
	}
}

// Test GetUnsectionedNotes
func TestGetUnsectionedNotes(t *testing.T) {
	testUserID := uuid.New()
	testNotebookID := uuid.New()

	tests := []struct {
		name          string
		notebookID    string
		mockNotebook  models.Notebook
		mockNotes     []models.Note
		expectedStatus int
		expectedCount int
	}{
		{
			name:       "Successfully get unsectioned notes",
			notebookID: testNotebookID.String(),
			mockNotebook: models.Notebook{
				ID:     testNotebookID,
				UserID: testUserID,
			},
			mockNotes: []models.Note{
				{ID: uuid.New(), Title: "Unsectioned 1", Content: "Content 1"},
				{ID: uuid.New(), Title: "Unsectioned 2", Content: "Content 2"},
			},
			expectedStatus: http.StatusOK,
			expectedCount:  2,
		},
		{
			name:       "Empty unsectioned notes",
			notebookID: testNotebookID.String(),
			mockNotebook: models.Notebook{
				ID:     testNotebookID,
				UserID: testUserID,
			},
			mockNotes:      []models.Note{},
			expectedStatus: http.StatusOK,
			expectedCount:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSectionRepo := &mockSectionRepository{
				fetchUnsectionedNotesFunc: func(ctx context.Context, notebookID uuid.UUID) ([]models.Note, error) {
					return tt.mockNotes, nil
				},
			}

			mockNotebookRepo := &mockNotebookRepository{
				fetchNotebookFunc: func(ctx context.Context, id uuid.UUID) (models.Notebook, error) {
					return tt.mockNotebook, nil
				},
			}

			handler := NewSectionHandler(mockSectionRepo, mockNotebookRepo)

			req := httptest.NewRequest(http.MethodGet, "/notebooks/"+tt.notebookID+"/unsectioned", nil)
			rctx := chi.NewRouteContext()
			rctx.URLParams.Add("id", tt.notebookID)
			req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

			ctx := context.WithValue(req.Context(), utils.UserIDKey, testUserID)
			ctx = context.WithValue(ctx, utils.UsernameKey, "testuser")
			req = req.WithContext(ctx)

			w := httptest.NewRecorder()
			handler.GetUnsectionedNotes(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if tt.expectedStatus == http.StatusOK {
				var notes []models.Note
				if err := json.NewDecoder(w.Body).Decode(&notes); err != nil {
					t.Fatalf("Failed to decode response: %v", err)
				}
				if len(notes) != tt.expectedCount {
					t.Errorf("Expected %d notes, got %d", tt.expectedCount, len(notes))
				}
			}
		})
	}
}

// Test missing auth context
func TestSectionHandlerWithoutAuth(t *testing.T) {
	mockSectionRepo := &mockSectionRepository{}
	mockNotebookRepo := &mockNotebookRepository{}
	handler := NewSectionHandler(mockSectionRepo, mockNotebookRepo)

	testSectionID := uuid.New().String()
	req := httptest.NewRequest(http.MethodGet, "/sections/"+testSectionID, nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", testSectionID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	// No user context added - simulating missing auth

	w := httptest.NewRecorder()
	handler.FetchSection(w, req)

	// Should return 500 when user context is missing
	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status %d for missing auth, got %d", http.StatusInternalServerError, w.Code)
	}
}
