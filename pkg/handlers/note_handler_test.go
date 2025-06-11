package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
	"tofoss/org-go/pkg/db/repositories"
	"tofoss/org-go/pkg/handlers/requests"
	"tofoss/org-go/pkg/handlers/responses"
	"tofoss/org-go/pkg/models"
	"tofoss/org-go/pkg/utils"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupNoteHandler(t *testing.T) (*NoteHandler, pgxmock.PgxPoolIface) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)

	repo := repositories.NewNoteRepository(mock)
	handler := NewNoteHandler(repo)
	return &handler, mock
}

func createTestRequestWithAuth(method, url string, body []byte, userID uuid.UUID, username string) *http.Request {
	req := httptest.NewRequest(method, url, bytes.NewReader(body))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	// Add user context as if JWT middleware processed it
	ctx := context.WithValue(req.Context(), utils.UserIDKey, userID)
	ctx = context.WithValue(ctx, utils.UsernameKey, username)
	return req.WithContext(ctx)
}

func TestNoteHandler_FetchNote(t *testing.T) {
	userID := uuid.New()
	noteID := uuid.New()
	otherUserID := uuid.New()
	now := time.Now()

	tests := []struct {
		name           string
		noteID         string
		setupMock      func(mock pgxmock.PgxPoolIface)
		expectedStatus int
		checkResponse  func(t *testing.T, w *httptest.ResponseRecorder)
	}{
		{
			name:   "successful fetch of own note",
			noteID: noteID.String(),
			setupMock: func(mock pgxmock.PgxPoolIface) {
				rows := pgxmock.NewRows([]string{"id", "user_id", "title", "content", "created_at", "updated_at", "published_at", "published"}).
					AddRow(noteID, userID, "Test Note", "Test Content", now, now, nil, false)
				mock.ExpectQuery(`select id, user_id, title, content, created_at, updated_at, published_at, published from notes where id = \$1`).
					WithArgs(noteID).
					WillReturnRows(rows)

				tagsRows := pgxmock.NewRows([]string{"id", "name"})
				mock.ExpectQuery(`SELECT t\.id, t\.name FROM tags t JOIN note_tags nt ON t\.id = nt\.tag_id WHERE nt\.note_id = \$1`).
					WithArgs(noteID).
					WillReturnRows(tagsRows)
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				var response responses.FetchNoteResponse
				err := json.Unmarshal(w.Body.Bytes(), &response)
				require.NoError(t, err)
				assert.Equal(t, noteID, response.Note.ID)
				assert.Equal(t, "Test Note", response.Note.Title)
				assert.True(t, response.IsEditable)
			},
		},
		{
			name:   "successful fetch of published note by other user",
			noteID: noteID.String(),
			setupMock: func(mock pgxmock.PgxPoolIface) {
				rows := pgxmock.NewRows([]string{"id", "user_id", "title", "content", "created_at", "updated_at", "published_at", "published"}).
					AddRow(noteID, otherUserID, "Public Note", "Public Content", now, now, &now, true)
				mock.ExpectQuery(`select id, user_id, title, content, created_at, updated_at, published_at, published from notes where id = \$1`).
					WithArgs(noteID).
					WillReturnRows(rows)

				tagsRows := pgxmock.NewRows([]string{"id", "name"})
				mock.ExpectQuery(`SELECT t\.id, t\.name FROM tags t JOIN note_tags nt ON t\.id = nt\.tag_id WHERE nt\.note_id = \$1`).
					WithArgs(noteID).
					WillReturnRows(tagsRows)
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				var response responses.FetchNoteResponse
				err := json.Unmarshal(w.Body.Bytes(), &response)
				require.NoError(t, err)
				assert.Equal(t, noteID, response.Note.ID)
				assert.Equal(t, "Public Note", response.Note.Title)
				assert.False(t, response.IsEditable) // Not owner
			},
		},
		{
			name:   "unauthorized access to unpublished note",
			noteID: noteID.String(),
			setupMock: func(mock pgxmock.PgxPoolIface) {
				rows := pgxmock.NewRows([]string{"id", "user_id", "title", "content", "created_at", "updated_at", "published_at", "published"}).
					AddRow(noteID, otherUserID, "Private Note", "Private Content", now, now, nil, false)
				mock.ExpectQuery(`select id, user_id, title, content, created_at, updated_at, published_at, published from notes where id = \$1`).
					WithArgs(noteID).
					WillReturnRows(rows)
			},
			expectedStatus: http.StatusUnauthorized,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "Unauthorized")
			},
		},
		{
			name:   "note not found",
			noteID: noteID.String(),
			setupMock: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectQuery(`select id, user_id, title, content, created_at, updated_at, published_at, published from notes where id = \$1`).
					WithArgs(noteID).
					WillReturnError(pgx.ErrNoRows)
			},
			expectedStatus: http.StatusNotFound,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "note not found")
			},
		},
		{
			name:           "invalid note ID format",
			noteID:         "invalid-uuid",
			setupMock:      func(mock pgxmock.PgxPoolIface) {},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "Bad Request")
			},
		},
		{
			name:   "database error",
			noteID: noteID.String(),
			setupMock: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectQuery(`select id, user_id, title, content, created_at, updated_at, published_at, published from notes where id = \$1`).
					WithArgs(noteID).
					WillReturnError(fmt.Errorf("database error"))
			},
			expectedStatus: http.StatusInternalServerError,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "Internal Server Error")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, mock := setupNoteHandler(t)
			defer mock.Close()

			tt.setupMock(mock)

			req := createTestRequestWithAuth("GET", "/notes/"+tt.noteID, nil, userID, "testuser")
			
			// Set up chi router context for URL parameters
			rctx := chi.NewRouteContext()
			rctx.URLParams.Add("id", tt.noteID)
			req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

			w := httptest.NewRecorder()

			handler.FetchNote(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.checkResponse != nil {
				tt.checkResponse(t, w)
			}
			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestNoteHandler_FetchUsersNotes(t *testing.T) {
	userID := uuid.New()
	note1ID := uuid.New()
	note2ID := uuid.New()
	now := time.Now()

	tests := []struct {
		name           string
		setupMock      func(mock pgxmock.PgxPoolIface)
		expectedStatus int
		checkResponse  func(t *testing.T, w *httptest.ResponseRecorder)
	}{
		{
			name: "successful fetch of user's notes",
			setupMock: func(mock pgxmock.PgxPoolIface) {
				notesRows := pgxmock.NewRows([]string{"id", "user_id", "title", "content", "created_at", "updated_at", "published_at", "published"}).
					AddRow(note1ID, userID, "Note 1", "Content 1", now, now, nil, false).
					AddRow(note2ID, userID, "Note 2", "Content 2", now, now, &now, true)
				mock.ExpectQuery(`select id, user_id, title, content, created_at, updated_at, published_at, published from notes where user_id = \$1`).
					WithArgs(userID).
					WillReturnRows(notesRows)

				tagsRows := pgxmock.NewRows([]string{"note_id", "id", "name"})
				mock.ExpectQuery(`SELECT nt\.note_id, t\.id, t\.name FROM tags t JOIN note_tags nt ON t\.id = nt\.tag_id WHERE nt\.note_id = ANY\(\$1\)`).
					WithArgs(pgxmock.AnyArg()).
					WillReturnRows(tagsRows)
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				var notes []models.Note
				err := json.Unmarshal(w.Body.Bytes(), &notes)
				require.NoError(t, err)
				assert.Len(t, notes, 2)
				assert.Equal(t, "Note 1", notes[0].Title)
				assert.Equal(t, "Note 2", notes[1].Title)
			},
		},
		{
			name: "no notes found",
			setupMock: func(mock pgxmock.PgxPoolIface) {
				notesRows := pgxmock.NewRows([]string{"id", "user_id", "title", "content", "created_at", "updated_at", "published_at", "published"})
				mock.ExpectQuery(`select id, user_id, title, content, created_at, updated_at, published_at, published from notes where user_id = \$1`).
					WithArgs(userID).
					WillReturnRows(notesRows)

				tagsRows := pgxmock.NewRows([]string{"note_id", "id", "name"})
				mock.ExpectQuery(`SELECT nt\.note_id, t\.id, t\.name FROM tags t JOIN note_tags nt ON t\.id = nt\.tag_id WHERE nt\.note_id = ANY\(\$1\)`).
					WithArgs(pgxmock.AnyArg()).
					WillReturnRows(tagsRows)
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				var notes []models.Note
				err := json.Unmarshal(w.Body.Bytes(), &notes)
				require.NoError(t, err)
				assert.Empty(t, notes)
			},
		},
		{
			name: "database error",
			setupMock: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectQuery(`select id, user_id, title, content, created_at, updated_at, published_at, published from notes where user_id = \$1`).
					WithArgs(userID).
					WillReturnError(fmt.Errorf("database error"))
			},
			expectedStatus: http.StatusInternalServerError,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "Internal Server Error")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, mock := setupNoteHandler(t)
			defer mock.Close()

			tt.setupMock(mock)

			req := createTestRequestWithAuth("GET", "/notes", nil, userID, "testuser")
			w := httptest.NewRecorder()

			handler.FetchUsersNotes(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.checkResponse != nil {
				tt.checkResponse(t, w)
			}
			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestNoteHandler_PostNote(t *testing.T) {
	userID := uuid.New()
	noteID := uuid.New()
	now := time.Now()

	tests := []struct {
		name           string
		requestBody    interface{}
		setupMock      func(mock pgxmock.PgxPoolIface)
		expectedStatus int
		checkResponse  func(t *testing.T, w *httptest.ResponseRecorder)
	}{
		{
			name: "create new note",
			requestBody: requests.Note{
				ID:        uuid.Nil, // New note
				Content:   "New note content",
				Published: false,
			},
			setupMock: func(mock pgxmock.PgxPoolIface) {
				rows := pgxmock.NewRows([]string{"id", "user_id", "title", "content", "created_at", "updated_at", "published_at", "published"}).
					AddRow(pgxmock.AnyArg(), userID, "", "New note content", now, now, nil, false)
				mock.ExpectQuery(`INSERT INTO notes`).
					WithArgs(pgxmock.AnyArg(), userID, "", "New note content", pgxmock.AnyArg(), pgxmock.AnyArg(), nil, false).
					WillReturnRows(rows)
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				var note models.Note
				err := json.Unmarshal(w.Body.Bytes(), &note)
				require.NoError(t, err)
				assert.Equal(t, "New note content", note.Content)
				assert.False(t, note.Published)
			},
		},
		{
			name: "update existing note",
			requestBody: requests.Note{
				ID:        noteID,
				Content:   "Updated content",
				Published: true,
			},
			setupMock: func(mock pgxmock.PgxPoolIface) {
				// Fetch existing note
				existingRows := pgxmock.NewRows([]string{"id", "user_id", "title", "content", "created_at", "updated_at", "published_at", "published"}).
					AddRow(noteID, userID, "Existing Note", "Old content", now, now, nil, false)
				mock.ExpectQuery(`select id, user_id, title, content, created_at, updated_at, published_at, published from notes where id = \$1 and user_id = \$2`).
					WithArgs(noteID, userID).
					WillReturnRows(existingRows)

				// Update note
				updatedRows := pgxmock.NewRows([]string{"id", "user_id", "title", "content", "created_at", "updated_at", "published_at", "published"}).
					AddRow(noteID, userID, "Existing Note", "Updated content", now, pgxmock.AnyArg(), pgxmock.AnyArg(), true)
				mock.ExpectQuery(`INSERT INTO notes`).
					WithArgs(noteID, userID, "Existing Note", "Updated content", now, pgxmock.AnyArg(), pgxmock.AnyArg(), true).
					WillReturnRows(updatedRows)
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				var note models.Note
				err := json.Unmarshal(w.Body.Bytes(), &note)
				require.NoError(t, err)
				assert.Equal(t, "Updated content", note.Content)
				assert.True(t, note.Published)
			},
		},
		{
			name:           "invalid JSON payload",
			requestBody:    "invalid-json",
			setupMock:      func(mock pgxmock.PgxPoolIface) {},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "Bad Request")
			},
		},
		{
			name: "unauthorized note update",
			requestBody: requests.Note{
				ID:        noteID,
				Content:   "Hacked content",
				Published: true,
			},
			setupMock: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectQuery(`select id, user_id, title, content, created_at, updated_at, published_at, published from notes where id = \$1 and user_id = \$2`).
					WithArgs(noteID, userID).
					WillReturnError(pgx.ErrNoRows)
			},
			expectedStatus: http.StatusInternalServerError,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "Internal Server Error")
			},
		},
		{
			name: "database error during create",
			requestBody: requests.Note{
				ID:        uuid.Nil,
				Content:   "New content",
				Published: false,
			},
			setupMock: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectQuery(`INSERT INTO notes`).
					WithArgs(pgxmock.AnyArg(), userID, "", "New content", pgxmock.AnyArg(), pgxmock.AnyArg(), nil, false).
					WillReturnError(fmt.Errorf("database error"))
			},
			expectedStatus: http.StatusInternalServerError,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "Internal Server Error")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, mock := setupNoteHandler(t)
			defer mock.Close()

			tt.setupMock(mock)

			var body []byte
			if str, ok := tt.requestBody.(string); ok {
				body = []byte(str)
			} else {
				body, _ = json.Marshal(tt.requestBody)
			}

			req := createTestRequestWithAuth("POST", "/notes", body, userID, "testuser")
			w := httptest.NewRecorder()

			handler.PostNote(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.checkResponse != nil {
				tt.checkResponse(t, w)
			}
			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestNoteHandler_GetNoteTags(t *testing.T) {
	userID := uuid.New()
	noteID := uuid.New()
	tag1ID := uuid.New()
	tag2ID := uuid.New()

	tests := []struct {
		name           string
		noteID         string
		setupMock      func(mock pgxmock.PgxPoolIface)
		expectedStatus int
		checkResponse  func(t *testing.T, w *httptest.ResponseRecorder)
	}{
		{
			name:   "successful get note tags",
			noteID: noteID.String(),
			setupMock: func(mock pgxmock.PgxPoolIface) {
				// Verify user access to note
				noteRows := pgxmock.NewRows([]string{"id", "user_id", "title", "content", "created_at", "updated_at", "published_at", "published"}).
					AddRow(noteID, userID, "Test Note", "Content", time.Now(), time.Now(), nil, false)
				mock.ExpectQuery(`select id, user_id, title, content, created_at, updated_at, published_at, published from notes where id = \$1 and user_id = \$2`).
					WithArgs(noteID, userID).
					WillReturnRows(noteRows)

				// Get tags
				tagsRows := pgxmock.NewRows([]string{"id", "name"}).
					AddRow(tag1ID, "tag1").
					AddRow(tag2ID, "tag2")
				mock.ExpectQuery(`SELECT t\.id, t\.name FROM tags t JOIN note_tags nt ON t\.id = nt\.tag_id WHERE nt\.note_id = \$1`).
					WithArgs(noteID).
					WillReturnRows(tagsRows)
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				var tags []models.Tag
				err := json.Unmarshal(w.Body.Bytes(), &tags)
				require.NoError(t, err)
				assert.Len(t, tags, 2)
				assert.Equal(t, "tag1", tags[0].Name)
				assert.Equal(t, "tag2", tags[1].Name)
			},
		},
		{
			name:   "note not found or unauthorized",
			noteID: noteID.String(),
			setupMock: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectQuery(`select id, user_id, title, content, created_at, updated_at, published_at, published from notes where id = \$1 and user_id = \$2`).
					WithArgs(noteID, userID).
					WillReturnError(pgx.ErrNoRows)
			},
			expectedStatus: http.StatusNotFound,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "note not found")
			},
		},
		{
			name:           "invalid note ID",
			noteID:         "invalid-uuid",
			setupMock:      func(mock pgxmock.PgxPoolIface) {},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "Bad Request")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, mock := setupNoteHandler(t)
			defer mock.Close()

			tt.setupMock(mock)

			req := createTestRequestWithAuth("GET", "/notes/"+tt.noteID+"/tags", nil, userID, "testuser")
			
			rctx := chi.NewRouteContext()
			rctx.URLParams.Add("id", tt.noteID)
			req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

			w := httptest.NewRecorder()

			handler.GetNoteTags(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.checkResponse != nil {
				tt.checkResponse(t, w)
			}
			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestNoteHandler_AssignNoteTags(t *testing.T) {
	userID := uuid.New()
	noteID := uuid.New()
	tag1ID := uuid.New()
	tag2ID := uuid.New()

	tests := []struct {
		name           string
		noteID         string
		requestBody    interface{}
		setupMock      func(mock pgxmock.PgxPoolIface)
		expectedStatus int
		checkResponse  func(t *testing.T, w *httptest.ResponseRecorder)
	}{
		{
			name:   "successful tag assignment",
			noteID: noteID.String(),
			requestBody: requests.AssignTags{
				TagIDs: []uuid.UUID{tag1ID, tag2ID},
			},
			setupMock: func(mock pgxmock.PgxPoolIface) {
				// Verify user access to note
				noteRows := pgxmock.NewRows([]string{"id", "user_id", "title", "content", "created_at", "updated_at", "published_at", "published"}).
					AddRow(noteID, userID, "Test Note", "Content", time.Now(), time.Now(), nil, false)
				mock.ExpectQuery(`select id, user_id, title, content, created_at, updated_at, published_at, published from notes where id = \$1 and user_id = \$2`).
					WithArgs(noteID, userID).
					WillReturnRows(noteRows)

				// Assign tags (transaction)
				mock.ExpectBegin()
				mock.ExpectExec(`DELETE FROM note_tags WHERE note_id = \$1`).
					WithArgs(noteID).
					WillReturnResult(pgxmock.NewResult("DELETE", 0))
				mock.ExpectExec(`INSERT INTO note_tags \(note_id, tag_id\) VALUES \(\$1, \$2\)`).
					WithArgs(noteID, tag1ID).
					WillReturnResult(pgxmock.NewResult("INSERT", 1))
				mock.ExpectExec(`INSERT INTO note_tags \(note_id, tag_id\) VALUES \(\$1, \$2\)`).
					WithArgs(noteID, tag2ID).
					WillReturnResult(pgxmock.NewResult("INSERT", 1))
				mock.ExpectCommit()

				// Return updated tags
				tagsRows := pgxmock.NewRows([]string{"id", "name"}).
					AddRow(tag1ID, "tag1").
					AddRow(tag2ID, "tag2")
				mock.ExpectQuery(`SELECT t\.id, t\.name FROM tags t JOIN note_tags nt ON t\.id = nt\.tag_id WHERE nt\.note_id = \$1`).
					WithArgs(noteID).
					WillReturnRows(tagsRows)
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				var tags []models.Tag
				err := json.Unmarshal(w.Body.Bytes(), &tags)
				require.NoError(t, err)
				assert.Len(t, tags, 2)
			},
		},
		{
			name:           "invalid JSON payload",
			noteID:         noteID.String(),
			requestBody:    "invalid-json",
			setupMock:      func(mock pgxmock.PgxPoolIface) {},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "Bad Request")
			},
		},
		{
			name:   "unauthorized note access",
			noteID: noteID.String(),
			requestBody: requests.AssignTags{
				TagIDs: []uuid.UUID{tag1ID},
			},
			setupMock: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectQuery(`select id, user_id, title, content, created_at, updated_at, published_at, published from notes where id = \$1 and user_id = \$2`).
					WithArgs(noteID, userID).
					WillReturnError(pgx.ErrNoRows)
			},
			expectedStatus: http.StatusNotFound,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "note not found")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, mock := setupNoteHandler(t)
			defer mock.Close()

			tt.setupMock(mock)

			var body []byte
			if str, ok := tt.requestBody.(string); ok {
				body = []byte(str)
			} else {
				body, _ = json.Marshal(tt.requestBody)
			}

			req := createTestRequestWithAuth("POST", "/notes/"+tt.noteID+"/tags", body, userID, "testuser")
			
			rctx := chi.NewRouteContext()
			rctx.URLParams.Add("id", tt.noteID)
			req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

			w := httptest.NewRecorder()

			handler.AssignNoteTags(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.checkResponse != nil {
				tt.checkResponse(t, w)
			}
			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestNoteHandler_RemoveNoteTag(t *testing.T) {
	userID := uuid.New()
	noteID := uuid.New()
	tagID := uuid.New()

	tests := []struct {
		name           string
		noteID         string
		tagID          string
		setupMock      func(mock pgxmock.PgxPoolIface)
		expectedStatus int
		checkResponse  func(t *testing.T, w *httptest.ResponseRecorder)
	}{
		{
			name:   "successful tag removal",
			noteID: noteID.String(),
			tagID:  tagID.String(),
			setupMock: func(mock pgxmock.PgxPoolIface) {
				// Verify user access to note
				noteRows := pgxmock.NewRows([]string{"id", "user_id", "title", "content", "created_at", "updated_at", "published_at", "published"}).
					AddRow(noteID, userID, "Test Note", "Content", time.Now(), time.Now(), nil, false)
				mock.ExpectQuery(`select id, user_id, title, content, created_at, updated_at, published_at, published from notes where id = \$1 and user_id = \$2`).
					WithArgs(noteID, userID).
					WillReturnRows(noteRows)

				// Remove tag
				mock.ExpectExec(`DELETE FROM note_tags WHERE note_id = \$1 AND tag_id = \$2`).
					WithArgs(noteID, tagID).
					WillReturnResult(pgxmock.NewResult("DELETE", 1))
			},
			expectedStatus: http.StatusNoContent,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Empty(t, w.Body.String())
			},
		},
		{
			name:   "unauthorized note access",
			noteID: noteID.String(),
			tagID:  tagID.String(),
			setupMock: func(mock pgxmock.PgxPoolIface) {
				mock.ExpectQuery(`select id, user_id, title, content, created_at, updated_at, published_at, published from notes where id = \$1 and user_id = \$2`).
					WithArgs(noteID, userID).
					WillReturnError(pgx.ErrNoRows)
			},
			expectedStatus: http.StatusNotFound,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "note not found")
			},
		},
		{
			name:           "invalid note ID",
			noteID:         "invalid-uuid",
			tagID:          tagID.String(),
			setupMock:      func(mock pgxmock.PgxPoolIface) {},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "Bad Request")
			},
		},
		{
			name:           "invalid tag ID",
			noteID:         noteID.String(),
			tagID:          "invalid-uuid",
			setupMock:      func(mock pgxmock.PgxPoolIface) {},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "Bad Request")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, mock := setupNoteHandler(t)
			defer mock.Close()

			tt.setupMock(mock)

			req := createTestRequestWithAuth("DELETE", "/notes/"+tt.noteID+"/tags/"+tt.tagID, nil, userID, "testuser")
			
			rctx := chi.NewRouteContext()
			rctx.URLParams.Add("id", tt.noteID)
			rctx.URLParams.Add("tagId", tt.tagID)
			req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

			w := httptest.NewRecorder()

			handler.RemoveNoteTag(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.checkResponse != nil {
				tt.checkResponse(t, w)
			}
			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestNoteHandler_Integration(t *testing.T) {
	// Integration test that creates a note, adds tags, and then removes them
	handler, mock := setupNoteHandler(t)
	defer mock.Close()

	userID := uuid.New()
	noteID := uuid.New()
	tagID := uuid.New()
	now := time.Now()

	// Step 1: Create a new note
	t.Run("create_note", func(t *testing.T) {
		rows := pgxmock.NewRows([]string{"id", "user_id", "title", "content", "created_at", "updated_at", "published_at", "published"}).
			AddRow(noteID, userID, "", "Test content", now, now, nil, false)
		mock.ExpectQuery(`INSERT INTO notes`).
			WithArgs(pgxmock.AnyArg(), userID, "", "Test content", pgxmock.AnyArg(), pgxmock.AnyArg(), nil, false).
			WillReturnRows(rows)

		noteReq := requests.Note{
			ID:        uuid.Nil,
			Content:   "Test content",
			Published: false,
		}
		body, _ := json.Marshal(noteReq)
		req := createTestRequestWithAuth("POST", "/notes", body, userID, "testuser")
		w := httptest.NewRecorder()

		handler.PostNote(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	// Step 2: Assign tags to the note
	t.Run("assign_tags", func(t *testing.T) {
		// Verify user access
		noteRows := pgxmock.NewRows([]string{"id", "user_id", "title", "content", "created_at", "updated_at", "published_at", "published"}).
			AddRow(noteID, userID, "", "Test content", now, now, nil, false)
		mock.ExpectQuery(`select id, user_id, title, content, created_at, updated_at, published_at, published from notes where id = \$1 and user_id = \$2`).
			WithArgs(noteID, userID).
			WillReturnRows(noteRows)

		// Assign tags
		mock.ExpectBegin()
		mock.ExpectExec(`DELETE FROM note_tags WHERE note_id = \$1`).
			WithArgs(noteID).
			WillReturnResult(pgxmock.NewResult("DELETE", 0))
		mock.ExpectExec(`INSERT INTO note_tags \(note_id, tag_id\) VALUES \(\$1, \$2\)`).
			WithArgs(noteID, tagID).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))
		mock.ExpectCommit()

		// Return tags
		tagsRows := pgxmock.NewRows([]string{"id", "name"}).
			AddRow(tagID, "test-tag")
		mock.ExpectQuery(`SELECT t\.id, t\.name FROM tags t JOIN note_tags nt ON t\.id = nt\.tag_id WHERE nt\.note_id = \$1`).
			WithArgs(noteID).
			WillReturnRows(tagsRows)

		assignReq := requests.AssignTags{
			TagIDs: []uuid.UUID{tagID},
		}
		body, _ := json.Marshal(assignReq)
		req := createTestRequestWithAuth("POST", "/notes/"+noteID.String()+"/tags", body, userID, "testuser")
		
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", noteID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()

		handler.AssignNoteTags(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	// Step 3: Remove tag from note
	t.Run("remove_tag", func(t *testing.T) {
		// Verify user access
		noteRows := pgxmock.NewRows([]string{"id", "user_id", "title", "content", "created_at", "updated_at", "published_at", "published"}).
			AddRow(noteID, userID, "", "Test content", now, now, nil, false)
		mock.ExpectQuery(`select id, user_id, title, content, created_at, updated_at, published_at, published from notes where id = \$1 and user_id = \$2`).
			WithArgs(noteID, userID).
			WillReturnRows(noteRows)

		// Remove tag
		mock.ExpectExec(`DELETE FROM note_tags WHERE note_id = \$1 AND tag_id = \$2`).
			WithArgs(noteID, tagID).
			WillReturnResult(pgxmock.NewResult("DELETE", 1))

		req := createTestRequestWithAuth("DELETE", "/notes/"+noteID.String()+"/tags/"+tagID.String(), nil, userID, "testuser")
		
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", noteID.String())
		rctx.URLParams.Add("tagId", tagID.String())
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()

		handler.RemoveNoteTag(w, req)
		assert.Equal(t, http.StatusNoContent, w.Code)
	})

	assert.NoError(t, mock.ExpectationsWereMet())
}