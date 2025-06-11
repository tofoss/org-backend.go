package repositories

import (
	"context"
	"fmt"
	"testing"
	"time"
	"tofoss/org-go/pkg/models"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNoteRepository_Upsert(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	repo := NewNoteRepository(mock)
	ctx := context.Background()

	noteID := uuid.New()
	userID := uuid.New()
	now := time.Now()

	note := models.Note{
		ID:        noteID,
		UserID:    userID,
		Title:     "Test Note",
		Content:   "Test Content",
		CreatedAt: now,
		UpdatedAt: now,
		Published: true,
	}

	t.Run("successful upsert", func(t *testing.T) {
		expectedQuery := `INSERT INTO notes \(id, user_id, title, content, created_at, updated_at, published_at, published\) 
			VALUES \(\$1, \$2, \$3, \$4, \$5, \$6, \$7, \$8\) 
	        ON CONFLICT \(id\) DO UPDATE SET 
				user_id = EXCLUDED\.user_id, 
				title = EXCLUDED\.title, 
				content = EXCLUDED\.content, 
				updated_at = EXCLUDED\.updated_at, 
				published_at = EXCLUDED\.published_at,
				published = EXCLUDED\.published 
	        RETURNING id, user_id, title, content, created_at, updated_at, published_at, published`

		rows := pgxmock.NewRows([]string{"id", "user_id", "title", "content", "created_at", "updated_at", "published_at", "published"}).
			AddRow(note.ID, note.UserID, note.Title, note.Content, note.CreatedAt, note.UpdatedAt, note.PublishedAt, note.Published)

		mock.ExpectQuery(expectedQuery).
			WithArgs(note.ID, note.UserID, note.Title, note.Content, note.CreatedAt, note.UpdatedAt, note.PublishedAt, note.Published).
			WillReturnRows(rows)

		result, err := repo.Upsert(ctx, note)

		require.NoError(t, err)
		assert.Equal(t, note.ID, result.ID)
		assert.Equal(t, note.UserID, result.UserID)
		assert.Equal(t, note.Title, result.Title)
		assert.Equal(t, note.Content, result.Content)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("database error", func(t *testing.T) {
		mock.ExpectQuery(`INSERT INTO notes`).
			WithArgs(note.ID, note.UserID, note.Title, note.Content, note.CreatedAt, note.UpdatedAt, note.PublishedAt, note.Published).
			WillReturnError(fmt.Errorf("database connection error"))

		_, err := repo.Upsert(ctx, note)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "database connection error")
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestNoteRepository_FetchNote(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	repo := NewNoteRepository(mock)
	ctx := context.Background()

	noteID := uuid.New()
	userID := uuid.New()
	now := time.Now()

	t.Run("successful fetch", func(t *testing.T) {
		expectedQuery := `select id, user_id, title, content, created_at, updated_at, published_at, published from notes where id = \$1`

		rows := pgxmock.NewRows([]string{"id", "user_id", "title", "content", "created_at", "updated_at", "published_at", "published"}).
			AddRow(noteID, userID, "Test Note", "Test Content", now, now, &now, true)

		mock.ExpectQuery(expectedQuery).
			WithArgs(noteID).
			WillReturnRows(rows)

		result, err := repo.FetchNote(ctx, noteID)

		require.NoError(t, err)
		assert.Equal(t, noteID, result.ID)
		assert.Equal(t, userID, result.UserID)
		assert.Equal(t, "Test Note", result.Title)
		assert.Equal(t, "Test Content", result.Content)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("note not found", func(t *testing.T) {
		mock.ExpectQuery(`select id, user_id, title, content, created_at, updated_at, published_at, published from notes where id = \$1`).
			WithArgs(noteID).
			WillReturnError(pgx.ErrNoRows)

		_, err := repo.FetchNote(ctx, noteID)

		assert.Error(t, err)
		assert.Equal(t, pgx.ErrNoRows, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestNoteRepository_FetchUsersNote(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	repo := NewNoteRepository(mock)
	ctx := context.Background()

	noteID := uuid.New()
	userID := uuid.New()
	now := time.Now()

	t.Run("successful fetch users note", func(t *testing.T) {
		expectedQuery := `select id, user_id, title, content, created_at, updated_at, published_at, published from notes where id = \$1 and user_id = \$2`

		rows := pgxmock.NewRows([]string{"id", "user_id", "title", "content", "created_at", "updated_at", "published_at", "published"}).
			AddRow(noteID, userID, "User Note", "User Content", now, now, nil, false)

		mock.ExpectQuery(expectedQuery).
			WithArgs(noteID, userID).
			WillReturnRows(rows)

		result, err := repo.FetchUsersNote(ctx, noteID, userID)

		require.NoError(t, err)
		assert.Equal(t, noteID, result.ID)
		assert.Equal(t, userID, result.UserID)
		assert.Equal(t, "User Note", result.Title)
		assert.False(t, result.Published)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("unauthorized access", func(t *testing.T) {
		wrongUserID := uuid.New()

		mock.ExpectQuery(`select id, user_id, title, content, created_at, updated_at, published_at, published from notes where id = \$1 and user_id = \$2`).
			WithArgs(noteID, wrongUserID).
			WillReturnError(pgx.ErrNoRows)

		_, err := repo.FetchUsersNote(ctx, noteID, wrongUserID)

		assert.Error(t, err)
		assert.Equal(t, pgx.ErrNoRows, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestNoteRepository_FetchUsersNotes(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	repo := NewNoteRepository(mock)
	ctx := context.Background()

	userID := uuid.New()
	note1ID := uuid.New()
	note2ID := uuid.New()
	tag1ID := uuid.New()
	tag2ID := uuid.New()
	now := time.Now()

	t.Run("successful fetch with tags", func(t *testing.T) {
		// Mock the notes query
		notesQuery := `select id, user_id, title, content, created_at, updated_at, published_at, published from notes where user_id = \$1`
		notesRows := pgxmock.NewRows([]string{"id", "user_id", "title", "content", "created_at", "updated_at", "published_at", "published"}).
			AddRow(note1ID, userID, "Note 1", "Content 1", now, now, nil, false).
			AddRow(note2ID, userID, "Note 2", "Content 2", now, now, &now, true)

		mock.ExpectQuery(notesQuery).
			WithArgs(userID).
			WillReturnRows(notesRows)

		// Mock the tags query
		tagsQuery := `SELECT nt\.note_id, t\.id, t\.name 
			FROM tags t 
			JOIN note_tags nt ON t\.id = nt\.tag_id 
			WHERE nt\.note_id = ANY\(\$1\)
			ORDER BY nt\.note_id, t\.name`
		tagsRows := pgxmock.NewRows([]string{"note_id", "id", "name"}).
			AddRow(note1ID, tag1ID, "tag1").
			AddRow(note2ID, tag2ID, "tag2")

		mock.ExpectQuery(tagsQuery).
			WithArgs(pgxmock.AnyArg()).
			WillReturnRows(tagsRows)

		results, err := repo.FetchUsersNotes(ctx, userID)

		require.NoError(t, err)
		assert.Len(t, results, 2)
		
		// Verify notes
		assert.Equal(t, note1ID, results[0].ID)
		assert.Equal(t, "Note 1", results[0].Title)
		assert.Len(t, results[0].Tags, 1)
		assert.Equal(t, "tag1", results[0].Tags[0].Name)
		
		assert.Equal(t, note2ID, results[1].ID)
		assert.Equal(t, "Note 2", results[1].Title)
		assert.Len(t, results[1].Tags, 1)
		assert.Equal(t, "tag2", results[1].Tags[0].Name)
		
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("no notes found", func(t *testing.T) {
		notesQuery := `select id, user_id, title, content, created_at, updated_at, published_at, published from notes where user_id = \$1`
		notesRows := pgxmock.NewRows([]string{"id", "user_id", "title", "content", "created_at", "updated_at", "published_at", "published"})

		mock.ExpectQuery(notesQuery).
			WithArgs(userID).
			WillReturnRows(notesRows)

		// Mock empty tags query
		tagsQuery := `SELECT nt\.note_id, t\.id, t\.name`
		tagsRows := pgxmock.NewRows([]string{"note_id", "id", "name"})

		mock.ExpectQuery(tagsQuery).
			WithArgs(pgxmock.AnyArg()).
			WillReturnRows(tagsRows)

		results, err := repo.FetchUsersNotes(ctx, userID)

		require.NoError(t, err)
		assert.Empty(t, results)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestNoteRepository_GetTagsForNote(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	repo := NewNoteRepository(mock)
	ctx := context.Background()

	noteID := uuid.New()
	tag1ID := uuid.New()
	tag2ID := uuid.New()

	t.Run("successful get tags", func(t *testing.T) {
		expectedQuery := `SELECT t\.id, t\.name 
			FROM tags t 
			JOIN note_tags nt ON t\.id = nt\.tag_id 
			WHERE nt\.note_id = \$1
			ORDER BY t\.name`

		rows := pgxmock.NewRows([]string{"id", "name"}).
			AddRow(tag1ID, "tag1").
			AddRow(tag2ID, "tag2")

		mock.ExpectQuery(expectedQuery).
			WithArgs(noteID).
			WillReturnRows(rows)

		tags, err := repo.GetTagsForNote(ctx, noteID)

		require.NoError(t, err)
		assert.Len(t, tags, 2)
		assert.Equal(t, "tag1", tags[0].Name)
		assert.Equal(t, "tag2", tags[1].Name)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("no tags found", func(t *testing.T) {
		expectedQuery := `SELECT t\.id, t\.name`
		rows := pgxmock.NewRows([]string{"id", "name"})

		mock.ExpectQuery(expectedQuery).
			WithArgs(noteID).
			WillReturnRows(rows)

		tags, err := repo.GetTagsForNote(ctx, noteID)

		require.NoError(t, err)
		assert.Empty(t, tags)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestNoteRepository_AssignTagsToNote(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	repo := NewNoteRepository(mock)
	ctx := context.Background()

	noteID := uuid.New()
	tag1ID := uuid.New()
	tag2ID := uuid.New()
	tagIDs := []uuid.UUID{tag1ID, tag2ID}

	t.Run("successful assign tags", func(t *testing.T) {
		// Mock transaction
		mock.ExpectBegin()
		
		// Mock delete existing tags
		mock.ExpectExec(`DELETE FROM note_tags WHERE note_id = \$1`).
			WithArgs(noteID).
			WillReturnResult(pgxmock.NewResult("DELETE", 0))
		
		// Mock insert new tags
		mock.ExpectExec(`INSERT INTO note_tags \(note_id, tag_id\) VALUES \(\$1, \$2\)`).
			WithArgs(noteID, tag1ID).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))
		
		mock.ExpectExec(`INSERT INTO note_tags \(note_id, tag_id\) VALUES \(\$1, \$2\)`).
			WithArgs(noteID, tag2ID).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))
		
		mock.ExpectCommit()

		err := repo.AssignTagsToNote(ctx, noteID, tagIDs)

		require.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("transaction rollback on error", func(t *testing.T) {
		mock.ExpectBegin()
		
		mock.ExpectExec(`DELETE FROM note_tags WHERE note_id = \$1`).
			WithArgs(noteID).
			WillReturnResult(pgxmock.NewResult("DELETE", 0))
		
		// Simulate error on insert
		mock.ExpectExec(`INSERT INTO note_tags \(note_id, tag_id\) VALUES \(\$1, \$2\)`).
			WithArgs(noteID, tag1ID).
			WillReturnError(fmt.Errorf("constraint violation"))
		
		mock.ExpectRollback()

		err := repo.AssignTagsToNote(ctx, noteID, tagIDs)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "constraint violation")
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("empty tag list", func(t *testing.T) {
		mock.ExpectBegin()
		
		mock.ExpectExec(`DELETE FROM note_tags WHERE note_id = \$1`).
			WithArgs(noteID).
			WillReturnResult(pgxmock.NewResult("DELETE", 2))
		
		mock.ExpectCommit()

		err := repo.AssignTagsToNote(ctx, noteID, []uuid.UUID{})

		require.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestNoteRepository_RemoveTagFromNote(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	repo := NewNoteRepository(mock)
	ctx := context.Background()

	noteID := uuid.New()
	tagID := uuid.New()

	t.Run("successful remove tag", func(t *testing.T) {
		expectedQuery := `DELETE FROM note_tags WHERE note_id = \$1 AND tag_id = \$2`

		mock.ExpectExec(expectedQuery).
			WithArgs(noteID, tagID).
			WillReturnResult(pgxmock.NewResult("DELETE", 1))

		err := repo.RemoveTagFromNote(ctx, noteID, tagID)

		require.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("tag not found", func(t *testing.T) {
		expectedQuery := `DELETE FROM note_tags WHERE note_id = \$1 AND tag_id = \$2`

		mock.ExpectExec(expectedQuery).
			WithArgs(noteID, tagID).
			WillReturnResult(pgxmock.NewResult("DELETE", 0))

		err := repo.RemoveTagFromNote(ctx, noteID, tagID)

		require.NoError(t, err) // Should not error even if no rows affected
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("database error", func(t *testing.T) {
		expectedQuery := `DELETE FROM note_tags WHERE note_id = \$1 AND tag_id = \$2`

		mock.ExpectExec(expectedQuery).
			WithArgs(noteID, tagID).
			WillReturnError(&pgconn.PgError{Code: "23503"}) // Foreign key violation

		err := repo.RemoveTagFromNote(ctx, noteID, tagID)

		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestNoteRepository_FetchNoteWithTags(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	repo := NewNoteRepository(mock)
	ctx := context.Background()

	noteID := uuid.New()
	userID := uuid.New()
	tagID := uuid.New()
	now := time.Now()

	t.Run("successful fetch note with tags", func(t *testing.T) {
		// Mock note fetch
		noteQuery := `select id, user_id, title, content, created_at, updated_at, published_at, published from notes where id = \$1`
		noteRows := pgxmock.NewRows([]string{"id", "user_id", "title", "content", "created_at", "updated_at", "published_at", "published"}).
			AddRow(noteID, userID, "Test Note", "Test Content", now, now, &now, true)

		mock.ExpectQuery(noteQuery).
			WithArgs(noteID).
			WillReturnRows(noteRows)

		// Mock tags fetch
		tagsQuery := `SELECT t\.id, t\.name 
			FROM tags t 
			JOIN note_tags nt ON t\.id = nt\.tag_id 
			WHERE nt\.note_id = \$1
			ORDER BY t\.name`
		tagsRows := pgxmock.NewRows([]string{"id", "name"}).
			AddRow(tagID, "test-tag")

		mock.ExpectQuery(tagsQuery).
			WithArgs(noteID).
			WillReturnRows(tagsRows)

		result, err := repo.FetchNoteWithTags(ctx, noteID)

		require.NoError(t, err)
		assert.Equal(t, noteID, result.ID)
		assert.Equal(t, "Test Note", result.Title)
		assert.Len(t, result.Tags, 1)
		assert.Equal(t, "test-tag", result.Tags[0].Name)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("note not found", func(t *testing.T) {
		noteQuery := `select id, user_id, title, content, created_at, updated_at, published_at, published from notes where id = \$1`

		mock.ExpectQuery(noteQuery).
			WithArgs(noteID).
			WillReturnError(pgx.ErrNoRows)

		_, err := repo.FetchNoteWithTags(ctx, noteID)

		assert.Error(t, err)
		assert.Equal(t, pgx.ErrNoRows, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestNoteRepository_GetTagsForNotes(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	repo := NewNoteRepository(mock)
	ctx := context.Background()

	note1ID := uuid.New()
	note2ID := uuid.New()
	tag1ID := uuid.New()
	tag2ID := uuid.New()
	noteIDs := []uuid.UUID{note1ID, note2ID}

	t.Run("successful bulk fetch", func(t *testing.T) {
		expectedQuery := `SELECT nt\.note_id, t\.id, t\.name 
			FROM tags t 
			JOIN note_tags nt ON t\.id = nt\.tag_id 
			WHERE nt\.note_id = ANY\(\$1\)
			ORDER BY nt\.note_id, t\.name`

		rows := pgxmock.NewRows([]string{"note_id", "id", "name"}).
			AddRow(note1ID, tag1ID, "tag1").
			AddRow(note2ID, tag2ID, "tag2")

		mock.ExpectQuery(expectedQuery).
			WithArgs(pgxmock.AnyArg()).
			WillReturnRows(rows)

		tagsMap, err := repo.GetTagsForNotes(ctx, noteIDs)

		require.NoError(t, err)
		assert.Len(t, tagsMap, 2)
		assert.Len(t, tagsMap[note1ID], 1)
		assert.Equal(t, "tag1", tagsMap[note1ID][0].Name)
		assert.Len(t, tagsMap[note2ID], 1)
		assert.Equal(t, "tag2", tagsMap[note2ID][0].Name)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("empty note IDs", func(t *testing.T) {
		tagsMap, err := repo.GetTagsForNotes(ctx, []uuid.UUID{})

		require.NoError(t, err)
		assert.Empty(t, tagsMap)
	})

	t.Run("notes with no tags", func(t *testing.T) {
		expectedQuery := `SELECT nt\.note_id, t\.id, t\.name`
		rows := pgxmock.NewRows([]string{"note_id", "id", "name"})

		mock.ExpectQuery(expectedQuery).
			WithArgs(pgxmock.AnyArg()).
			WillReturnRows(rows)

		tagsMap, err := repo.GetTagsForNotes(ctx, noteIDs)

		require.NoError(t, err)
		assert.Len(t, tagsMap, 2)
		assert.Empty(t, tagsMap[note1ID])
		assert.Empty(t, tagsMap[note2ID])
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}