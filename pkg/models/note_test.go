package models

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNote_JSONSerialization(t *testing.T) {
	noteID := uuid.New()
	userID := uuid.New()
	tagID1 := uuid.New()
	tagID2 := uuid.New()
	now := time.Now().UTC()

	note := Note{
		ID:          noteID,
		UserID:      userID,
		Title:       "Test Note",
		Content:     "This is test content",
		CreatedAt:   now,
		UpdatedAt:   now,
		PublishedAt: &now,
		Published:   true,
		Tags: []Tag{
			{ID: tagID1, Name: "tag1"},
			{ID: tagID2, Name: "tag2"},
		},
	}

	t.Run("marshal to JSON", func(t *testing.T) {
		jsonData, err := json.Marshal(note)
		require.NoError(t, err)
		assert.NotEmpty(t, jsonData)

		// Verify JSON contains expected fields
		var jsonMap map[string]interface{}
		err = json.Unmarshal(jsonData, &jsonMap)
		require.NoError(t, err)

		assert.Equal(t, noteID.String(), jsonMap["id"])
		assert.Equal(t, userID.String(), jsonMap["userId"])
		assert.Equal(t, "Test Note", jsonMap["title"])
		assert.Equal(t, "This is test content", jsonMap["content"])
		assert.Equal(t, true, jsonMap["published"])
		assert.Contains(t, jsonMap, "createdAt")
		assert.Contains(t, jsonMap, "updatedAt")
		assert.Contains(t, jsonMap, "publishedAt")
		assert.Contains(t, jsonMap, "tags")

		// Verify tags array
		tags, ok := jsonMap["tags"].([]interface{})
		require.True(t, ok)
		assert.Len(t, tags, 2)
	})

	t.Run("unmarshal from JSON", func(t *testing.T) {
		jsonStr := `{
			"id": "` + noteID.String() + `",
			"userId": "` + userID.String() + `",
			"title": "Test Note",
			"content": "This is test content",
			"createdAt": "` + now.Format(time.RFC3339Nano) + `",
			"updatedAt": "` + now.Format(time.RFC3339Nano) + `",
			"publishedAt": "` + now.Format(time.RFC3339Nano) + `",
			"published": true,
			"tags": [
				{"id": "` + tagID1.String() + `", "name": "tag1"},
				{"id": "` + tagID2.String() + `", "name": "tag2"}
			]
		}`

		var parsedNote Note
		err := json.Unmarshal([]byte(jsonStr), &parsedNote)
		require.NoError(t, err)

		assert.Equal(t, noteID, parsedNote.ID)
		assert.Equal(t, userID, parsedNote.UserID)
		assert.Equal(t, "Test Note", parsedNote.Title)
		assert.Equal(t, "This is test content", parsedNote.Content)
		assert.True(t, parsedNote.Published)
		assert.NotNil(t, parsedNote.PublishedAt)
		assert.Equal(t, now.Truncate(time.Microsecond), parsedNote.PublishedAt.Truncate(time.Microsecond))
		assert.Len(t, parsedNote.Tags, 2)
		assert.Equal(t, "tag1", parsedNote.Tags[0].Name)
		assert.Equal(t, "tag2", parsedNote.Tags[1].Name)
	})

	t.Run("round trip serialization", func(t *testing.T) {
		// Marshal
		jsonData, err := json.Marshal(note)
		require.NoError(t, err)

		// Unmarshal
		var parsedNote Note
		err = json.Unmarshal(jsonData, &parsedNote)
		require.NoError(t, err)

		// Compare (with time truncation for compatibility)
		assert.Equal(t, note.ID, parsedNote.ID)
		assert.Equal(t, note.UserID, parsedNote.UserID)
		assert.Equal(t, note.Title, parsedNote.Title)
		assert.Equal(t, note.Content, parsedNote.Content)
		assert.Equal(t, note.Published, parsedNote.Published)
		assert.Equal(t, note.CreatedAt.Truncate(time.Microsecond), parsedNote.CreatedAt.Truncate(time.Microsecond))
		assert.Equal(t, note.UpdatedAt.Truncate(time.Microsecond), parsedNote.UpdatedAt.Truncate(time.Microsecond))
		
		if note.PublishedAt != nil {
			require.NotNil(t, parsedNote.PublishedAt)
			assert.Equal(t, note.PublishedAt.Truncate(time.Microsecond), parsedNote.PublishedAt.Truncate(time.Microsecond))
		}
		
		assert.Len(t, parsedNote.Tags, len(note.Tags))
	})
}

func TestNote_NullableFields(t *testing.T) {
	noteID := uuid.New()
	userID := uuid.New()

	t.Run("note with null published_at", func(t *testing.T) {
		note := Note{
			ID:          noteID,
			UserID:      userID,
			Title:       "Unpublished Note",
			Content:     "Draft content",
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
			PublishedAt: nil, // NULL
			Published:   false,
			Tags:        []Tag{},
		}

		jsonData, err := json.Marshal(note)
		require.NoError(t, err)

		var jsonMap map[string]interface{}
		err = json.Unmarshal(jsonData, &jsonMap)
		require.NoError(t, err)

		assert.Nil(t, jsonMap["publishedAt"])
		assert.False(t, jsonMap["published"].(bool))

		// Round trip test
		var parsedNote Note
		err = json.Unmarshal(jsonData, &parsedNote)
		require.NoError(t, err)

		assert.Nil(t, parsedNote.PublishedAt)
		assert.False(t, parsedNote.Published)
	})

	t.Run("note with empty tags", func(t *testing.T) {
		note := Note{
			ID:        noteID,
			UserID:    userID,
			Title:     "No Tags Note",
			Content:   "Content without tags",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			Tags:      []Tag{}, // Empty slice
		}

		jsonData, err := json.Marshal(note)
		require.NoError(t, err)

		var parsedNote Note
		err = json.Unmarshal(jsonData, &parsedNote)
		require.NoError(t, err)

		assert.Empty(t, parsedNote.Tags)
	})

	t.Run("note with nil tags", func(t *testing.T) {
		note := Note{
			ID:        noteID,
			UserID:    userID,
			Title:     "Nil Tags Note",
			Content:   "Content with nil tags",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			Tags:      nil, // Nil slice
		}

		jsonData, err := json.Marshal(note)
		require.NoError(t, err)

		var parsedNote Note
		err = json.Unmarshal(jsonData, &parsedNote)
		require.NoError(t, err)

		// JSON unmarshaling null creates nil slice
		assert.Nil(t, parsedNote.Tags)
	})
}

func TestNote_JSONValidation(t *testing.T) {
	tests := []struct {
		name        string
		jsonStr     string
		expectError bool
		checkResult func(t *testing.T, note Note)
	}{
		{
			name: "valid complete note",
			jsonStr: `{
				"id": "550e8400-e29b-41d4-a716-446655440000",
				"userId": "550e8400-e29b-41d4-a716-446655440001",
				"title": "Valid Note",
				"content": "Valid content",
				"createdAt": "2023-01-01T12:00:00Z",
				"updatedAt": "2023-01-01T12:00:00Z",
				"publishedAt": "2023-01-01T12:00:00Z",
				"published": true,
				"tags": []
			}`,
			expectError: false,
			checkResult: func(t *testing.T, note Note) {
				assert.Equal(t, "Valid Note", note.Title)
				assert.Equal(t, "Valid content", note.Content)
				assert.True(t, note.Published)
				assert.NotNil(t, note.PublishedAt)
				assert.Empty(t, note.Tags)
			},
		},
		{
			name: "minimal note",
			jsonStr: `{
				"id": "550e8400-e29b-41d4-a716-446655440000",
				"userId": "550e8400-e29b-41d4-a716-446655440001",
				"content": "Minimal content"
			}`,
			expectError: false,
			checkResult: func(t *testing.T, note Note) {
				assert.Equal(t, "Minimal content", note.Content)
				assert.Empty(t, note.Title)
				assert.False(t, note.Published)
				assert.Nil(t, note.PublishedAt)
			},
		},
		{
			name: "invalid UUID format",
			jsonStr: `{
				"id": "invalid-uuid",
				"userId": "550e8400-e29b-41d4-a716-446655440001",
				"content": "content"
			}`,
			expectError: true,
		},
		{
			name: "invalid time format",
			jsonStr: `{
				"id": "550e8400-e29b-41d4-a716-446655440000",
				"userId": "550e8400-e29b-41d4-a716-446655440001",
				"content": "content",
				"createdAt": "invalid-time"
			}`,
			expectError: true,
		},
		{
			name: "invalid tags format",
			jsonStr: `{
				"id": "550e8400-e29b-41d4-a716-446655440000",
				"userId": "550e8400-e29b-41d4-a716-446655440001",
				"content": "content",
				"tags": "not-an-array"
			}`,
			expectError: true,
		},
		{
			name: "very long content",
			jsonStr: `{
				"id": "550e8400-e29b-41d4-a716-446655440000",
				"userId": "550e8400-e29b-41d4-a716-446655440001",
				"content": "` + strings.Repeat("a", 10000) + `"
			}`,
			expectError: false,
			checkResult: func(t *testing.T, note Note) {
				assert.Len(t, note.Content, 10000)
			},
		},
		{
			name: "unicode content",
			jsonStr: `{
				"id": "550e8400-e29b-41d4-a716-446655440000",
				"userId": "550e8400-e29b-41d4-a716-446655440001",
				"title": "测试笔记",
				"content": "这是中文内容 🚀"
			}`,
			expectError: false,
			checkResult: func(t *testing.T, note Note) {
				assert.Equal(t, "测试笔记", note.Title)
				assert.Equal(t, "这是中文内容 🚀", note.Content)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var note Note
			err := json.Unmarshal([]byte(tt.jsonStr), &note)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				if tt.checkResult != nil {
					tt.checkResult(t, note)
				}
			}
		})
	}
}

func TestNote_JSONFieldMapping(t *testing.T) {
	// Test that JSON field tags are working correctly
	noteID := uuid.New()
	userID := uuid.New()
	now := time.Now()

	note := Note{
		ID:          noteID,
		UserID:      userID,
		Title:       "Field Test",
		Content:     "Testing field mapping",
		CreatedAt:   now,
		UpdatedAt:   now,
		PublishedAt: &now,
		Published:   true,
		Tags:        []Tag{{ID: uuid.New(), Name: "test"}},
	}

	jsonData, err := json.Marshal(note)
	require.NoError(t, err)

	// Parse as generic map to check field names
	var fields map[string]interface{}
	err = json.Unmarshal(jsonData, &fields)
	require.NoError(t, err)

	// Verify JSON field names match struct tags
	expectedFields := []string{"id", "userId", "title", "content", "createdAt", "updatedAt", "publishedAt", "published", "tags"}
	for _, field := range expectedFields {
		assert.Contains(t, fields, field, "JSON should contain field: %s", field)
	}

	// Verify Go field names are NOT in JSON
	unexpectedFields := []string{"ID", "UserID", "Title", "Content", "CreatedAt", "UpdatedAt", "PublishedAt", "Published", "Tags"}
	for _, field := range unexpectedFields {
		assert.NotContains(t, fields, field, "JSON should not contain Go field name: %s", field)
	}
}

func TestNote_DatabaseTagHandling(t *testing.T) {
	// Test that the `db:"-"` tag for Tags field works as expected
	// This is important because Tags are loaded separately in the repository
	noteID := uuid.New()
	userID := uuid.New()

	note := Note{
		ID:      noteID,
		UserID:  userID,
		Title:   "DB Tag Test",
		Content: "Testing database tag handling",
		Tags: []Tag{
			{ID: uuid.New(), Name: "should-not-affect-db"},
		},
	}

	// The Tags field should serialize to JSON normally
	jsonData, err := json.Marshal(note)
	require.NoError(t, err)

	var jsonMap map[string]interface{}
	err = json.Unmarshal(jsonData, &jsonMap)
	require.NoError(t, err)

	// Tags should be present in JSON
	assert.Contains(t, jsonMap, "tags")
	tags, ok := jsonMap["tags"].([]interface{})
	require.True(t, ok)
	assert.Len(t, tags, 1)
}

func TestNote_EdgeCases(t *testing.T) {
	t.Run("zero values", func(t *testing.T) {
		note := Note{
			ID:     uuid.Nil,
			UserID: uuid.Nil,
		}

		jsonData, err := json.Marshal(note)
		require.NoError(t, err)

		var parsed Note
		err = json.Unmarshal(jsonData, &parsed)
		require.NoError(t, err)

		assert.Equal(t, uuid.Nil, parsed.ID)
		assert.Equal(t, uuid.Nil, parsed.UserID)
		assert.Empty(t, parsed.Title)
		assert.Empty(t, parsed.Content)
		assert.False(t, parsed.Published)
	})

	t.Run("special characters in content", func(t *testing.T) {
		specialContent := "Content with\nnewlines\tand\ttabs\"quotes\"and'apostrophes'and\\backslashes"

		note := Note{
			ID:      uuid.New(),
			UserID:  uuid.New(),
			Title:   "Special \"Chars\" & Symbols",
			Content: specialContent,
		}

		jsonData, err := json.Marshal(note)
		require.NoError(t, err)

		var parsed Note
		err = json.Unmarshal(jsonData, &parsed)
		require.NoError(t, err)

		assert.Equal(t, "Special \"Chars\" & Symbols", parsed.Title)
		assert.Equal(t, specialContent, parsed.Content)
	})

	t.Run("time zone handling", func(t *testing.T) {
		// Test with different time zones
		utcTime := time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)
		localTime := utcTime.In(time.FixedZone("TEST", 3*3600)) // UTC+3

		note := Note{
			ID:          uuid.New(),
			UserID:      uuid.New(),
			Content:     "Timezone test",
			CreatedAt:   utcTime,
			UpdatedAt:   localTime,
			PublishedAt: &localTime,
		}

		jsonData, err := json.Marshal(note)
		require.NoError(t, err)

		var parsed Note
		err = json.Unmarshal(jsonData, &parsed)
		require.NoError(t, err)

		// Times should be preserved with their timezone info
		assert.Equal(t, utcTime.Unix(), parsed.CreatedAt.Unix())
		assert.Equal(t, localTime.Unix(), parsed.UpdatedAt.Unix())
		assert.Equal(t, localTime.Unix(), parsed.PublishedAt.Unix())
	})

	t.Run("large tag collections", func(t *testing.T) {
		// Test with many tags
		tags := make([]Tag, 100)
		for i := range tags {
			tags[i] = Tag{
				ID:   uuid.New(),
				Name: fmt.Sprintf("tag-%d", i),
			}
		}

		note := Note{
			ID:      uuid.New(),
			UserID:  uuid.New(),
			Content: "Many tags test",
			Tags:    tags,
		}

		jsonData, err := json.Marshal(note)
		require.NoError(t, err)

		var parsed Note
		err = json.Unmarshal(jsonData, &parsed)
		require.NoError(t, err)

		assert.Len(t, parsed.Tags, 100)
		assert.Equal(t, "tag-0", parsed.Tags[0].Name)
		assert.Equal(t, "tag-99", parsed.Tags[99].Name)
	})
}