package models

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTag_JSONSerialization(t *testing.T) {
	tagID := uuid.New()

	tag := Tag{
		ID:   tagID,
		Name: "test-tag",
	}

	t.Run("marshal to JSON", func(t *testing.T) {
		jsonData, err := json.Marshal(tag)
		require.NoError(t, err)
		assert.NotEmpty(t, jsonData)

		// Verify JSON contains expected fields
		var jsonMap map[string]interface{}
		err = json.Unmarshal(jsonData, &jsonMap)
		require.NoError(t, err)

		assert.Equal(t, tagID.String(), jsonMap["id"])
		assert.Equal(t, "test-tag", jsonMap["name"])
	})

	t.Run("unmarshal from JSON", func(t *testing.T) {
		jsonStr := `{
			"id": "` + tagID.String() + `",
			"name": "test-tag"
		}`

		var parsedTag Tag
		err := json.Unmarshal([]byte(jsonStr), &parsedTag)
		require.NoError(t, err)

		assert.Equal(t, tagID, parsedTag.ID)
		assert.Equal(t, "test-tag", parsedTag.Name)
	})

	t.Run("round trip serialization", func(t *testing.T) {
		// Marshal
		jsonData, err := json.Marshal(tag)
		require.NoError(t, err)

		// Unmarshal
		var parsedTag Tag
		err = json.Unmarshal(jsonData, &parsedTag)
		require.NoError(t, err)

		// Compare
		assert.Equal(t, tag.ID, parsedTag.ID)
		assert.Equal(t, tag.Name, parsedTag.Name)
	})
}

func TestTag_JSONValidation(t *testing.T) {
	tests := []struct {
		name        string
		jsonStr     string
		expectError bool
		checkResult func(t *testing.T, tag Tag)
	}{
		{
			name: "valid tag",
			jsonStr: `{
				"id": "550e8400-e29b-41d4-a716-446655440000",
				"name": "valid-tag"
			}`,
			expectError: false,
			checkResult: func(t *testing.T, tag Tag) {
				assert.Equal(t, "valid-tag", tag.Name)
				assert.NotEqual(t, uuid.Nil, tag.ID)
			},
		},
		{
			name: "empty tag name",
			jsonStr: `{
				"id": "550e8400-e29b-41d4-a716-446655440000",
				"name": ""
			}`,
			expectError: false,
			checkResult: func(t *testing.T, tag Tag) {
				assert.Empty(t, tag.Name)
			},
		},
		{
			name: "missing name field",
			jsonStr: `{
				"id": "550e8400-e29b-41d4-a716-446655440000"
			}`,
			expectError: false,
			checkResult: func(t *testing.T, tag Tag) {
				assert.Empty(t, tag.Name)
			},
		},
		{
			name: "missing id field",
			jsonStr: `{
				"name": "tagname"
			}`,
			expectError: false,
			checkResult: func(t *testing.T, tag Tag) {
				assert.Equal(t, "tagname", tag.Name)
				assert.Equal(t, uuid.Nil, tag.ID)
			},
		},
		{
			name: "invalid UUID format",
			jsonStr: `{
				"id": "invalid-uuid",
				"name": "tagname"
			}`,
			expectError: true,
		},
		{
			name: "special characters in name",
			jsonStr: `{
				"id": "550e8400-e29b-41d4-a716-446655440000",
				"name": "tag-with_special.chars@domain.com"
			}`,
			expectError: false,
			checkResult: func(t *testing.T, tag Tag) {
				assert.Equal(t, "tag-with_special.chars@domain.com", tag.Name)
			},
		},
		{
			name: "unicode tag name",
			jsonStr: `{
				"id": "550e8400-e29b-41d4-a716-446655440000",
				"name": "标签名称"
			}`,
			expectError: false,
			checkResult: func(t *testing.T, tag Tag) {
				assert.Equal(t, "标签名称", tag.Name)
			},
		},
		{
			name: "very long tag name",
			jsonStr: `{
				"id": "550e8400-e29b-41d4-a716-446655440000",
				"name": "` + strings.Repeat("a", 1000) + `"
			}`,
			expectError: false,
			checkResult: func(t *testing.T, tag Tag) {
				assert.Len(t, tag.Name, 1000)
			},
		},
		{
			name:        "malformed JSON",
			jsonStr:     `{"id": "550e8400-e29b-41d4-a716-446655440000", "name":}`,
			expectError: true,
		},
		{
			name:        "empty JSON object",
			jsonStr:     `{}`,
			expectError: false,
			checkResult: func(t *testing.T, tag Tag) {
				assert.Equal(t, uuid.Nil, tag.ID)
				assert.Empty(t, tag.Name)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var tag Tag
			err := json.Unmarshal([]byte(tt.jsonStr), &tag)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				if tt.checkResult != nil {
					tt.checkResult(t, tag)
				}
			}
		})
	}
}

func TestTag_JSONFieldMapping(t *testing.T) {
	// Test that JSON field tags are working correctly
	tagID := uuid.New()
	tag := Tag{
		ID:   tagID,
		Name: "fieldtest",
	}

	jsonData, err := json.Marshal(tag)
	require.NoError(t, err)

	// Parse as generic map to check field names
	var fields map[string]interface{}
	err = json.Unmarshal(jsonData, &fields)
	require.NoError(t, err)

	// Verify JSON field names match struct tags
	expectedFields := []string{"id", "name"}
	for _, field := range expectedFields {
		assert.Contains(t, fields, field, "JSON should contain field: %s", field)
	}

	// Verify Go field names are NOT in JSON
	unexpectedFields := []string{"ID", "Name"}
	for _, field := range unexpectedFields {
		assert.NotContains(t, fields, field, "JSON should not contain Go field name: %s", field)
	}
}

func TestTag_EdgeCases(t *testing.T) {
	t.Run("zero UUID", func(t *testing.T) {
		tag := Tag{
			ID:   uuid.Nil,
			Name: "zerotag",
		}

		jsonData, err := json.Marshal(tag)
		require.NoError(t, err)

		var parsed Tag
		err = json.Unmarshal(jsonData, &parsed)
		require.NoError(t, err)

		assert.Equal(t, uuid.Nil, parsed.ID)
		assert.Equal(t, "zerotag", parsed.Name)
	})

	t.Run("whitespace in tag name", func(t *testing.T) {
		tag := Tag{
			ID:   uuid.New(),
			Name: "  tag with spaces  ",
		}

		jsonData, err := json.Marshal(tag)
		require.NoError(t, err)

		var parsed Tag
		err = json.Unmarshal(jsonData, &parsed)
		require.NoError(t, err)

		// Whitespace should be preserved
		assert.Equal(t, "  tag with spaces  ", parsed.Name)
	})

	t.Run("newlines and tabs in tag name", func(t *testing.T) {
		tag := Tag{
			ID:   uuid.New(),
			Name: "tag\nwith\nnewlines\tand\ttabs",
		}

		jsonData, err := json.Marshal(tag)
		require.NoError(t, err)

		var parsed Tag
		err = json.Unmarshal(jsonData, &parsed)
		require.NoError(t, err)

		assert.Equal(t, "tag\nwith\nnewlines\tand\ttabs", parsed.Name)
	})

	t.Run("quotes and escapes in tag name", func(t *testing.T) {
		tag := Tag{
			ID:   uuid.New(),
			Name: `tag"with"quotes'and'backslashes\`,
		}

		jsonData, err := json.Marshal(tag)
		require.NoError(t, err)

		var parsed Tag
		err = json.Unmarshal(jsonData, &parsed)
		require.NoError(t, err)

		assert.Equal(t, `tag"with"quotes'and'backslashes\`, parsed.Name)
	})

	t.Run("emoji in tag name", func(t *testing.T) {
		tag := Tag{
			ID:   uuid.New(),
			Name: "🏷️ tag-with-emoji 🚀",
		}

		jsonData, err := json.Marshal(tag)
		require.NoError(t, err)

		var parsed Tag
		err = json.Unmarshal(jsonData, &parsed)
		require.NoError(t, err)

		assert.Equal(t, "🏷️ tag-with-emoji 🚀", parsed.Name)
	})
}

func TestTag_ArraySerialization(t *testing.T) {
	// Test serialization of tag arrays (common use case)
	tags := []Tag{
		{ID: uuid.New(), Name: "tag1"},
		{ID: uuid.New(), Name: "tag2"},
		{ID: uuid.New(), Name: "tag3"},
	}

	t.Run("marshal tag array", func(t *testing.T) {
		jsonData, err := json.Marshal(tags)
		require.NoError(t, err)
		assert.NotEmpty(t, jsonData)

		var jsonArray []interface{}
		err = json.Unmarshal(jsonData, &jsonArray)
		require.NoError(t, err)
		assert.Len(t, jsonArray, 3)
	})

	t.Run("unmarshal tag array", func(t *testing.T) {
		jsonStr := `[
			{"id": "550e8400-e29b-41d4-a716-446655440000", "name": "tag1"},
			{"id": "550e8400-e29b-41d4-a716-446655440001", "name": "tag2"},
			{"id": "550e8400-e29b-41d4-a716-446655440002", "name": "tag3"}
		]`

		var parsedTags []Tag
		err := json.Unmarshal([]byte(jsonStr), &parsedTags)
		require.NoError(t, err)

		assert.Len(t, parsedTags, 3)
		assert.Equal(t, "tag1", parsedTags[0].Name)
		assert.Equal(t, "tag2", parsedTags[1].Name)
		assert.Equal(t, "tag3", parsedTags[2].Name)
	})

	t.Run("round trip tag array", func(t *testing.T) {
		jsonData, err := json.Marshal(tags)
		require.NoError(t, err)

		var parsedTags []Tag
		err = json.Unmarshal(jsonData, &parsedTags)
		require.NoError(t, err)

		assert.Len(t, parsedTags, len(tags))
		for i, tag := range tags {
			assert.Equal(t, tag.ID, parsedTags[i].ID)
			assert.Equal(t, tag.Name, parsedTags[i].Name)
		}
	})

	t.Run("empty tag array", func(t *testing.T) {
		var emptyTags []Tag

		jsonData, err := json.Marshal(emptyTags)
		require.NoError(t, err)

		var parsed []Tag
		err = json.Unmarshal(jsonData, &parsed)
		require.NoError(t, err)

		assert.Empty(t, parsed)
	})

	t.Run("nil tag array", func(t *testing.T) {
		var nilTags []Tag = nil

		jsonData, err := json.Marshal(nilTags)
		require.NoError(t, err)

		var parsed []Tag
		err = json.Unmarshal(jsonData, &parsed)
		require.NoError(t, err)

		// JSON unmarshaling null creates nil slice
		assert.Nil(t, parsed)
	})
}