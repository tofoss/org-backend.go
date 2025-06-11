package models

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUser_JSONSerialization(t *testing.T) {
	userID := uuid.New()

	user := User{
		ID:       userID,
		Username: "testuser",
	}

	t.Run("marshal to JSON", func(t *testing.T) {
		jsonData, err := json.Marshal(user)
		require.NoError(t, err)
		assert.NotEmpty(t, jsonData)

		// Verify JSON contains expected fields
		var jsonMap map[string]interface{}
		err = json.Unmarshal(jsonData, &jsonMap)
		require.NoError(t, err)

		assert.Equal(t, userID.String(), jsonMap["id"])
		assert.Equal(t, "testuser", jsonMap["username"])
	})

	t.Run("unmarshal from JSON", func(t *testing.T) {
		jsonStr := `{
			"id": "` + userID.String() + `",
			"username": "testuser"
		}`

		var parsedUser User
		err := json.Unmarshal([]byte(jsonStr), &parsedUser)
		require.NoError(t, err)

		assert.Equal(t, userID, parsedUser.ID)
		assert.Equal(t, "testuser", parsedUser.Username)
	})

	t.Run("round trip serialization", func(t *testing.T) {
		// Marshal
		jsonData, err := json.Marshal(user)
		require.NoError(t, err)

		// Unmarshal
		var parsedUser User
		err = json.Unmarshal(jsonData, &parsedUser)
		require.NoError(t, err)

		// Compare
		assert.Equal(t, user.ID, parsedUser.ID)
		assert.Equal(t, user.Username, parsedUser.Username)
	})
}

func TestUser_JSONValidation(t *testing.T) {
	tests := []struct {
		name        string
		jsonStr     string
		expectError bool
		checkResult func(t *testing.T, user User)
	}{
		{
			name: "valid complete user",
			jsonStr: `{
				"id": "550e8400-e29b-41d4-a716-446655440000",
				"username": "validuser"
			}`,
			expectError: false,
			checkResult: func(t *testing.T, user User) {
				assert.Equal(t, "validuser", user.Username)
				assert.NotEqual(t, uuid.Nil, user.ID)
			},
		},
		{
			name: "missing optional fields",
			jsonStr: `{
				"id": "550e8400-e29b-41d4-a716-446655440000",
				"username": "minimaluser"
			}`,
			expectError: false,
			checkResult: func(t *testing.T, user User) {
				assert.Equal(t, "minimaluser", user.Username)
				assert.NotEqual(t, uuid.Nil, user.ID)
			},
		},
		{
			name: "invalid UUID format",
			jsonStr: `{
				"id": "invalid-uuid",
				"username": "testuser"
			}`,
			expectError: true,
		},
		{
			name: "empty username",
			jsonStr: `{
				"id": "550e8400-e29b-41d4-a716-446655440000",
				"username": ""
			}`,
			expectError: false,
			checkResult: func(t *testing.T, user User) {
				assert.Empty(t, user.Username)
			},
		},
		{
			name: "unicode username",
			jsonStr: `{
				"id": "550e8400-e29b-41d4-a716-446655440000",
				"username": "用户名"
			}`,
			expectError: false,
			checkResult: func(t *testing.T, user User) {
				assert.Equal(t, "用户名", user.Username)
			},
		},
		{
			name:        "malformed JSON",
			jsonStr:     `{"id": "550e8400-e29b-41d4-a716-446655440000", "username":}`,
			expectError: true,
		},
		{
			name:        "empty JSON object",
			jsonStr:     `{}`,
			expectError: false,
			checkResult: func(t *testing.T, user User) {
				assert.Equal(t, uuid.Nil, user.ID)
				assert.Empty(t, user.Username)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var user User
			err := json.Unmarshal([]byte(tt.jsonStr), &user)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				if tt.checkResult != nil {
					tt.checkResult(t, user)
				}
			}
		})
	}
}

func TestUser_JSONFieldMapping(t *testing.T) {
	// Test that JSON field tags are working correctly
	userID := uuid.New()
	user := User{
		ID:       userID,
		Username: "fieldtest",
	}

	jsonData, err := json.Marshal(user)
	require.NoError(t, err)

	// Parse as generic map to check field names
	var fields map[string]interface{}
	err = json.Unmarshal(jsonData, &fields)
	require.NoError(t, err)

	// Verify JSON field names match struct tags
	expectedFields := []string{"id", "username"}
	for _, field := range expectedFields {
		assert.Contains(t, fields, field, "JSON should contain field: %s", field)
	}

	// Verify Go field names are NOT in JSON
	unexpectedFields := []string{"ID", "Username"}
	for _, field := range unexpectedFields {
		assert.NotContains(t, fields, field, "JSON should not contain Go field name: %s", field)
	}
}

func TestUser_EdgeCases(t *testing.T) {
	t.Run("zero UUID", func(t *testing.T) {
		user := User{
			ID:       uuid.Nil,
			Username: "zerouser",
		}

		jsonData, err := json.Marshal(user)
		require.NoError(t, err)

		var parsed User
		err = json.Unmarshal(jsonData, &parsed)
		require.NoError(t, err)

		assert.Equal(t, uuid.Nil, parsed.ID)
		assert.Equal(t, "zerouser", parsed.Username)
	})

	t.Run("very long username", func(t *testing.T) {
		longUsername := string(make([]byte, 1000))
		for i := range longUsername {
			longUsername = longUsername[:i] + "a" + longUsername[i+1:]
		}

		user := User{
			ID:       uuid.New(),
			Username: longUsername,
		}

		jsonData, err := json.Marshal(user)
		require.NoError(t, err)

		var parsed User
		err = json.Unmarshal(jsonData, &parsed)
		require.NoError(t, err)

		assert.Equal(t, longUsername, parsed.Username)
	})

	t.Run("special characters in username", func(t *testing.T) {
		user := User{
			ID:       uuid.New(),
			Username: "user@domain.com",
		}

		jsonData, err := json.Marshal(user)
		require.NoError(t, err)

		var parsed User
		err = json.Unmarshal(jsonData, &parsed)
		require.NoError(t, err)

		assert.Equal(t, "user@domain.com", parsed.Username)
	})

	t.Run("whitespace in username", func(t *testing.T) {
		user := User{
			ID:       uuid.New(),
			Username: "  user with spaces  ",
		}

		jsonData, err := json.Marshal(user)
		require.NoError(t, err)

		var parsed User
		err = json.Unmarshal(jsonData, &parsed)
		require.NoError(t, err)

		assert.Equal(t, "  user with spaces  ", parsed.Username)
	})
}