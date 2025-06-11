package utils

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateHS512Key(t *testing.T) {
	tests := []struct {
		name     string
		runCount int
	}{
		{
			name:     "single generation",
			runCount: 1,
		},
		{
			name:     "multiple generations",
			runCount: 10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keys := make([]string, tt.runCount)
			
			for i := 0; i < tt.runCount; i++ {
				key, err := GenerateHS512Key()
				require.NoError(t, err, "GenerateHS512Key should not return an error")
				require.NotEmpty(t, key, "Generated key should not be empty")
				
				// Verify key is valid base64
				decoded, err := base64.StdEncoding.DecodeString(key)
				require.NoError(t, err, "Key should be valid base64")
				
				// HS512 keys should be 64 bytes (512 bits) for optimal security
				assert.Equal(t, 64, len(decoded), "HS512 key should be 64 bytes")
				
				// Verify key is not all zeros
				allZeros := true
				for _, b := range decoded {
					if b != 0 {
						allZeros = false
						break
					}
				}
				assert.False(t, allZeros, "Generated key should not be all zeros")
				
				keys[i] = key
			}
			
			// For multiple generations, verify uniqueness
			if tt.runCount > 1 {
				for i := 0; i < len(keys); i++ {
					for j := i + 1; j < len(keys); j++ {
						assert.NotEqual(t, keys[i], keys[j], "Generated keys should be unique")
					}
				}
			}
		})
	}
}

func TestGenerateHS512Key_Properties(t *testing.T) {
	key, err := GenerateHS512Key()
	require.NoError(t, err)
	require.NotEmpty(t, key)

	t.Run("key format", func(t *testing.T) {
		// Check that the key is valid base64
		decoded, err := base64.StdEncoding.DecodeString(key)
		require.NoError(t, err, "Key should be valid base64")
		assert.Equal(t, 64, len(decoded), "Key should decode to 64 bytes")
	})

	t.Run("key entropy", func(t *testing.T) {
		decoded, err := base64.StdEncoding.DecodeString(key)
		require.NoError(t, err)
		
		// Basic entropy check - count unique bytes
		uniqueBytes := make(map[byte]bool)
		for _, b := range decoded {
			uniqueBytes[b] = true
		}
		
		// Should have reasonable diversity (at least 25% unique bytes)
		minUniqueBytes := len(decoded) / 4
		assert.GreaterOrEqual(t, len(uniqueBytes), minUniqueBytes, 
			"Key should have sufficient entropy (unique bytes)")
	})

	t.Run("key usability", func(t *testing.T) {
		// Test that the generated key can be used for JWT signing
		// We need to decode it first since our JWT functions expect []byte
		keyBytes, err := base64.StdEncoding.DecodeString(key)
		require.NoError(t, err)
		
		testClaims := map[string]interface{}{
			"sub": "test-user",
			"exp": 1234567890,
		}
		
		// This should not panic or return an error if key is valid
		token, err := SignJWT(keyBytes, testClaims)
		require.NoError(t, err, "Generated key should be usable for JWT signing")
		assert.NotEmpty(t, token, "Should generate a valid JWT token")
		
		// And should be parseable back
		parsedClaims, err := ParseJWT(keyBytes, token)
		require.NoError(t, err, "Should be able to parse JWT with generated key")
		assert.Equal(t, testClaims["sub"], parsedClaims["sub"])
	})
}

func TestGenerateHS512Key_Consistency(t *testing.T) {
	// Generate multiple keys and verify they're all different
	const numKeys = 100
	keys := make([]string, numKeys)
	
	for i := 0; i < numKeys; i++ {
		key, err := GenerateHS512Key()
		require.NoError(t, err)
		keys[i] = key
	}
	
	// Check that all keys are unique
	keySet := make(map[string]bool)
	for _, key := range keys {
		assert.False(t, keySet[key], "All generated keys should be unique")
		keySet[key] = true
	}
	
	assert.Equal(t, numKeys, len(keySet), "Should have generated exactly %d unique keys", numKeys)
}

// Benchmark the key generation performance
func BenchmarkGenerateHS512Key(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := GenerateHS512Key()
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Test that demonstrates thread safety by generating keys concurrently
func TestGenerateHS512Key_Concurrent(t *testing.T) {
	const numGoroutines = 10
	const keysPerGoroutine = 10
	
	keysChan := make(chan string, numGoroutines*keysPerGoroutine)
	
	// Start multiple goroutines generating keys
	for i := 0; i < numGoroutines; i++ {
		go func() {
			for j := 0; j < keysPerGoroutine; j++ {
				key, err := GenerateHS512Key()
				if err != nil {
					t.Errorf("Error generating key: %v", err)
					return
				}
				keysChan <- key
			}
		}()
	}
	
	// Collect all keys
	keys := make([]string, 0, numGoroutines*keysPerGoroutine)
	for i := 0; i < numGoroutines*keysPerGoroutine; i++ {
		key := <-keysChan
		keys = append(keys, key)
	}
	
	// Verify all keys are unique
	keySet := make(map[string]bool)
	for _, key := range keys {
		assert.False(t, keySet[key], "All concurrently generated keys should be unique")
		keySet[key] = true
	}
	
	expectedTotal := numGoroutines * keysPerGoroutine
	assert.Equal(t, expectedTotal, len(keySet), "Should have generated %d unique keys", expectedTotal)
}

func TestGenerateHS512Key_Base64Encoding(t *testing.T) {
	key, err := GenerateHS512Key()
	require.NoError(t, err)

	t.Run("valid base64", func(t *testing.T) {
		_, err := base64.StdEncoding.DecodeString(key)
		assert.NoError(t, err, "Key should be valid base64")
	})

	t.Run("no padding issues", func(t *testing.T) {
		// Base64 should be properly padded
		decoded, err := base64.StdEncoding.DecodeString(key)
		require.NoError(t, err)
		
		// Re-encode and verify it matches
		reencoded := base64.StdEncoding.EncodeToString(decoded)
		assert.Equal(t, key, reencoded, "Key should survive encode/decode cycle")
	})

	t.Run("url safe compatibility", func(t *testing.T) {
		// Standard encoding should be compatible with URL-safe base64
		decoded, err := base64.StdEncoding.DecodeString(key)
		require.NoError(t, err)
		
		urlSafeKey := base64.URLEncoding.EncodeToString(decoded)
		urlDecoded, err := base64.URLEncoding.DecodeString(urlSafeKey)
		require.NoError(t, err)
		
		assert.Equal(t, decoded, urlDecoded, "Should be compatible with URL-safe encoding")
	})
}