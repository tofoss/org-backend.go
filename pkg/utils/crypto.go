package utils

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

func GenerateHS512Key() (string, error) {
	secret := make([]byte, 64)
	_, err := rand.Read(secret)

	if err != nil {
		return "", fmt.Errorf("failed to generate secret key: %w", err)
	}

	return base64.StdEncoding.EncodeToString(secret), nil
}

// GenerateRefreshToken generates a cryptographically secure random token
// Returns a 32-byte (256-bit) token encoded as base64 URL-safe string
func GenerateRefreshToken() (string, error) {
	tokenBytes := make([]byte, 32)
	_, err := rand.Read(tokenBytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Use URL-safe base64 encoding (no padding) for cookie-friendly tokens
	return base64.RawURLEncoding.EncodeToString(tokenBytes), nil
}

// HashToken returns the SHA-256 hash of a token as a hex string
// This is used to store token hashes in the database instead of plaintext
func HashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}
