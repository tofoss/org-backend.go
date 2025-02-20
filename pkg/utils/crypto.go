package utils

import (
	"crypto/rand"
	"encoding/base64"
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
