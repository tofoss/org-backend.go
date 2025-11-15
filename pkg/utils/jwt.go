package utils

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
)

func SignJWT(key []byte, claims jwt.MapClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)

	return token.SignedString(key)
}

// SignAccessToken creates a JWT access token with a 15-minute expiration
// userID: The user's UUID
// username: The user's username
func SignAccessToken(key []byte, userID uuid.UUID, username string) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub":      userID.String(),
		"username": username,
		"type":     "access", // Token type for additional validation
		"iat":      now.Unix(),
		"exp":      now.Add(15 * time.Minute).Unix(), // 15 minute expiration
	}

	return SignJWT(key, claims)
}

func ParseJWT(key []byte, jwtString string) (map[string]interface{}, error) {
	token, err := jwt.Parse(jwtString, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}

		return key, nil
	})

	if err != nil || !token.Valid {
		log.Printf("invalid token: %v", err)
		return nil, errors.New("invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("failed to parse claims")
	}

	return claims, nil
}

func ExtractUserInfo(claims map[string]interface{}) (uuid.UUID, string, error) {
	sub, ok := claims["sub"].(string)

	invalidClaimsError := func(msg string) (uuid.UUID, string, error) {
		return uuid.Nil, "", fmt.Errorf("invalid claims, %s", msg)
	}

	if !ok {
		return invalidClaimsError("sub is missing")
	}

	userID, err := uuid.Parse(sub)
	if err != nil {
		return invalidClaimsError("sub is invalid uuid")
	}

	username, ok := claims["username"].(string)

	if !ok {
		return invalidClaimsError("username claim is invalid")
	}

	return userID, username, nil
}

// ValidateTokenType checks if the token has the expected type claim
func ValidateTokenType(claims map[string]interface{}, expectedType string) error {
	tokenType, ok := claims["type"].(string)
	if !ok {
		// For backward compatibility, allow tokens without type claim
		// This can be removed once all old tokens have expired
		return nil
	}

	if tokenType != expectedType {
		return fmt.Errorf("invalid token type: expected %s, got %s", expectedType, tokenType)
	}

	return nil
}

func ParseHeaderJWTClaims(r *http.Request, jwtKey []byte) (map[string]interface{}, error) {
	token := extractBearerToken(r.Header.Get("Authorization"))

	if token == "" {
		jwtCookie, err := r.Cookie("JWT-Cookie")
		if err != nil {
			return nil, fmt.Errorf("JWT not found in header or cookie: %w", err)
		}
		token = jwtCookie.Value
	}

	claims, err := ParseJWT(jwtKey, strings.TrimSpace(token))
	if err != nil {
		return nil, fmt.Errorf("unable to parse JWT: %w", err)
	}

	return claims, nil
}

func extractBearerToken(authHeader string) string {
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer ")
	}
	return ""
}
