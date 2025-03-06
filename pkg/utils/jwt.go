package utils

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
)

func SignJWT(key []byte, claims jwt.MapClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)

	return token.SignedString(key)
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
