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

	invalidTokenError := func() (uuid.UUID, string, error) {
		return uuid.Nil, "", fmt.Errorf("invalid token")
	}

	if !ok {
		return invalidTokenError()
	}

	userID, err := uuid.Parse(sub)
	if err != nil {
		return invalidTokenError()
	}

	username, ok := claims["username"].(string)

	if !ok {
		return invalidTokenError()
	}

	return userID, username, nil
}

func ParseHeaderJWTClaims(r *http.Request, jwtKey []byte) (map[string]interface{}, error) {
	var token string
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		token = strings.TrimPrefix(authHeader, "Bearer ")
	}

	claims, err := ParseJWT(jwtKey, strings.Trim(token, " "))
	if err != nil {
		log.Printf("unable to parse JWT %v", err)
		return nil, err
	}

	return claims, nil
}
