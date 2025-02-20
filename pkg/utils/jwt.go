package utils

import (
	"encoding/base64"
	"errors"

	"github.com/golang-jwt/jwt"
)

func SignJWT(secret string, claims jwt.MapClaims) (string, error) {
	secretBytes, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		return "", errors.New("invalid secret key")
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)

	return token.SignedString(secretBytes)
}

func ParseJWT(secret, jwtString string) (map[string]interface{}, error) {
	token, err := jwt.Parse(jwtString, func(t *jwt.Token) (interface{}, error) {
		return secret, nil
	})

	if err != nil || !token.Valid {
		return nil, errors.New("invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("failed to parse claims")
	}

	return claims, nil
}
