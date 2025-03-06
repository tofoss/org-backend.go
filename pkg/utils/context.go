package utils

import (
	"fmt"
	"net/http"

	"github.com/google/uuid"
)

type ContextKey string

const (
	UserIDKey   ContextKey = "UserID"
	UsernameKey ContextKey = "Username"
)

func UserContext(r *http.Request) (uuid.UUID, string, error) {
	ctx := r.Context()

	invalidContextError := func() (uuid.UUID, string, error) {
		return uuid.Nil, "", fmt.Errorf("user information is missing from context")
	}

	userID, ok := ctx.Value(UserIDKey).(uuid.UUID)

	if !ok {
		return invalidContextError()
	}

	username, ok := ctx.Value(UsernameKey).(string)
	if !ok {
		return invalidContextError()
	}

	return userID, username, nil
}
