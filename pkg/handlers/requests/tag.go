package requests

import "github.com/google/uuid"

type Tag struct {
	Name string `json:"name"`
}

type AssignTags struct {
	TagIDs []uuid.UUID `json:"tagIds"`
}
