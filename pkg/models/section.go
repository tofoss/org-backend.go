package models

import (
	"time"

	"github.com/google/uuid"
)

type Section struct {
	ID         uuid.UUID `json:"id"                 db:"id"`
	NotebookID uuid.UUID `json:"notebook_id"        db:"notebook_id"`
	Name       string    `json:"name"               db:"name"`
	Position   int       `json:"position,omitempty" db:"position"`
	CreatedAt  time.Time `json:"created_at"         db:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"         db:"updated_at"`
}
