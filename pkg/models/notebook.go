package models

import (
	"time"

	"github.com/google/uuid"
)

type Notebook struct {
	ID          uuid.UUID  `json:"id"                    db:"id"`
	UserID      uuid.UUID  `json:"user_id"               db:"user_id"`
	Name        string     `json:"name"                  db:"name"`
	Description string     `json:"description,omitempty" db:"description"`
	CreatedAt   time.Time  `json:"created_at"            db:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"            db:"updated_at"`
	SectionID   *uuid.UUID `json:"section_id,omitempty"  db:"section_id"` // Section assignment when note is in notebook
}
