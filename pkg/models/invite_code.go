package models

import (
	"time"

	"github.com/google/uuid"
)

type InviteCode struct {
	Code      uuid.UUID  `json:"code" db:"code"`
	UserID    *uuid.UUID `json:"user_id" db:"user_id"`
	Note      *string    `json:"note" db:"note"`
	CreatedAt time.Time  `json:"created_at" db:"created_at"`
	ExpiresAt time.Time  `json:"expires_at" db:"expires_at"`
}
