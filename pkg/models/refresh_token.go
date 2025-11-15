package models

import (
	"time"

	"github.com/google/uuid"
)

type RefreshToken struct {
	ID        uuid.UUID  `json:"id" db:"id"`
	UserID    uuid.UUID  `json:"user_id" db:"user_id"`
	TokenHash string     `json:"-" db:"token_hash"` // Never expose in JSON
	ExpiresAt time.Time  `json:"expires_at" db:"expires_at"`
	CreatedAt time.Time  `json:"created_at" db:"created_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty" db:"revoked_at"` // NULL means active
}
