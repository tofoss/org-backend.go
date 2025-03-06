package models

import (
	"time"

	"github.com/google/uuid"
)

type Article struct {
	ID          uuid.UUID  `db:"id"`
	UserID      uuid.UUID  `db:"user_id"`
	Title       string     `db:"title"`
	Content     string     `db:"content"`
	CreatedAt   time.Time  `db:"created_at"`
	UpdatedAt   time.Time  `db:"updated_at"`
	PublishedAt *time.Time `db:"published_at"`
	Published   bool       `db:"published"`
}
