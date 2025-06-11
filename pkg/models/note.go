package models

import (
	"time"

	"github.com/google/uuid"
)

type Note struct {
	ID          uuid.UUID  `json:"id"          db:"id"`
	UserID      uuid.UUID  `json:"userId"      db:"user_id"`
	Title       string     `json:"title"       db:"title"`
	Content     string     `json:"content"     db:"content"`
	CreatedAt   time.Time  `json:"createdAt"   db:"created_at"`
	UpdatedAt   time.Time  `json:"updatedAt"   db:"updated_at"`
	PublishedAt *time.Time `json:"publishedAt" db:"published_at"`
	Published   bool       `json:"published"   db:"published"`
	Tags        []Tag      `json:"tags" db:"-"`
}
