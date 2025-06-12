package requests

import "github.com/google/uuid"

type Note struct {
	ID        uuid.UUID `json:"id"`
	Title     string    `json:"title,omitempty"`
	Content   string    `json:"content"`
	Published bool      `json:"published"`
}
