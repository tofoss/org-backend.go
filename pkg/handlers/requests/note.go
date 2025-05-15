package requests

import "github.com/google/uuid"

type Note struct {
	ID        uuid.UUID `json:"id"`
	Content   string    `json:"content"`
	Published bool      `json:"published"`
}
