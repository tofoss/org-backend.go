package requests

import "github.com/google/uuid"

type AssignToSection struct {
	SectionID *uuid.UUID `json:"section_id"` // Can be null to unsection the note
}
