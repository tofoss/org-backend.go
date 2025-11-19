package models

import "github.com/google/uuid"

// TreeNote represents a minimal note for the tree view
type TreeNote struct {
	ID    uuid.UUID `json:"id"`
	Title string    `json:"title"`
}

// TreeSection represents a section with its notes for the tree view
type TreeSection struct {
	ID    uuid.UUID  `json:"id"`
	Title string     `json:"title"`
	Notes []TreeNote `json:"notes"`
}

// TreeNotebook represents a notebook with sections and unsectioned notes for the tree view
type TreeNotebook struct {
	ID          uuid.UUID     `json:"id"`
	Title       string        `json:"title"`
	Sections    []TreeSection `json:"sections"`
	Unsectioned []TreeNote    `json:"unsectioned"`
}

// TreeData represents the complete tree structure
type TreeData struct {
	Notebooks  []TreeNotebook `json:"notebooks"`
	Unassigned []TreeNote     `json:"unassigned"`
}
