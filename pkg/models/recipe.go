package models

import (
	"time"

	"github.com/google/uuid"
)

type Recipe struct {
	ID          uuid.UUID    `json:"id"          db:"id"`
	NoteID      uuid.UUID    `json:"noteId"      db:"note_id"`
	Name        string       `json:"name"        db:"name"`
	Summary     *string      `json:"summary"     db:"summary"`
	Servings    *int         `json:"servings"    db:"servings"`
	PrepTime    *string      `json:"prepTime"    db:"prep_time"`
	Ingredients []Ingredient `json:"ingredients" db:"ingredients"`
	Steps       []string     `json:"steps"       db:"steps"`
	CreatedAt   time.Time    `json:"createdAt"   db:"created_at"`
	UpdatedAt   time.Time    `json:"updatedAt"   db:"updated_at"`
}

type Ingredient struct {
	Name       string    `json:"name"`
	Quantity   *Quantity `json:"quantity"` // null for "to taste" ingredients
	IsOptional bool      `json:"isOptional"`
	Notes      string    `json:"notes"`
}

type Quantity struct {
	Min  *float64 `json:"min"`  // nullable for cases like "1 cup" (only max specified)
	Max  *float64 `json:"max"`  // nullable for cases like "at least 2 tbsp" (only min specified)
	Unit string   `json:"unit"` // required - tablespoons, grams, cups, cloves, etc.
}

