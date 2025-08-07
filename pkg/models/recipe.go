package models

import (
	"time"

	"github.com/google/uuid"
)

type Recipe struct {
	ID          uuid.UUID    `json:"id"          db:"id"`
	Name        string       `json:"name"        db:"name"`
	Summary     *string      `json:"summary"     db:"summary"`
	Servings    *int         `json:"servings"    db:"servings"`
	PrepTime    *string      `json:"prepTime"    db:"prep_time"`
	SourceURL   *string      `json:"sourceUrl"   db:"source_url"`
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

type RecipeJob struct {
	ID           uuid.UUID  `json:"id"           db:"id"`
	UserID       uuid.UUID  `json:"userId"       db:"user_id"`
	URL          string     `json:"url"          db:"url"`
	Status       string     `json:"status"       db:"status"`
	ErrorMessage *string    `json:"errorMessage" db:"error_message"`
	RecipeID     *uuid.UUID `json:"recipeId"     db:"recipe_id"`
	NoteID       *uuid.UUID `json:"noteId"       db:"note_id"`
	CreatedAt    time.Time  `json:"createdAt"    db:"created_at"`
	CompletedAt  *time.Time `json:"completedAt"  db:"completed_at"`
}

type RecipeURLCache struct {
	URLHash      string    `json:"urlHash"     db:"url_hash"`
	OriginalURL  string    `json:"originalUrl" db:"original_url"`
	RecipeID     uuid.UUID `json:"recipeId"    db:"recipe_id"`
	CreatedAt    time.Time `json:"createdAt"   db:"created_at"`
	LastAccessed time.Time `json:"lastAccessed" db:"last_accessed"`
}

