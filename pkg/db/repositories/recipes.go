package repositories

import (
	"context"
	"encoding/json"
	"tofoss/org-go/pkg/models"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type RecipeRepository struct {
	pool *pgxpool.Pool
}

func NewRecipeRepository(pool *pgxpool.Pool) *RecipeRepository {
	return &RecipeRepository{pool: pool}
}

func (r *RecipeRepository) Create(
	ctx context.Context,
	recipe models.Recipe,
) (models.Recipe, error) {
	ingredientsJSON, err := json.Marshal(recipe.Ingredients)
	if err != nil {
		return models.Recipe{}, err
	}

	stepsJSON, err := json.Marshal(recipe.Steps)
	if err != nil {
		return models.Recipe{}, err
	}

	query := `
		INSERT INTO recipes (id, name, summary, servings, prep_time, source_url, ingredients, steps, created_at, updated_at) 
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) 
		RETURNING id, name, summary, servings, prep_time, source_url, ingredients, steps, created_at, updated_at`

	rows, err := r.pool.Query(ctx, query,
		recipe.ID,
		recipe.Name,
		recipe.Summary,
		recipe.Servings,
		recipe.PrepTime,
		recipe.SourceURL,
		ingredientsJSON,
		stepsJSON,
		recipe.CreatedAt,
		recipe.UpdatedAt,
	)

	if err != nil {
		return models.Recipe{}, err
	}
	defer rows.Close()

	return r.scanRecipe(rows)
}

func (r *RecipeRepository) Update(
	ctx context.Context,
	recipe models.Recipe,
) (models.Recipe, error) {
	ingredientsJSON, err := json.Marshal(recipe.Ingredients)
	if err != nil {
		return models.Recipe{}, err
	}

	stepsJSON, err := json.Marshal(recipe.Steps)
	if err != nil {
		return models.Recipe{}, err
	}

	query := `
		UPDATE recipes 
		SET name = $2, summary = $3, servings = $4, prep_time = $5, source_url = $6, ingredients = $7, steps = $8, updated_at = $9
		WHERE id = $1 
		RETURNING id, name, summary, servings, prep_time, source_url, ingredients, steps, created_at, updated_at`

	rows, err := r.pool.Query(ctx, query,
		recipe.ID,
		recipe.Name,
		recipe.Summary,
		recipe.Servings,
		recipe.PrepTime,
		recipe.SourceURL,
		ingredientsJSON,
		stepsJSON,
		recipe.UpdatedAt,
	)

	if err != nil {
		return models.Recipe{}, err
	}
	defer rows.Close()

	return r.scanRecipe(rows)
}

func (r *RecipeRepository) FetchByID(
	ctx context.Context,
	recipeID uuid.UUID,
) (models.Recipe, error) {
	query := "SELECT id, name, summary, servings, prep_time, source_url, ingredients, steps, created_at, updated_at FROM recipes WHERE id = $1"

	rows, err := r.pool.Query(ctx, query, recipeID)
	if err != nil {
		return models.Recipe{}, err
	}
	defer rows.Close()

	return r.scanRecipe(rows)
}

func (r *RecipeRepository) FetchByNoteID(
	ctx context.Context,
	noteID uuid.UUID,
) ([]models.Recipe, error) {
	query := `
		SELECT r.id, r.name, r.summary, r.servings, r.prep_time, r.source_url, r.ingredients, r.steps, r.created_at, r.updated_at 
		FROM recipes r 
		JOIN note_recipes nr ON r.id = nr.recipe_id 
		WHERE nr.note_id = $1`

	rows, err := r.pool.Query(ctx, query, noteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return r.scanRecipes(rows)
}

func (r *RecipeRepository) FetchByUserID(
	ctx context.Context,
	userID uuid.UUID,
) ([]models.Recipe, error) {
	query := `
		SELECT DISTINCT r.id, r.name, r.summary, r.servings, r.prep_time, r.source_url, r.ingredients, r.steps, r.created_at, r.updated_at 
		FROM recipes r 
		JOIN note_recipes nr ON r.id = nr.recipe_id
		JOIN notes n ON nr.note_id = n.id 
		WHERE n.user_id = $1 
		ORDER BY r.created_at DESC`

	rows, err := r.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return r.scanRecipes(rows)
}

func (r *RecipeRepository) Delete(
	ctx context.Context,
	recipeID uuid.UUID,
) error {
	_, err := r.pool.Exec(ctx, "DELETE FROM recipes WHERE id = $1", recipeID)
	return err
}

// LinkRecipeToNote creates a relationship between a recipe and note
func (r *RecipeRepository) LinkRecipeToNote(
	ctx context.Context,
	recipeID uuid.UUID,
	noteID uuid.UUID,
) error {
	_, err := r.pool.Exec(ctx, "INSERT INTO note_recipes (recipe_id, note_id) VALUES ($1, $2) ON CONFLICT DO NOTHING", recipeID, noteID)
	return err
}

// UnlinkRecipeFromNote removes the relationship between a recipe and note
func (r *RecipeRepository) UnlinkRecipeFromNote(
	ctx context.Context,
	recipeID uuid.UUID,
	noteID uuid.UUID,
) error {
	_, err := r.pool.Exec(ctx, "DELETE FROM note_recipes WHERE recipe_id = $1 AND note_id = $2", recipeID, noteID)
	return err
}

// scanRecipe scans a single recipe row with JSON unmarshaling
func (r *RecipeRepository) scanRecipe(rows pgx.Rows) (models.Recipe, error) {
	recipe := models.Recipe{}
	var ingredientsJSON []byte
	var stepsJSON []byte

	if !rows.Next() {
		return models.Recipe{}, pgx.ErrNoRows
	}

	err := rows.Scan(
		&recipe.ID,
		&recipe.Name,
		&recipe.Summary,
		&recipe.Servings,
		&recipe.PrepTime,
		&recipe.SourceURL,
		&ingredientsJSON,
		&stepsJSON,
		&recipe.CreatedAt,
		&recipe.UpdatedAt,
	)
	if err != nil {
		return models.Recipe{}, err
	}

	// Unmarshal JSON fields
	if err := json.Unmarshal(ingredientsJSON, &recipe.Ingredients); err != nil {
		return models.Recipe{}, err
	}

	if err := json.Unmarshal(stepsJSON, &recipe.Steps); err != nil {
		return models.Recipe{}, err
	}

	return recipe, nil
}

// scanRecipes scans multiple recipe rows
func (r *RecipeRepository) scanRecipes(rows pgx.Rows) ([]models.Recipe, error) {
	var recipes []models.Recipe

	for rows.Next() {
		recipe := models.Recipe{}
		var ingredientsJSON []byte
		var stepsJSON []byte

		err := rows.Scan(
			&recipe.ID,
			&recipe.Name,
			&recipe.Summary,
			&recipe.Servings,
			&recipe.PrepTime,
			&recipe.SourceURL,
			&ingredientsJSON,
			&stepsJSON,
			&recipe.CreatedAt,
			&recipe.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}

		// Unmarshal JSON fields
		if err := json.Unmarshal(ingredientsJSON, &recipe.Ingredients); err != nil {
			return nil, err
		}

		if err := json.Unmarshal(stepsJSON, &recipe.Steps); err != nil {
			return nil, err
		}

		recipes = append(recipes, recipe)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return recipes, nil
}