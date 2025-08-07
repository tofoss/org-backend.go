package repositories

import (
	"context"
	"tofoss/org-go/pkg/models"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type RecipeJobRepository struct {
	pool *pgxpool.Pool
}

func NewRecipeJobRepository(pool *pgxpool.Pool) *RecipeJobRepository {
	return &RecipeJobRepository{pool: pool}
}

func (r *RecipeJobRepository) Create(
	ctx context.Context,
	job models.RecipeJob,
) (models.RecipeJob, error) {
	query := `
		INSERT INTO recipe_jobs (id, user_id, url, status, created_at) 
		VALUES ($1, $2, $3, $4, $5) 
		RETURNING id, user_id, url, status, error_message, recipe_id, note_id, created_at, completed_at`

	rows, err := r.pool.Query(ctx, query,
		job.ID,
		job.UserID,
		job.URL,
		job.Status,
		job.CreatedAt,
	)

	if err != nil {
		return models.RecipeJob{}, err
	}
	defer rows.Close()

	return r.scanJob(rows)
}

func (r *RecipeJobRepository) UpdateStatus(
	ctx context.Context,
	jobID uuid.UUID,
	status string,
	errorMessage *string,
) error {
	now := time.Now()
	
	query := `
		UPDATE recipe_jobs 
		SET status = $2, error_message = $3, completed_at = $4
		WHERE id = $1`

	_, err := r.pool.Exec(ctx, query, jobID, status, errorMessage, now)
	return err
}

func (r *RecipeJobRepository) Complete(
	ctx context.Context,
	jobID uuid.UUID,
	recipeID uuid.UUID,
	noteID uuid.UUID,
) error {
	now := time.Now()
	
	query := `
		UPDATE recipe_jobs 
		SET status = 'completed', recipe_id = $2, note_id = $3, completed_at = $4
		WHERE id = $1`

	_, err := r.pool.Exec(ctx, query, jobID, recipeID, noteID, now)
	return err
}

func (r *RecipeJobRepository) FetchByID(
	ctx context.Context,
	jobID uuid.UUID,
) (models.RecipeJob, error) {
	query := `
		SELECT id, user_id, url, status, error_message, recipe_id, note_id, created_at, completed_at 
		FROM recipe_jobs 
		WHERE id = $1`

	rows, err := r.pool.Query(ctx, query, jobID)
	if err != nil {
		return models.RecipeJob{}, err
	}
	defer rows.Close()

	return r.scanJob(rows)
}

func (r *RecipeJobRepository) FetchPendingJobs(
	ctx context.Context,
	limit int,
) ([]models.RecipeJob, error) {
	query := `
		SELECT id, user_id, url, status, error_message, recipe_id, note_id, created_at, completed_at 
		FROM recipe_jobs 
		WHERE status = 'pending' 
		ORDER BY created_at ASC 
		LIMIT $1`

	rows, err := r.pool.Query(ctx, query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return r.scanJobs(rows)
}

func (r *RecipeJobRepository) scanJob(rows pgx.Rows) (models.RecipeJob, error) {
	if !rows.Next() {
		return models.RecipeJob{}, pgx.ErrNoRows
	}

	var job models.RecipeJob
	err := rows.Scan(
		&job.ID,
		&job.UserID,
		&job.URL,
		&job.Status,
		&job.ErrorMessage,
		&job.RecipeID,
		&job.NoteID,
		&job.CreatedAt,
		&job.CompletedAt,
	)
	return job, err
}

func (r *RecipeJobRepository) scanJobs(rows pgx.Rows) ([]models.RecipeJob, error) {
	var jobs []models.RecipeJob

	for rows.Next() {
		var job models.RecipeJob
		err := rows.Scan(
			&job.ID,
			&job.UserID,
			&job.URL,
			&job.Status,
			&job.ErrorMessage,
			&job.RecipeID,
			&job.NoteID,
			&job.CreatedAt,
			&job.CompletedAt,
		)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, job)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return jobs, nil
}