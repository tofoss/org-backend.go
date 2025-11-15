package repositories

import (
	"context"
	"time"
	"tofoss/org-go/pkg/models"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type RefreshTokenRepository struct {
	pool *pgxpool.Pool
}

func NewRefreshTokenRepository(pool *pgxpool.Pool) *RefreshTokenRepository {
	return &RefreshTokenRepository{pool: pool}
}

// Insert creates a new refresh token
func (r *RefreshTokenRepository) Insert(ctx context.Context, userID uuid.UUID, tokenHash string, expiresAt time.Time) error {
	query := `
		INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
		VALUES ($1, $2, $3)
	`
	_, err := r.pool.Exec(ctx, query, userID, tokenHash, expiresAt)
	return err
}

// GetByTokenHash retrieves a refresh token by its hash
func (r *RefreshTokenRepository) GetByTokenHash(ctx context.Context, tokenHash string) (*models.RefreshToken, error) {
	query := `
		SELECT id, user_id, token_hash, expires_at, created_at, revoked_at
		FROM refresh_tokens
		WHERE token_hash = $1
	`

	rows, err := r.pool.Query(ctx, query, tokenHash)
	if err != nil {
		return nil, err
	}

	token, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[models.RefreshToken])
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return &token, nil
}

// Revoke soft-deletes a refresh token by setting revoked_at
func (r *RefreshTokenRepository) Revoke(ctx context.Context, tokenHash string) error {
	query := `
		UPDATE refresh_tokens
		SET revoked_at = current_timestamp
		WHERE token_hash = $1 AND revoked_at IS NULL
	`
	_, err := r.pool.Exec(ctx, query, tokenHash)
	return err
}

// RevokeAllForUser revokes all active refresh tokens for a user (useful for "logout all devices")
func (r *RefreshTokenRepository) RevokeAllForUser(ctx context.Context, userID uuid.UUID) error {
	query := `
		UPDATE refresh_tokens
		SET revoked_at = current_timestamp
		WHERE user_id = $1 AND revoked_at IS NULL
	`
	_, err := r.pool.Exec(ctx, query, userID)
	return err
}

// DeleteExpired removes expired tokens from the database (cleanup)
func (r *RefreshTokenRepository) DeleteExpired(ctx context.Context) (int64, error) {
	query := `
		DELETE FROM refresh_tokens
		WHERE expires_at < current_timestamp
	`
	result, err := r.pool.Exec(ctx, query)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected(), nil
}

// IsValid checks if a token is valid (not revoked, not expired)
func (r *RefreshTokenRepository) IsValid(ctx context.Context, tokenHash string) (bool, uuid.UUID, error) {
	var userID uuid.UUID
	query := `
		SELECT user_id
		FROM refresh_tokens
		WHERE token_hash = $1
		  AND revoked_at IS NULL
		  AND expires_at > current_timestamp
	`

	err := r.pool.QueryRow(ctx, query, tokenHash).Scan(&userID)
	if err != nil {
		if err == pgx.ErrNoRows {
			return false, uuid.Nil, nil
		}
		return false, uuid.Nil, err
	}

	return true, userID, nil
}
