package repositories

import (
	"context"
	"time"
	"tofoss/org-go/pkg/models"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type InviteCodeRepository struct {
	pool *pgxpool.Pool
}

func NewInviteCodeRepository(pool *pgxpool.Pool) *InviteCodeRepository {
	return &InviteCodeRepository{pool: pool}
}

// GetByCode fetches an invite code by its code value
func (r *InviteCodeRepository) GetByCode(ctx context.Context, code uuid.UUID) (*models.InviteCode, error) {
	query := `SELECT code, user_id, note, created_at, expires_at
			  FROM invite_codes WHERE code = $1`

	rows, err := r.pool.Query(ctx, query, code)
	if err != nil {
		return nil, err
	}

	inviteCode, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[models.InviteCode])
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return &inviteCode, nil
}

// IsValid checks if an invite code is valid (exists, not used, not expired)
func (r *InviteCodeRepository) IsValid(ctx context.Context, code uuid.UUID) (bool, error) {
	inviteCode, err := r.GetByCode(ctx, code)
	if err != nil {
		return false, err
	}

	if inviteCode == nil {
		return false, nil
	}

	// Check if already used
	if inviteCode.UserID != nil {
		return false, nil
	}

	// Check if expired
	if time.Now().After(inviteCode.ExpiresAt) {
		return false, nil
	}

	return true, nil
}

// MarkUsed marks an invite code as used by a user
func (r *InviteCodeRepository) MarkUsed(ctx context.Context, code uuid.UUID, userID uuid.UUID) error {
	query := `UPDATE invite_codes SET user_id = $1 WHERE code = $2`
	_, err := r.pool.Exec(ctx, query, userID, code)
	return err
}
