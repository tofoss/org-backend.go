package repositories

import (
	"context"
	"tofoss/org-go/pkg/models"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type UserRepository struct {
	pool *pgxpool.Pool
}

func NewUserRepository(pool *pgxpool.Pool) *UserRepository {
	return &UserRepository{pool: pool}
}

func (r *UserRepository) Insert(ctx context.Context, username, password string) error {
	query := "INSERT INTO users (username, password) VALUES ($1, $2)"
	_, err := r.pool.Exec(ctx, query, username, password)

	return err
}

func (r *UserRepository) CheckUserExists(ctx context.Context, username string) (bool, error) {
	var res int
	query := "SELECT 1 FROM users WHERE username = $1 LIMIT 1"
	err := r.pool.QueryRow(ctx, query, username).Scan(&res)

	if err != nil {
		if err == pgx.ErrNoRows {
			return false, nil
		}
		return false, err
	}

	return true, nil
}

func (r *UserRepository) FetchHashedPassword(ctx context.Context, username string) (string, error) {
	var res string

	query := "SELECT password FROM users WHERE username = $1 LIMIT 1"

	err := r.pool.QueryRow(ctx, query, username).Scan(&res)

	if err != nil {
		return "", err
	}

	return res, nil
}

func (r *UserRepository) FetchUser(ctx context.Context, username string) (*models.User, error) {
	query := "SELECT id, username FROM users WHERE username = $1"

	rows, err := r.pool.Query(ctx, query, username)

	if err != nil {
		return nil, err
	}

	user, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[models.User])

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return &user, nil
}

func (r *UserRepository) FetchUserByID(ctx context.Context, userID string) (*models.User, error) {
	query := "SELECT id, username FROM users WHERE id = $1"

	rows, err := r.pool.Query(ctx, query, userID)

	if err != nil {
		return nil, err
	}

	user, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[models.User])

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return &user, nil
}
