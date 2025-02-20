package db

import (
	"context"
	"tofoss/org-go/pkg/models"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func Insert(pool *pgxpool.Pool, ctx context.Context, username, password string) error {
	query := "INSERT INTO users (username, password) VALUES ($1, $2)"
	_, err := pool.Exec(ctx, query, username, password)

	return err
}

func CheckUserExists(pool *pgxpool.Pool, ctx context.Context, username string) (bool, error) {
	var res int
	query := "SELECT 1 FROM users WHERE username = $1 LIMIT 1"
	err := pool.QueryRow(ctx, query, username).Scan(&res)

	if err != nil {
		if err == pgx.ErrNoRows {
			return false, nil
		}
		return false, err
	}

	return true, nil
}

func FetchHashedPassword(pool *pgxpool.Pool, ctx context.Context, username string) (string, error) {
	var res string

	query := "SELECT password FROM users WHERE username = $1 LIMIT 1"

	err := pool.QueryRow(ctx, query, username).Scan(&res)

	if err != nil {
		return "", err
	}

	return res, nil
}

func FetchUser(pool *pgxpool.Pool, ctx context.Context, username string) (*models.User, error) {
	query := "SELECT id, username FROM users WHERE username = $1"

	rows, err := pool.Query(ctx, query, username)

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
