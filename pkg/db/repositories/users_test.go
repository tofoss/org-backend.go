package repositories

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUserRepository_Insert(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	repo := NewUserRepository(mock)
	ctx := context.Background()

	username := "testuser"
	password := "hashed_password"

	t.Run("successful insert", func(t *testing.T) {
		expectedQuery := `INSERT INTO users \(username, password\) VALUES \(\$1, \$2\)`

		mock.ExpectExec(expectedQuery).
			WithArgs(username, password).
			WillReturnResult(pgxmock.NewResult("INSERT", 1))

		err := repo.Insert(ctx, username, password)

		require.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("duplicate username error", func(t *testing.T) {
		duplicateErr := &pgconn.PgError{
			Code:       "23505", // unique_violation
			ColumnName: "username",
		}

		mock.ExpectExec(`INSERT INTO users`).
			WithArgs(username, password).
			WillReturnError(duplicateErr)

		err := repo.Insert(ctx, username, password)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "23505")
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("database connection error", func(t *testing.T) {
		mock.ExpectExec(`INSERT INTO users`).
			WithArgs(username, password).
			WillReturnError(fmt.Errorf("connection refused"))

		err := repo.Insert(ctx, username, password)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "connection refused")
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestUserRepository_CheckUserExists(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	repo := NewUserRepository(mock)
	ctx := context.Background()

	username := "testuser"

	t.Run("user exists", func(t *testing.T) {
		expectedQuery := `SELECT 1 FROM users WHERE username = \$1 LIMIT 1`

		rows := pgxmock.NewRows([]string{"exists"}).AddRow(1)

		mock.ExpectQuery(expectedQuery).
			WithArgs(username).
			WillReturnRows(rows)

		exists, err := repo.CheckUserExists(ctx, username)

		require.NoError(t, err)
		assert.True(t, exists)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("user does not exist", func(t *testing.T) {
		expectedQuery := `SELECT 1 FROM users WHERE username = \$1 LIMIT 1`

		mock.ExpectQuery(expectedQuery).
			WithArgs(username).
			WillReturnError(pgx.ErrNoRows)

		exists, err := repo.CheckUserExists(ctx, username)

		require.NoError(t, err)
		assert.False(t, exists)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("database error", func(t *testing.T) {
		expectedQuery := `SELECT 1 FROM users WHERE username = \$1 LIMIT 1`

		mock.ExpectQuery(expectedQuery).
			WithArgs(username).
			WillReturnError(fmt.Errorf("database timeout"))

		_, err := repo.CheckUserExists(ctx, username)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "database timeout")
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("case sensitivity", func(t *testing.T) {
		// Test that usernames are case sensitive
		upperUsername := "TESTUSER"
		expectedQuery := `SELECT 1 FROM users WHERE username = \$1 LIMIT 1`

		mock.ExpectQuery(expectedQuery).
			WithArgs(upperUsername).
			WillReturnError(pgx.ErrNoRows)

		exists, err := repo.CheckUserExists(ctx, upperUsername)

		require.NoError(t, err)
		assert.False(t, exists)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestUserRepository_FetchHashedPassword(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	repo := NewUserRepository(mock)
	ctx := context.Background()

	username := "testuser"
	hashedPassword := "$2a$10$abcdefghijklmnopqrstuvwxyz"

	t.Run("successful fetch", func(t *testing.T) {
		expectedQuery := `SELECT password FROM users WHERE username = \$1 LIMIT 1`

		rows := pgxmock.NewRows([]string{"password"}).AddRow(hashedPassword)

		mock.ExpectQuery(expectedQuery).
			WithArgs(username).
			WillReturnRows(rows)

		result, err := repo.FetchHashedPassword(ctx, username)

		require.NoError(t, err)
		assert.Equal(t, hashedPassword, result)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("user not found", func(t *testing.T) {
		expectedQuery := `SELECT password FROM users WHERE username = \$1 LIMIT 1`

		mock.ExpectQuery(expectedQuery).
			WithArgs(username).
			WillReturnError(pgx.ErrNoRows)

		_, err := repo.FetchHashedPassword(ctx, username)

		assert.Error(t, err)
		assert.Equal(t, pgx.ErrNoRows, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("database error", func(t *testing.T) {
		expectedQuery := `SELECT password FROM users WHERE username = \$1 LIMIT 1`

		mock.ExpectQuery(expectedQuery).
			WithArgs(username).
			WillReturnError(fmt.Errorf("database connection lost"))

		_, err := repo.FetchHashedPassword(ctx, username)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "database connection lost")
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("empty password hash", func(t *testing.T) {
		expectedQuery := `SELECT password FROM users WHERE username = \$1 LIMIT 1`

		rows := pgxmock.NewRows([]string{"password"}).AddRow("")

		mock.ExpectQuery(expectedQuery).
			WithArgs(username).
			WillReturnRows(rows)

		result, err := repo.FetchHashedPassword(ctx, username)

		require.NoError(t, err)
		assert.Empty(t, result)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestUserRepository_FetchUser(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	repo := NewUserRepository(mock)
	ctx := context.Background()

	userID := uuid.New()
	username := "testuser"

	t.Run("successful fetch by username", func(t *testing.T) {
		expectedQuery := `SELECT id, username FROM users WHERE username = \$1`

		rows := pgxmock.NewRows([]string{"id", "username"}).
			AddRow(userID, username)

		mock.ExpectQuery(expectedQuery).
			WithArgs(username).
			WillReturnRows(rows)

		result, err := repo.FetchUser(ctx, username)

		require.NoError(t, err)
		assert.Equal(t, userID, result.ID)
		assert.Equal(t, username, result.Username)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("user not found", func(t *testing.T) {
		nonexistentUser := "nonexistent"
		expectedQuery := `SELECT id, username FROM users WHERE username = \$1`

		mock.ExpectQuery(expectedQuery).
			WithArgs(nonexistentUser).
			WillReturnError(pgx.ErrNoRows)

		result, err := repo.FetchUser(ctx, nonexistentUser)

		require.NoError(t, err)
		assert.Nil(t, result)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("database error", func(t *testing.T) {
		expectedQuery := `SELECT id, username FROM users WHERE username = \$1`

		mock.ExpectQuery(expectedQuery).
			WithArgs(username).
			WillReturnError(fmt.Errorf("database is locked"))

		_, err := repo.FetchUser(ctx, username)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "database is locked")
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("malformed data", func(t *testing.T) {
		expectedQuery := `SELECT id, username FROM users WHERE username = \$1`

		// Invalid UUID for ID field
		rows := pgxmock.NewRows([]string{"id", "username"}).
			AddRow("invalid-uuid", username)

		mock.ExpectQuery(expectedQuery).
			WithArgs(username).
			WillReturnRows(rows)

		_, err := repo.FetchUser(ctx, username)

		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestUserRepository_EdgeCases(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	repo := NewUserRepository(mock)
	ctx := context.Background()

	t.Run("very long username", func(t *testing.T) {
		longUsername := string(make([]byte, 1000)) // Very long username
		expectedQuery := `SELECT 1 FROM users WHERE username = \$1 LIMIT 1`

		mock.ExpectQuery(expectedQuery).
			WithArgs(longUsername).
			WillReturnError(pgx.ErrNoRows)

		exists, err := repo.CheckUserExists(ctx, longUsername)

		require.NoError(t, err)
		assert.False(t, exists)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("special characters in username", func(t *testing.T) {
		specialUsername := "user@domain.com"
		expectedQuery := `SELECT 1 FROM users WHERE username = \$1 LIMIT 1`

		rows := pgxmock.NewRows([]string{"exists"}).AddRow(1)

		mock.ExpectQuery(expectedQuery).
			WithArgs(specialUsername).
			WillReturnRows(rows)

		exists, err := repo.CheckUserExists(ctx, specialUsername)

		require.NoError(t, err)
		assert.True(t, exists)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("unicode username", func(t *testing.T) {
		unicodeUsername := "用户名"
		expectedQuery := `SELECT 1 FROM users WHERE username = \$1 LIMIT 1`

		mock.ExpectQuery(expectedQuery).
			WithArgs(unicodeUsername).
			WillReturnError(pgx.ErrNoRows)

		exists, err := repo.CheckUserExists(ctx, unicodeUsername)

		require.NoError(t, err)
		assert.False(t, exists)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("context cancellation", func(t *testing.T) {
		cancelCtx, cancel := context.WithCancel(ctx)
		cancel() // Cancel immediately

		expectedQuery := `SELECT 1 FROM users WHERE username = \$1 LIMIT 1`

		mock.ExpectQuery(expectedQuery).
			WithArgs("testuser").
			WillReturnError(context.Canceled)

		_, err := repo.CheckUserExists(cancelCtx, "testuser")

		assert.Error(t, err)
		assert.Equal(t, context.Canceled, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("context timeout", func(t *testing.T) {
		timeoutCtx, cancel := context.WithTimeout(ctx, time.Nanosecond)
		defer cancel()

		time.Sleep(time.Millisecond) // Ensure timeout has passed

		expectedQuery := `SELECT 1 FROM users WHERE username = \$1 LIMIT 1`

		mock.ExpectQuery(expectedQuery).
			WithArgs("testuser").
			WillReturnError(context.DeadlineExceeded)

		_, err := repo.CheckUserExists(timeoutCtx, "testuser")

		assert.Error(t, err)
		assert.Equal(t, context.DeadlineExceeded, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestUserRepository_ConcurrentAccess(t *testing.T) {
	mock, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mock.Close()

	repo := NewUserRepository(mock)
	ctx := context.Background()

	// Simulate concurrent access scenarios
	t.Run("concurrent user existence checks", func(t *testing.T) {
		usernames := []string{"user1", "user2", "user3"}

		for _, username := range usernames {
			expectedQuery := `SELECT 1 FROM users WHERE username = \$1 LIMIT 1`

			mock.ExpectQuery(expectedQuery).
				WithArgs(username).
				WillReturnError(pgx.ErrNoRows)
		}

		// Simulate concurrent checks
		done := make(chan bool, len(usernames))
		for _, username := range usernames {
			go func(user string) {
				defer func() { done <- true }()
				exists, err := repo.CheckUserExists(ctx, user)
				assert.NoError(t, err)
				assert.False(t, exists)
			}(username)
		}

		// Wait for all goroutines to complete
		for i := 0; i < len(usernames); i++ {
			<-done
		}

		assert.NoError(t, mock.ExpectationsWereMet())
	})
}