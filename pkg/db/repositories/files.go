package repositories

import (
	"context"
	"fmt"

	"tofoss/org-go/pkg/models"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type FileRepository struct {
	pool *pgxpool.Pool
}

// FetchFile implements FileRepositoryInterface.
func (r *FileRepository) FetchFileForUser(ctx context.Context, id, userID uuid.UUID) (models.FileMetadata, error) {
	fmt.Printf("getting files where id = %v and user_id = %v", id, userID)
	query := `
	SELECT
		id,
		user_id,
		note_id,
		filetype,
		filesize,
		extension
	FROM files 
	WHERE id = $1 and user_id = $2
	`
	rows, err := r.pool.Query(ctx, query, id, userID)
	if err != nil {
		return models.FileMetadata{}, err
	}
	defer rows.Close()

	return pgx.CollectOneRow(rows, pgx.RowToStructByName[models.FileMetadata])
}

// Insert implements FileRepositoryInterface.
func (r *FileRepository) Insert(ctx context.Context, file models.FileMetadata) (models.FileMetadata, error) {
	query := `
	INSERT INTO files (
		id,
		user_id,
		note_id,
		filetype,
		filesize,
		extension
	) VALUES (
		$1,  -- id
		$2,  -- user_id
		$3,  -- note_id
		$4,  -- filetype
		$5,  -- filesize
		$6   -- extension
	)
	RETURNING 
		id,
		user_id,
		note_id,
		filetype,
		filesize,
		extension;
	`

	rows, err := r.pool.Query(ctx, query,
		file.ID,
		file.UserID,
		file.NoteID,
		file.Filetype,
		file.Filesize,
		file.Extension,
	)
	if err != nil {
		return models.FileMetadata{}, err
	}
	defer rows.Close()

	return pgx.CollectOneRow(rows, pgx.RowToStructByName[models.FileMetadata])
}

func NewFileRepository(pool *pgxpool.Pool) *FileRepository {
	return &FileRepository{pool: pool}
}
