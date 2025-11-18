package services

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path"

	"tofoss/org-go/pkg/db/repositories"
	"tofoss/org-go/pkg/models"

	"github.com/google/uuid"
)

type FileService struct {
	repo   repositories.FileRepositoryInterface
	config FileConfig
}

func (s *FileService) GetMetadata(ctx context.Context, id, userID uuid.UUID) (*models.FileMetadata, error) {
	meta, err := s.repo.FetchFileForUser(ctx, id, userID)
	if err != nil {
		return nil, err
	}
	return &meta, nil
}

func NewFileService(
	repo repositories.FileRepositoryInterface,
	config FileConfig,
) *FileService {
	return &FileService{
		repo:   repo,
		config: config,
	}
}

type FileConfig struct {
	StorageRoot        string
	MaxFilesize        int
	SupportedFiletypes map[string]string
}

func (s *FileService) CreateFile(
	ctx context.Context,
	file multipart.File,
	header *multipart.FileHeader,
	noteID *uuid.UUID,
	userID uuid.UUID,
) (*models.FileMetadata, error) {
	log.Printf("Creating file...")
	defer file.Close()

	buffer := make([]byte, header.Size)
	_, err := file.Read(buffer)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("could not read file content %w", err)
	}

	mimeType, err := s.checkSupportedFiletype(buffer)
	if err != nil {
		return nil, err
	}

	log.Printf("Found file format %s", s.config.SupportedFiletypes[mimeType])

	fileID, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("failed to create random uuid %w", err)
	}

	metadata := models.FileMetadata{
		ID:        fileID,
		UserID:    userID,
		NoteID:    noteID,
		Filetype:  mimeType,
		Filesize:  int(header.Size),
		Extension: s.config.SupportedFiletypes[mimeType],
	}

	if err = s.storeFileToDisk(buffer, metadata); err != nil {
		return nil, err
	}

	_, err = s.repo.Insert(ctx, metadata)
	if err != nil {
		return nil, err
	}

	log.Printf("created file %v", metadata.ID)

	return &metadata, nil
}

func (s *FileService) storeFileToDisk(data []byte, file models.FileMetadata) error {
	dst, err := s.createDestination(file)
	if err != nil {
		return fmt.Errorf("failed to create file %w", err)
	}
	defer dst.Close()

	_, err = io.Copy(dst, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to store file to disk %w", err)
	}

	log.Printf("stored file to disk: %v", dst)

	return nil
}

func (s *FileService) createDestination(file models.FileMetadata) (*os.File, error) {
	filepath := file.Filepath(s.config.StorageRoot)
	err := os.MkdirAll(filepath, 0o700)
	if err != nil {
		return nil, err
	}

	dst, err := os.Create(path.Join(filepath, file.Filename()))
	if err != nil {
		return nil, err
	}

	return dst, nil
}

func (s *FileService) checkSupportedFiletype(data []byte) (string, error) {
	mimeType := http.DetectContentType(data)

	if s.config.SupportedFiletypes[mimeType] == "" {
		return mimeType, fmt.Errorf("unsupported filetype: %s", mimeType)
	}
	return mimeType, nil
}
