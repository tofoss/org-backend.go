package models

import (
	"fmt"
	"path"

	"github.com/google/uuid"
)

type FileMetadata struct {
	ID        uuid.UUID  `json:"id"          db:"id"`
	UserID    uuid.UUID  `json:"userId"      db:"user_id"`
	NoteID    *uuid.UUID `json:"noteId"      db:"note_id"`
	Filetype  string     `json:"filetype"    db:"filetype"`
	Filesize  int        `json:"filesize"    db:"filesize"`
	Extension string     `json:"extension"   db:"extension"`
}

func (f *FileMetadata) Filepath(root string) string {
	part1 := root
	part2 := f.ID.String()[0:2]
	part3 := f.ID.String()[2:4]

	filepath := path.Join(part1, part2, part3)
	return filepath
}

func (f *FileMetadata) Filename() string {
	return fmt.Sprintf("%s.%s", f.ID, f.Extension)
}
