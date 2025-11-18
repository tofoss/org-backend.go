package handlers

import (
	"log"
	"net/http"
	"os"
	"path"

	"tofoss/org-go/pkg/handlers/errors"
	"tofoss/org-go/pkg/services"
	"tofoss/org-go/pkg/utils"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type FileHandler struct {
	fileService *services.FileService
	fileConfig  services.FileConfig
}

const (
	FormFileKey   = "file"
	FormNoteIDKey = "noteId"
)

func (h *FileHandler) FetchFile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, _, err := utils.UserContext(r)
	if err != nil {
		log.Printf("unable upload, user not logged in: %v", err)
		errors.Unauthenticated(w)
		return
	}

	fileID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		log.Printf("invalid file id: %v", err)
		errors.BadRequest(w)
		return
	}

	metadata, err := h.fileService.GetMetadata(ctx, fileID, userID)
	if err != nil {
		log.Printf("could not get file: %v", err)
		errors.Unauthorized(w, "could not get file")
		return
	}

	file, err := os.Open(path.Join(metadata.Filepath(h.fileConfig.StorageRoot), metadata.Filename()))
	if err != nil {
		log.Printf("could not get file: %v", err)
		errors.InternalServerError(w)
		return
	}

	response := make([]byte, metadata.Filesize)

	_, err = file.Read(response)
	if err != nil {
		log.Printf("could not get file: %v", err)
		errors.InternalServerError(w)
		return
	}

	w.Header().Set("Content-Type", metadata.Filetype)
	w.WriteHeader(http.StatusOK)

	w.Write(response)
}

func (h *FileHandler) UploadFile(w http.ResponseWriter, r *http.Request) {
	userID, _, err := utils.UserContext(r)
	if err != nil {
		log.Printf("unable upload, user not logged in: %v", err)
		errors.Unauthenticated(w)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, int64(h.fileConfig.MaxFilesize))
	defer r.Body.Close()

	file, header, err := r.FormFile(FormFileKey)
	if err != nil {
		log.Printf("could not upload file: %v", err)
		errors.BadRequest(w)
		return
	}

	rawNoteID := r.FormValue(FormNoteIDKey)

	var noteID *uuid.UUID
	if rawNoteID == "" {
		log.Printf("uploading file independent of note")
	} else {
		id, err := uuid.Parse(rawNoteID)
		if err != nil {
			log.Printf("could not parse noteID: %v", err)
			errors.BadRequest(w)
			return
		}
		noteID = &id
	}

	metadata, err := h.fileService.CreateFile(r.Context(), file, header, noteID, userID)
	if err != nil {
		log.Printf("could not create file: %v", err)
		errors.BadRequest(w)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)

	w.Write([]byte(metadata.ID.String()))
}

func NewFileHandler(
	fileService *services.FileService,
	fileConfig services.FileConfig,
) FileHandler {
	return FileHandler{fileService: fileService, fileConfig: fileConfig}
}
