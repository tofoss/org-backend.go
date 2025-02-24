package errors

import "net/http"

func BadRequest(w http.ResponseWriter) {
	http.Error(w, "Invalid request body", http.StatusBadRequest)
}

func InternalServerError(w http.ResponseWriter) {
	http.Error(w, "Something went wrong", http.StatusInternalServerError)
}

func Conflict(w http.ResponseWriter, msg string) {
	http.Error(w, msg, http.StatusConflict)
}

func Unauthorized(w http.ResponseWriter, msg string) {
	http.Error(w, msg, http.StatusUnauthorized)
}
