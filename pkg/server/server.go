package server

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

func NewServer() *chi.Mux {
	router := chi.NewRouter()

	router.Get("/", HomeHandler)

	return router
}

func HomeHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Hello, world"))
}
