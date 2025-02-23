package main

import (
	"log"
	"net/http"
	"tofoss/org-go/pkg/db"
	"tofoss/org-go/pkg/server"
)

func main() {
	pool := db.NewPool()
	srv := server.NewServer(pool)
	log.Printf("Starting server on %s\n", "localhost:8081")
	log.Fatal(http.ListenAndServe(":8081", srv))
}
