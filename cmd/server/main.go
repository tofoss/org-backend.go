package main

import (
	"log"
	"net/http"
	"tofoss/org-go/pkg/server"
)

func main() {
	srv := server.NewServer()
	log.Printf("Starting server on %s\n", "foo.bar")
	log.Fatal(http.ListenAndServe(":8081", srv))
}
