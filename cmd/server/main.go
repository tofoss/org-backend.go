package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
	"tofoss/org-go/pkg/db"
	"tofoss/org-go/pkg/server"
)

func main() {
	// Create context that can be cancelled
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize database pool
	pool := db.NewPool()
	defer pool.Close()

	// Create server with background services
	srv, err := server.NewServer(ctx, pool)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	// Start background services
	srv.Start(ctx)
	defer srv.Stop()

	// Setup HTTP server
	httpServer := &http.Server{
		Addr:    ":8081",
		Handler: srv.Router,
	}

	// Start HTTP server in a goroutine
	go func() {
		log.Printf("Starting server on localhost:8081")
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server failed: %v", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")

	// Cancel context to stop background services
	cancel()

	// Shutdown HTTP server with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("HTTP server forced to shutdown: %v", err)
	} else {
		log.Println("Server gracefully stopped")
	}
}
