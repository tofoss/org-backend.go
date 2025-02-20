package db

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func NewPool() *pgxpool.Pool {
	pool, err := pgxpool.New(context.Background(), buildPostgresDSN())
	if err != nil {
		log.Fatal("Unable to connect to database:", err)
	}
	defer pool.Close()

	return pool
}

func buildPostgresDSN() string {
	config, err := pgx.ParseConfig("")
	if err != nil {
		panic(fmt.Sprintf("Failed to parse PG config: %v", err))
	}

	config.Host = getEnv("POSTGRES_HOST", "localhost")
	config.Port = uint16(mustAtoi(getEnv("POSTGRES_PORT", "5432")))
	config.Database = getEnv("POSTGRES_DB", "mydb")
	config.User = getEnv("POSTGRES_USER", "postgres")
	config.Password = getEnv("POSTGRES_PASSWORD", "")

	return config.ConnString()
}

func mustAtoi(s string) int {
	v, err := strconv.Atoi(s)
	if err != nil {
		panic(fmt.Sprintf("Invalid number: %s", s))
	}
	return v
}

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}
