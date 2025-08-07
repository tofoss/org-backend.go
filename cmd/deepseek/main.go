package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"tofoss/org-go/pkg/genai"
	"tofoss/org-go/pkg/parser"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Error: missing arguments")
		fmt.Println("Usage: go run cmd/deepseek url")
		os.Exit(1)
	}
	url := os.Args[1]
	ctx := context.Background()

	extractor := parser.NewMainContentExtractor()

	userContent, err := extractor.ExtractFromURL(url)
	if err != nil {
		fmt.Printf("Error extracting text: %s\n", err)
		os.Exit(1)
	}

	fmt.Println(userContent)
	fmt.Printf("Extracted text from url. len=%d\n\n", len(userContent))

	// Load prompt from file
	promptPath := filepath.Join("prompts", "recipe_extraction.txt")
	systemContentBytes, err := os.ReadFile(promptPath)
	if err != nil {
		fmt.Printf("Error reading prompt file: %s\n", err)
		os.Exit(1)
	}
	systemContent := string(systemContentBytes)

	client := genai.NewDeepseekClient()

	msg, err := client.Chat(systemContent, userContent, true, ctx)

	if err != nil {
		fmt.Printf("%v\n", err)
		os.Exit(1)
	}

	fmt.Println(msg)
}
