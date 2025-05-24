package main

import (
	"fmt"
	"os"
	"tofoss/org-go/pkg/parser"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Error: Missing URL argument")
		fmt.Println("Usage: go run cmd/parser <url>")
		os.Exit(1)
	}

	url := os.Args[1]

	extractor := parser.NewMainContentExtractor()

	text, err := extractor.ExtractFromURL(url)
	if err != nil {
		fmt.Printf("Error extracting text: %s\n", err)
		os.Exit(1)
	}

	fmt.Println(text)
}
