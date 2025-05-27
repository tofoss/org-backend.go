package main

import (
	"context"
	"fmt"
	"os"
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

	client := genai.NewDeepseekClient()
	systemContent := `
		The user will provide some text that will contain a recipe. Please extract the number of servings mentioned, the ingredient list and steps to make the recipe. Also create a summary of the recipe containing maximum 200 characters.
		Please output the recipe in JSON format.

		EXAMPLE INPUT:
		A fast and flavorful stir-fried greens dish using soy sauce, garlic, and chili. Great as a side or a light meal.
		Ingredients:
			200g bok choy
			1–2 tablespoons soy sauce (Adjust to taste)
			1 clove garlic (minced)
			0.5–1 teaspoon chili flakes (optional)
			1 teaspoon sesame oil
			Salt and pepper to taste
		Steps:
			Heat sesame oil in a pan over medium heat.
			Add garlic and chili flakes (if using), sauté briefly until fragrant.
			Toss in bok choy and stir-fry until wilted.
			Add soy sauce and cook for another 1–2 minutes.
			Serve immediately.

		EXAMPLE OUTPUT:
		{
		  "name": "Quick Stir-Fried Greens",
		  "summary": "A fast and flavorful stir-fried greens dish using soy sauce, garlic, and chili. Great as a side or a light meal.",
		  "servings": 2,
		  "ingredients": [
			{
			  "name": "Bok choy",
			  "quantity": {
				"min": 200,
				"max": 200,
				"unit": "grams"
			  },
			  "isOptional": false,
			  "notes": ""
			},
			{
			  "name": "Soy sauce",
			  "quantity": {
				"min": 1,
				"max": 2,
				"unit": "tablespoons"
			  },
			  "isOptional": false,
			  "notes": "Adjust to taste"
			},
			{
			  "name": "Garlic",
			  "quantity": {
				"min": 1,
				"max": 1,
				"unit": "clove"
			  },
			  "isOptional": false,
			  "notes": "Minced"
			},
			{
			  "name": "Chili flakes",
			  "quantity": {
				"min": 0.5,
				"max": 1,
				"unit": "teaspoons"
			  },
			  "isOptional": true,
			  "notes": ""
			},
			{
			  "name": "Sesame oil",
			  "quantity": {
				"min": 1,
				"max": 1,
				"unit": "teaspoon"
			  },
			  "isOptional": false,
			  "notes": ""
			},
			{
			  "name": "Salt",
			  "quantity": null,
			  "isOptional": false,
			  "notes": "To taste"
			},
			{
			  "name": "Pepper",
			  "quantity": null,
			  "isOptional": false,
			  "notes": "To taste"
			},
		  ],
		  "steps": [
			"Heat sesame oil in a pan over medium heat.",
			"Add garlic and chili flakes (if using), sauté briefly until fragrant.",
			"Toss in bok choy and stir-fry until wilted.",
			"Add soy sauce and cook for another 1–2 minutes.",
			"Serve immediately."
		  ]
		}

	`

	msg, err := client.Chat(systemContent, userContent, true, ctx)

	if err != nil {
		fmt.Printf("%v\n", err)
		os.Exit(1)
	}

	fmt.Println(msg)
}
