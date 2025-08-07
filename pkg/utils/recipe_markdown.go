package utils

import (
	"strconv"
	"strings"
	"tofoss/org-go/pkg/models"
)

// RecipeToMarkdown converts a Recipe struct to formatted markdown
func RecipeToMarkdown(recipe models.Recipe) string {
	var md strings.Builder

	// Title
	md.WriteString("# ")
	md.WriteString(recipe.Name)
	md.WriteString("\n\n")

	// Summary
	if recipe.Summary != nil && *recipe.Summary != "" {
		md.WriteString(*recipe.Summary)
		md.WriteString("\n\n")
	}

	// Recipe info section
	md.WriteString("## Recipe Info\n\n")

	if recipe.Servings != nil {
		md.WriteString("**Servings:** ")
		md.WriteString(strconv.Itoa(*recipe.Servings))
		md.WriteString("\n")
	}

	if recipe.PrepTime != nil && *recipe.PrepTime != "" {
		md.WriteString("**Prep Time:** ")
		md.WriteString(*recipe.PrepTime)
		md.WriteString("\n")
	}

	if recipe.SourceURL != nil && *recipe.SourceURL != "" {
		md.WriteString("**Source:** ")
		md.WriteString(*recipe.SourceURL)
		md.WriteString("\n")
	}

	md.WriteString("\n")

	// Ingredients section
	md.WriteString("## Ingredients\n\n")
	for _, ingredient := range recipe.Ingredients {
		md.WriteString("- ")

		// Format quantity if present
		if ingredient.Quantity != nil {
			quantityStr := formatQuantity(*ingredient.Quantity)
			if quantityStr != "" {
				md.WriteString(quantityStr)
				md.WriteString(" ")
			}
		}

		// Ingredient name
		md.WriteString(ingredient.Name)

		// Mark optional ingredients
		if ingredient.IsOptional {
			md.WriteString(" *(optional)*")
		}

		// Add notes if present
		if ingredient.Notes != "" {
			md.WriteString(" - ")
			md.WriteString(ingredient.Notes)
		}

		md.WriteString("\n")
	}

	md.WriteString("\n")

	// Instructions section
	md.WriteString("## Instructions\n\n")
	for i, step := range recipe.Steps {
		md.WriteString(strconv.Itoa(i + 1))
		md.WriteString(". ")
		md.WriteString(step)
		md.WriteString("\n")
	}

	return md.String()
}

// formatQuantity formats a Quantity struct into a readable string
func formatQuantity(q models.Quantity) string {
	if q.Min == nil && q.Max == nil {
		return ""
	}

	var quantityStr string

	if q.Min != nil && q.Max != nil {
		// Range: "1-2 cups"
		if *q.Min == *q.Max {
			// Same min/max: "1 cup"
			quantityStr = formatNumber(*q.Min)
		} else {
			// Different min/max: "1-2 cups"
			quantityStr = formatNumber(*q.Min) + "-" + formatNumber(*q.Max)
		}
	} else if q.Min != nil {
		// Only minimum: "at least 1 cup"
		quantityStr = "at least " + formatNumber(*q.Min)
	} else if q.Max != nil {
		// Only maximum: "up to 2 cups"
		quantityStr = "up to " + formatNumber(*q.Max)
	}

	// Add unit
	if quantityStr != "" && q.Unit != "" {
		quantityStr += " " + q.Unit
	} else if q.Unit != "" {
		quantityStr = q.Unit
	}

	return quantityStr
}

// formatNumber formats a float64 to remove unnecessary decimal places
func formatNumber(n float64) string {
	if n == float64(int(n)) {
		// Whole number
		return strconv.Itoa(int(n))
	}
	// Has decimal places
	return strconv.FormatFloat(n, 'g', -1, 64)
}

