package utils

import (
	"regexp"
	"strings"
)

// GenerateTitleFromContent extracts and sanitizes the first line of content to create a title
func GenerateTitleFromContent(content string) string {
	if content == "" {
		return "Untitled"
	}

	// Split content into lines and find first line that produces usable content after sanitization
	lines := strings.Split(content, "\n")
	var title string
	
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		
		// Remove markdown syntax
		sanitized := sanitizeMarkdown(trimmed)
		
		// Trim whitespace again after sanitization
		sanitized = strings.TrimSpace(sanitized)
		
		if sanitized != "" {
			title = sanitized
			break
		}
	}

	if title == "" {
		return "Untitled"
	}

	// Truncate to 80 characters
	if len(title) > 80 {
		title = title[:80-3] + "..."
	}

	return title
}

// sanitizeMarkdown removes common markdown syntax from text
func sanitizeMarkdown(text string) string {
	// Remove leading # (headers)
	text = regexp.MustCompile(`^#+\s*`).ReplaceAllString(text, "")
	
	// Remove emphasis markers (* and _)
	text = regexp.MustCompile(`\*\*([^*]+)\*\*`).ReplaceAllString(text, "$1") // **bold**
	text = regexp.MustCompile(`\*([^*]+)\*`).ReplaceAllString(text, "$1")     // *italic*
	text = regexp.MustCompile(`__([^_]+)__`).ReplaceAllString(text, "$1")     // __bold__
	text = regexp.MustCompile(`_([^_]+)_`).ReplaceAllString(text, "$1")       // _italic_
	
	// Remove strikethrough
	text = regexp.MustCompile(`~~([^~]+)~~`).ReplaceAllString(text, "$1")
	
	// Remove code markers
	text = regexp.MustCompile("`([^`]+)`").ReplaceAllString(text, "$1")       // `code`
	
	// Remove blockquote markers
	text = regexp.MustCompile(`^>\s*`).ReplaceAllString(text, "")
	
	// Remove list markers (-, +, *, numbered lists)
	text = regexp.MustCompile(`^[-+*]\s+`).ReplaceAllString(text, "")
	text = regexp.MustCompile(`^\d+\.\s+`).ReplaceAllString(text, "")
	
	// Remove link syntax [text](url) -> text
	text = regexp.MustCompile(`\[([^\]]+)\]\([^)]+\)`).ReplaceAllString(text, "$1")
	
	// Remove image syntax ![alt](url) -> alt (handle the ! separately)
	text = regexp.MustCompile(`!\[([^\]]*)\]\([^)]+\)`).ReplaceAllString(text, "$1")
	
	// Remove any remaining ! characters that might be left from images
	text = strings.ReplaceAll(text, "!", "")
	
	// Remove remaining brackets and parentheses that might be left
	text = regexp.MustCompile(`[\[\]()]`).ReplaceAllString(text, "")
	
	return text
}