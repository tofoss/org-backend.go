package utils

import "testing"

func TestGenerateTitleFromContent(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected string
	}{
		{
			name:     "Empty content",
			content:  "",
			expected: "Untitled",
		},
		{
			name:     "Only whitespace",
			content:  "   \n\n\t  ",
			expected: "Untitled",
		},
		{
			name:     "Simple text",
			content:  "My Great Idea\nSome additional content here",
			expected: "My Great Idea",
		},
		{
			name:     "Header markdown",
			content:  "# My Great Idea\nSome content",
			expected: "My Great Idea",
		},
		{
			name:     "Multiple headers",
			content:  "## Another Header\nContent follows",
			expected: "Another Header",
		},
		{
			name:     "Bold text",
			content:  "**Bold text** here",
			expected: "Bold text here",
		},
		{
			name:     "Italic text",
			content:  "*Italic text* here",
			expected: "Italic text here",
		},
		{
			name:     "Underscore emphasis",
			content:  "__Bold__ and _italic_ text",
			expected: "Bold and italic text",
		},
		{
			name:     "List item",
			content:  "- Task item one\n- Task item two",
			expected: "Task item one",
		},
		{
			name:     "Numbered list",
			content:  "1. First item\n2. Second item",
			expected: "First item",
		},
		{
			name:     "Blockquote",
			content:  "> This is a quote\nRegular text",
			expected: "This is a quote",
		},
		{
			name:     "Code inline",
			content:  "`code snippet` in title",
			expected: "code snippet in title",
		},
		{
			name:     "Link markdown",
			content:  "[Link text](https://example.com) in title",
			expected: "Link text in title",
		},
		{
			name:     "Image markdown",
			content:  "![Alt text](image.png) description",
			expected: "Alt text description",
		},
		{
			name:     "Complex markdown",
			content:  "## **Bold Header** with [link](url) and *emphasis*",
			expected: "Bold Header with link and emphasis",
		},
		{
			name:     "Long title truncation",
			content:  "This is a very long title that exceeds the eighty character limit and should be truncated",
			expected: "This is a very long title that exceeds the eighty character limit and should ...",
		},
		{
			name:     "Leading whitespace in first line",
			content:  "   \n\n  My Title After Whitespace\nContent",
			expected: "My Title After Whitespace",
		},
		{
			name:     "Strikethrough text",
			content:  "~~Deleted text~~ and normal text",
			expected: "Deleted text and normal text",
		},
		{
			name:     "Mixed list markers",
			content:  "+ Plus list item\n* Star list item",
			expected: "Plus list item",
		},
		{
			name:     "Only markdown that gets removed",
			content:  "###   \n**  **\n  \nActual content",
			expected: "Actual content",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GenerateTitleFromContent(tt.content)
			if result != tt.expected {
				t.Errorf("GenerateTitleFromContent() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

func TestSanitizeMarkdown(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Header with multiple hashes",
			input:    "### Header Text",
			expected: "Header Text",
		},
		{
			name:     "Bold with asterisks",
			input:    "**Bold Text**",
			expected: "Bold Text",
		},
		{
			name:     "Italic with asterisks",
			input:    "*Italic Text*",
			expected: "Italic Text",
		},
		{
			name:     "Complex link",
			input:    "Check out [this link](https://example.com/very/long/url)",
			expected: "Check out this link",
		},
		{
			name:     "List marker with dash",
			input:    "- List item text",
			expected: "List item text",
		},
		{
			name:     "Numbered list",
			input:    "42. Numbered item",
			expected: "Numbered item",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeMarkdown(tt.input)
			if result != tt.expected {
				t.Errorf("sanitizeMarkdown() = %q, expected %q", result, tt.expected)
			}
		})
	}
}