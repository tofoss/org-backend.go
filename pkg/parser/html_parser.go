package parser

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

type MainContentExtractor struct {
	FallbackToBody bool
}

func NewMainContentExtractor() *MainContentExtractor {
	return &MainContentExtractor{
		FallbackToBody: true,
	}
}

func (e *MainContentExtractor) ExtractFromURL(url string) (string, error) {
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "https://" + url
	}

	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("error making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("received non-200 response: %d %s", resp.StatusCode, resp.Status)
	}

	return e.ExtractFromReader(resp.Body)
}

func (e *MainContentExtractor) ExtractFromReader(r io.Reader) (string, error) {
	doc, err := goquery.NewDocumentFromReader(r)
	if err != nil {
		return "", fmt.Errorf("error parsing HTML: %w", err)
	}

	mainContent := doc.Find("main")

	if mainContent.Length() == 0 && e.FallbackToBody {
		mainContent = doc.Find("body")
		if mainContent.Length() == 0 {
			return "", fmt.Errorf("neither <main> nor <body> tags found in the HTML")
		}
	} else if mainContent.Length() == 0 {
		return "", fmt.Errorf("<main> tag not found in the HTML")
	}

	text := mainContent.Text()

	text = cleanWhitespace(text)

	return text, nil
}

func cleanWhitespace(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	return s
}
