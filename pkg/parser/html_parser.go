package parser

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/chromedp/chromedp"
)

type MainContentExtractor struct {
	FallbackToBody bool
	Timeout        time.Duration
}

func NewMainContentExtractor() *MainContentExtractor {
	return &MainContentExtractor{
		FallbackToBody: true,
		Timeout:        15 * time.Second,
	}
}

func (e *MainContentExtractor) ExtractFromURL(url string) (string, error) {
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "https://" + url
	}

	ctx, cancel := chromedp.NewContext(context.Background())
	defer cancel()

	ctx, cancel = context.WithTimeout(ctx, e.Timeout)
	defer cancel()

	var html string
	err := chromedp.Run(ctx,
		chromedp.Navigate(url),
		chromedp.OuterHTML("html", &html),
	)
	if err != nil {
		return "", fmt.Errorf("chromedp navigation error: %w", err)
	}

	return e.ExtractFromHTML(html)
}

func (e *MainContentExtractor) ExtractFromHTML(html string) (string, error) {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
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
	return strings.Join(strings.Fields(s), " ")
}
