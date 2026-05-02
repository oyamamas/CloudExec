package utils

import (
	"fmt"
	"io"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

// Copyright 2026 oyama forked cotsom
// regexp engine for exporters

// llm helped here oops
func ParseExportersType(body io.ReadCloser) (string, error) {
	defer body.Close()

	doc, err := goquery.NewDocumentFromReader(body)
	if err != nil {
		return "", fmt.Errorf("не удалось распарсить HTML: %w", err)
	}

	title := doc.Find("header h1").First().Text()
	title = strings.TrimSpace(title)

	if title == "" {
		// fallback — ищем любой h1
		title = doc.Find("h1").First().Text()
		title = strings.TrimSpace(title)
	}

	return title, nil
}
