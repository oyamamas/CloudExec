package utils

import (
	"strings"
	"testing"
)

func TestParseExportersType(t *testing.T) {
	for _, tt := range []struct{ html, want string }{
		{"<header><h1>Node Exporter</h1></header>", "Node Exporter"},
		{"<h1>postgres_exporter</h1>", "postgres_exporter"},
		{"<title>Redis Exporter</title>", "Redis Exporter"},
		{"<h1>Login</h1>", ""},
		{"{}", ""},
		{"", ""},
	} {
		got, err := ParseExportersType(strings.NewReader(tt.html))
		if got != tt.want || (err != nil) != (tt.want == "") {
			t.Errorf("ParseExportersType(%q) = %q, %v; want %q", tt.html, got, err, tt.want)
		}
	}
}
