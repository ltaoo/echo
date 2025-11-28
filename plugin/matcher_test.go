package plugin

import (
	"testing"
)

func assertMatch(t *testing.T, hostname, pattern string, expected bool) {
	t.Helper()
	got := isMatch(hostname, pattern)
	if got != expected {
		t.Fatalf("isMatch\n  pattern:   %q\n  hostname:  %q\n  expected:  %v\n  received:  %v", pattern, hostname, expected, got)
	}
}

func TestIsMatch(t *testing.T) {
	cases := []struct {
		name     string
		hostname string
		pattern  string
		expected bool
	}{
		{"exact host", "example.com", "example.com", true},
		{"subdomain vs exact host (substring)", "sub.example.com", "example.com", true},
		{"wildcard single-level", "a.example.com", "*.example.com", true},
		{"wildcard multi-level", "a.b.example.com", "*.example.com", true},
		{"wildcard has suffix slash", "https://www.baidu.com/", "*.baidu.com/*", true},
		{"wildcard not root", "example.com", "*.example.com", false},
		{"substring host positive", "test.example.com", "example", true},
		{"substring host different TLD", "myexample.net", "example", true},
		{"substring host negative", "samples.com", "example", false},
		{"any star matches anything", "anything.com", "*", true},
		{"url exact", "https://api.example.com/index.html", "https://api.example.com/index.html", true},
		{"url wildcard domain and path", "https://api.example.com/index.html", "https://*.example.com/*", true},
		{"url wildcard negative", "https://api.other.com/index.html", "https://*.example.com/*", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assertMatch(t, c.hostname, c.pattern, c.expected)
		})
	}
}
