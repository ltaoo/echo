//go:build linux

package main

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/ltaoo/echo"
)

const linuxModifiedTitle = "[echo linux] title modified"

var titleTagPattern = regexp.MustCompile(`(?is)(<title\b[^>]*>).*?(</title>)`)

func qqTitleRewritePlugin(logWriter io.Writer, target *echo.TargetConfig) *echo.Plugin {
	return &echo.Plugin{
		Match:  "**.qq.com",
		Target: target,
		OnRequest: func(ctx *echo.Context) {
			if ctx.Req == nil || logWriter == nil {
				return
			}
			fmt.Fprintf(logWriter, "%s %s\n", ctx.Req.Method, ctx.Req.URL.String())
		},
		OnResponse: func(ctx *echo.Context) {
			if ctx.Res == nil || !isWebPageResponse(ctx.Res) {
				return
			}

			body, err := ctx.GetResponseBody()
			if err != nil {
				return
			}

			modified := titleTagPattern.ReplaceAllString(body, "${1}"+linuxModifiedTitle+"${2}")
			ctx.SetResponseBody(modified)
		},
	}
}

func isWebPageResponse(res *http.Response) bool {
	contentType := strings.ToLower(res.Header.Get("Content-Type"))
	return strings.Contains(contentType, "text/html") ||
		strings.Contains(contentType, "application/xhtml+xml")
}

func TestLinuxQQPluginPrintsRequestAndRewritesHTMLTitle(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var compressed bytes.Buffer
		gzipWriter := gzip.NewWriter(&compressed)
		_, _ = gzipWriter.Write([]byte(`<!doctype html><html><head><title>Original QQ Title</title></head><body>ok</body></html>`))
		if err := gzipWriter.Close(); err != nil {
			t.Fatalf("gzip response body: %v", err)
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", compressed.Len()))
		_, _ = w.Write(compressed.Bytes())
	}))
	defer upstream.Close()

	target := targetFromServerURL(t, upstream.URL)
	var requestLog bytes.Buffer
	loader, err := echo.NewPluginLoader([]*echo.Plugin{
		qqTitleRewritePlugin(&requestLog, target),
	})
	if err != nil {
		t.Fatal(err)
	}

	handler := echo.NewHTTPHandler(loader)
	handler.Transport.Proxy = nil

	req := httptest.NewRequest(http.MethodGet, "http://www.qq.com/index.html?from=linux", nil)
	req.Host = "www.qq.com"
	rec := httptest.NewRecorder()

	handler.HandleRequest(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	body := string(bodyBytes)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status code: got %d, want %d; body: %s", resp.StatusCode, http.StatusOK, body)
	}
	if got := resp.Header.Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding: got %q, want empty after body rewrite", got)
	}
	if !strings.Contains(body, "<title>"+linuxModifiedTitle+"</title>") {
		t.Fatalf("rewritten title missing from body: %s", body)
	}
	if strings.Contains(body, "Original QQ Title") {
		t.Fatalf("original title was not replaced: %s", body)
	}
	if got := requestLog.String(); !strings.Contains(got, "GET http://www.qq.com/index.html?from=linux") {
		t.Fatalf("request log did not include qq request, got %q", got)
	}
}

func TestLinuxQQPluginDoesNotRewriteNonWebPageResponse(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"title":"Original QQ Title"}`))
	}))
	defer upstream.Close()

	target := targetFromServerURL(t, upstream.URL)
	loader, err := echo.NewPluginLoader([]*echo.Plugin{
		qqTitleRewritePlugin(io.Discard, target),
	})
	if err != nil {
		t.Fatal(err)
	}

	handler := echo.NewHTTPHandler(loader)
	handler.Transport.Proxy = nil

	req := httptest.NewRequest(http.MethodGet, "http://news.qq.com/data.json", nil)
	req.Host = "news.qq.com"
	rec := httptest.NewRecorder()

	handler.HandleRequest(rec, req)

	body := rec.Body.String()
	if body != `{"title":"Original QQ Title"}` {
		t.Fatalf("non-web response was modified: %s", body)
	}
}

func TestLinuxQQPluginPatternMatchesQQSubdomains(t *testing.T) {
	loader, err := echo.NewPluginLoader([]*echo.Plugin{
		qqTitleRewritePlugin(io.Discard, nil),
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, rawURL := range []string{
		"http://www.qq.com/",
		"https://a.b.qq.com/path",
	} {
		req, err := http.NewRequest(http.MethodGet, rawURL, nil)
		if err != nil {
			t.Fatal(err)
		}
		if got := loader.MatchPluginForRequest(req); got == nil {
			t.Fatalf("expected **.qq.com plugin to match %s", rawURL)
		}
	}

	req, err := http.NewRequest(http.MethodGet, "https://qq.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := loader.MatchPluginForRequest(req); got != nil {
		t.Fatalf("did not expect **.qq.com plugin to match root qq.com")
	}
}

func targetFromServerURL(t *testing.T, rawURL string) *echo.TargetConfig {
	t.Helper()

	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatal(err)
	}
	return &echo.TargetConfig{
		Protocol: u.Scheme,
		Host:     host,
		Port:     atoiForTest(t, port),
	}
}

func atoiForTest(t *testing.T, value string) int {
	t.Helper()

	var n int
	if _, err := fmt.Sscanf(value, "%d", &n); err != nil {
		t.Fatalf("parse port %q: %v", value, err)
	}
	return n
}
