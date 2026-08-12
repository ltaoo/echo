package echo

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestTargetConfigGetAuthorityOmitsDefaultPorts(t *testing.T) {
	tests := []struct {
		name     string
		target   TargetConfig
		protocol string
		want     string
	}{
		{
			name:     "https default port",
			target:   TargetConfig{Host: "wms-cn.urbanic-wms.cn", Port: 443},
			protocol: "https",
			want:     "wms-cn.urbanic-wms.cn",
		},
		{
			name:     "http default port",
			target:   TargetConfig{Host: "example.com", Port: 80},
			protocol: "http",
			want:     "example.com",
		},
		{
			name:     "local non-default port",
			target:   TargetConfig{Host: "127.0.0.1", Port: 3333},
			protocol: "http",
			want:     "127.0.0.1:3333",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.target.GetAuthority(tt.protocol); got != tt.want {
				t.Fatalf("GetAuthority() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestHTTPHandlerStreamsReaderMockBody(t *testing.T) {
	first_body_chunk := bytes.Repeat([]byte("v"), 64<<10)
	tail_chunk := []byte("second")
	body_reader, body_writer := io.Pipe()
	release_tail := make(chan struct{})
	writer_done := make(chan struct{})
	go func() {
		defer close(writer_done)
		_, _ = body_writer.Write(first_body_chunk)
		<-release_tail
		_, _ = body_writer.Write(tail_chunk)
		_ = body_writer.Close()
	}()

	loader, err := NewPluginLoader([]*Plugin{{
		Match: "video.example.test",
		OnRequest: func(context *Context) {
			context.Mock(http.StatusPartialContent, map[string]string{
				"Content-Type":   "video/mp4",
				"Content-Length": strconv.Itoa(len(first_body_chunk) + len(tail_chunk)),
				"Content-Range":  "bytes 0-65541/65542",
			}, body_reader)
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHTTPHandler(loader)
	server := httptest.NewServer(http.HandlerFunc(handler.HandleRequest))
	defer server.Close()

	request, err := http.NewRequest(http.MethodGet, server.URL+"/segment.mp4", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "video.example.test"
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		close(release_tail)
		t.Fatal(err)
	}
	defer response.Body.Close()

	first_chunk := make([]byte, len(first_body_chunk))
	if _, err := io.ReadFull(response.Body, first_chunk); err != nil {
		close(release_tail)
		t.Fatal(err)
	}
	if !bytes.Equal(first_chunk, first_body_chunk) {
		close(release_tail)
		t.Fatal("first streamed chunk changed")
	}
	if response.Header.Get("Content-Range") != "bytes 0-65541/65542" {
		close(release_tail)
		t.Fatalf("Content-Range = %q", response.Header.Get("Content-Range"))
	}

	close(release_tail)
	tail, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(tail, tail_chunk) {
		t.Fatalf("tail = %q, want %q", tail, tail_chunk)
	}
	select {
	case <-writer_done:
	case <-time.After(2 * time.Second):
		t.Fatal("mock response writer did not finish")
	}
}
