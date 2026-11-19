package http_inspector_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/13cast/assetwatch/pkg/http_inspector"
)

func TestInspector_InspectBatch(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Server", "nginx/1.24.0")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><head><meta name=\"generator\" content=\"Hugo 0.120\"></head><body>Test</body></html>"))
	}))
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("failed to parse url: %v", err)
	}

	ins := http_inspector.New(http_inspector.Config{
		Workers: 2,
		Timeout: 2 * time.Second,
	})

	results := ins.InspectBatch(context.Background(), []string{u.Host})

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	res := results[0]
	if !res.Reachable {
		t.Errorf("expected host to be reachable, got error: %s", res.Error)
	}

	if res.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", res.StatusCode)
	}

	if !res.SecurityHeaders.HSTS {
		t.Errorf("expected HSTS to be detected")
	}

	if !res.SecurityHeaders.CSP {
		t.Errorf("expected CSP to be detected")
	}

	if !res.SecurityHeaders.XFrameOptions {
		t.Errorf("expected X-Frame-Options to be detected")
	}
}
