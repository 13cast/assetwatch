package tech_detector_test

import (
	"net/http"
	"testing"

	"github.com/13cast/assetwatch/pkg/tech_detector"
)

func TestDetect(t *testing.T) {
	d := tech_detector.New()

	headers := http.Header{}
	headers.Set("Server", "nginx/1.18.0")
	headers.Set("X-Powered-By", "Next.js")
	headers.Set("Cf-Ray", "1234567890")

	cookies := []*http.Cookie{
		{Name: "csrftoken", Value: "abcdef12345"},
	}

	body := []byte(`<!DOCTYPE html><html><head><meta name="generator" content="WordPress 6.4"><script src="/wp-content/themes/twentytwenty/app.js"></script></head><body><div id="__next"></div></body></html>`)

	detected := d.Detect(headers, cookies, body)

	expected := map[string]bool{
		"Nginx":         true,
		"Next.js":       true,
		"Cloudflare":    true,
		"Django":        true,
		"WordPress":     true,
		"WordPress 6.4": true,
	}

	for _, tech := range detected {
		delete(expected, tech)
	}

	for missing := range expected {
		t.Errorf("expected technology %q was not detected in %v", missing, detected)
	}
}
