// Package tech_detector fingerprints web technologies from HTTP response headers,
// cookies, and HTML body snippets.
package tech_detector

import (
	"net/http"
	"regexp"
	"sort"
	"strings"
)

// MatchRule defines a rule to detect a specific technology.
type MatchRule struct {
	Name    string
	Headers map[string]*regexp.Regexp
	Cookies []*regexp.Regexp
	Body    []*regexp.Regexp
}

// Detector holds the signature database and methods to fingerprint responses.
type Detector struct {
	rules []MatchRule
}

// New creates a Detector preloaded with common web fingerprints.
func New() *Detector {
	return &Detector{
		rules: defaultRules(),
	}
}

// Detect inspects HTTP response headers, cookies, and a prefix of the body
// to return a unique, sorted slice of identified technologies.
func (d *Detector) Detect(header http.Header, cookies []*http.Cookie, bodySnippet []byte) []string {
	found := make(map[string]struct{})
	bodyStr := string(bodySnippet)

	// Extract generator meta tag if present
	if gen := extractMetaGenerator(bodyStr); gen != "" {
		found[gen] = struct{}{}
	}

	for _, rule := range d.rules {
		matched := false

		// 1. Header checks
		for headerName, pattern := range rule.Headers {
			for _, val := range header.Values(headerName) {
				if pattern == nil || pattern.MatchString(val) {
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}

		// 2. Cookie checks
		if !matched && len(rule.Cookies) > 0 {
			for _, cookie := range cookies {
				for _, pattern := range rule.Cookies {
					if pattern.MatchString(cookie.Name) {
						matched = true
						break
					}
				}
				if matched {
					break
				}
			}
		}

		// 3. Body patterns
		if !matched && len(rule.Body) > 0 && len(bodySnippet) > 0 {
			for _, pattern := range rule.Body {
				if pattern.MatchString(bodyStr) {
					matched = true
					break
				}
			}
		}

		if matched {
			found[rule.Name] = struct{}{}
		}
	}

	res := make([]string, 0, len(found))
	for name := range found {
		res = append(res, name)
	}
	sort.Strings(res)
	return res
}

var metaGenRegex = regexp.MustCompile(`(?i)<meta\s+[^>]*name=["']generator["'][^>]*content=["']([^"']+)["']`)
var metaGenRegexAlt = regexp.MustCompile(`(?i)<meta\s+[^>]*content=["']([^"']+)["'][^>]*name=["']generator["']`)

func extractMetaGenerator(body string) string {
	if m := metaGenRegex.FindStringSubmatch(body); len(m) > 1 {
		return strings.TrimSpace(m[1])
	}
	if m := metaGenRegexAlt.FindStringSubmatch(body); len(m) > 1 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

func defaultRules() []MatchRule {
	ci := func(pattern string) *regexp.Regexp {
		return regexp.MustCompile("(?i)" + pattern)
	}

	return []MatchRule{
		// Servers & CDNs
		{
			Name: "Nginx",
			Headers: map[string]*regexp.Regexp{
				"Server": ci(`nginx`),
			},
		},
		{
			Name: "Apache",
			Headers: map[string]*regexp.Regexp{
				"Server": ci(`apache`),
			},
		},
		{
			Name: "Cloudflare",
			Headers: map[string]*regexp.Regexp{
				"Server":          ci(`cloudflare`),
				"Cf-Ray":          nil,
				"Cf-Cache-Status": nil,
			},
		},
		{
			Name: "Amazon CloudFront",
			Headers: map[string]*regexp.Regexp{
				"Via":            ci(`cloudfront`),
				"X-Amz-Cf-Id":    nil,
				"X-Amz-Cf-Pop":   nil,
			},
		},
		{
			Name: "Microsoft IIS",
			Headers: map[string]*regexp.Regexp{
				"Server": ci(`microsoft-iis`),
			},
		},
		{
			Name: "Caddy",
			Headers: map[string]*regexp.Regexp{
				"Server": ci(`caddy`),
			},
		},
		{
			Name: "Varnish",
			Headers: map[string]*regexp.Regexp{
				"Via":       ci(`varnish`),
				"X-Varnish": nil,
			},
		},
		{
			Name: "Envoy",
			Headers: map[string]*regexp.Regexp{
				"Server": ci(`envoy`),
			},
		},

		// Backend Platforms & Languages
		{
			Name: "PHP",
			Headers: map[string]*regexp.Regexp{
				"X-Powered-By": ci(`php`),
			},
			Cookies: []*regexp.Regexp{
				ci(`^PHPSESSID$`),
			},
		},
		{
			Name: "ASP.NET",
			Headers: map[string]*regexp.Regexp{
				"X-Powered-By":   ci(`asp\.net`),
				"X-AspNet-Version": nil,
			},
			Cookies: []*regexp.Regexp{
				ci(`^ASP\.NET_SessionId$`),
			},
		},
		{
			Name: "Node.js / Express",
			Headers: map[string]*regexp.Regexp{
				"X-Powered-By": ci(`express`),
			},
		},
		{
			Name: "Java / Servlet",
			Cookies: []*regexp.Regexp{
				ci(`^JSESSIONID$`),
			},
		},
		{
			Name: "Django",
			Cookies: []*regexp.Regexp{
				ci(`^csrftoken$`),
				ci(`^django`),
			},
		},
		{
			Name: "Laravel",
			Cookies: []*regexp.Regexp{
				ci(`^laravel_session$`),
			},
		},

		// CMS & Frameworks
		{
			Name: "WordPress",
			Cookies: []*regexp.Regexp{
				ci(`^wordpress_`),
				ci(`^wp-settings`),
			},
			Body: []*regexp.Regexp{
				ci(`wp-content/`),
				ci(`wp-includes/`),
			},
		},
		{
			Name: "Next.js",
			Headers: map[string]*regexp.Regexp{
				"X-Powered-By": ci(`Next\.js`),
			},
			Body: []*regexp.Regexp{
				ci(`/_next/static/`),
				ci(`__NEXT_DATA__`),
			},
		},
		{
			Name: "Nuxt.js",
			Headers: map[string]*regexp.Regexp{
				"X-Powered-By": ci(`Nuxt`),
			},
			Body: []*regexp.Regexp{
				ci(`/_nuxt/`),
				ci(`__NUXT__`),
			},
		},
		{
			Name: "Drupal",
			Headers: map[string]*regexp.Regexp{
				"X-Drupal-Cache": nil,
				"X-Generator":    ci(`drupal`),
			},
		},

		// Frontend Libraries
		{
			Name: "React",
			Body: []*regexp.Regexp{
				ci(`react-dom`),
				ci(`data-reactroot`),
			},
		},
		{
			Name: "Vue.js",
			Body: []*regexp.Regexp{
				ci(`data-v-[a-f0-9]+`),
				ci(`vue(\.runtime)?(\.min)?\.js`),
			},
		},
		{
			Name: "Bootstrap",
			Body: []*regexp.Regexp{
				ci(`bootstrap(?:\.min)?\.(?:css|js)`),
			},
		},
		{
			Name: "Tailwind CSS",
			Body: []*regexp.Regexp{
				ci(`tailwindcss`),
			},
		},
		{
			Name: "jQuery",
			Body: []*regexp.Regexp{
				ci(`jquery(?:\.min)?\.js`),
			},
		},
		{
			Name: "Google Analytics / Tag Manager",
			Body: []*regexp.Regexp{
				ci(`googletagmanager\.com/gtm\.js`),
				ci(`google-analytics\.com/analytics\.js`),
			},
		},
	}
}
