// Package dns_enum performs passive subdomain discovery using the
// Certificate Transparency log aggregator at crt.sh.
//
// It queries the public JSON API, deduplicates entries, and returns
// a canonicalised slice of unique subdomain names for the given root domain.
package dns_enum

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	crtShBaseURL   = "https://crt.sh"
	apiQueryFmt    = "%s/?q=%%25.%s&output=json" // %25 → URL-encoded '%'
	apiQueryAlt    = "%s/?q=%s&output=json"      // query root domain directly
	defaultTimeout = 30 * time.Second
	maxRetries     = 3
)

// crtShEntry represents a single record returned by the crt.sh JSON API.
type crtShEntry struct {
	NameValue  string `json:"name_value"`
	IssuerName string `json:"issuer_name"`
}

// Result holds the outcome of a DNS enumeration run.
type Result struct {
	RootDomain string
	Subdomains []string
}

// Enumerator carries the HTTP client and options used for all crt.sh requests.
type Enumerator struct {
	client  *http.Client
	verbose bool
	logf    func(format string, args ...any)
}

// Option is a functional option for configuring an Enumerator.
type Option func(*Enumerator)

// WithTimeout overrides the default HTTP client timeout.
func WithTimeout(d time.Duration) Option {
	return func(e *Enumerator) {
		e.client.Timeout = d
	}
}

// WithVerboseLogger attaches a log function that is called for progress messages.
func WithVerboseLogger(logf func(format string, args ...any)) Option {
	return func(e *Enumerator) {
		e.verbose = true
		e.logf = logf
	}
}

// New creates an Enumerator with sensible defaults and applies any provided
// Option functions.
func New(opts ...Option) *Enumerator {
	e := &Enumerator{
		client: &http.Client{
			Timeout: defaultTimeout,
		},
		logf: func(string, ...any) {},
	}
	for _, o := range opts {
		o(e)
	}
	return e
}

// Enumerate queries crt.sh for all certificates issued for subdomains of
// rootDomain, deduplicates and normalises the results, then returns a Result.
func (e *Enumerator) Enumerate(ctx context.Context, rootDomain string) (*Result, error) {
	rootDomain = canonicaliseDomain(rootDomain)
	if rootDomain == "" {
		return nil, fmt.Errorf("dns_enum: rootDomain must not be empty")
	}

	e.logf("[dns_enum] querying crt.sh for %s (with retries)", rootDomain)

	entries, err := e.fetchWithRetry(ctx, rootDomain)
	if err != nil {
		e.logf("[dns_enum] warning: crt.sh unavailable (%v), falling back to root domain", err)
		return &Result{
			RootDomain: rootDomain,
			Subdomains: []string{rootDomain},
		}, nil
	}

	e.logf("[dns_enum] received %d raw certificate entries", len(entries))

	subdomains := deduplicateAndFilter(entries, rootDomain)
	if len(subdomains) == 0 {
		subdomains = []string{rootDomain}
	}

	e.logf("[dns_enum] found %d unique subdomains after deduplication", len(subdomains))

	return &Result{
		RootDomain: rootDomain,
		Subdomains: subdomains,
	}, nil
}

// fetchWithRetry tries wildcard query first, then direct root query with backoff.
func (e *Enumerator) fetchWithRetry(ctx context.Context, domain string) ([]crtShEntry, error) {
	queries := []string{
		fmt.Sprintf(apiQueryFmt, crtShBaseURL, url.PathEscape(domain)),
		fmt.Sprintf(apiQueryAlt, crtShBaseURL, url.PathEscape(domain)),
	}

	var lastErr error
	for _, rawURL := range queries {
		for attempt := 1; attempt <= maxRetries; attempt++ {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}

			entries, err := e.fetchCrtShURL(ctx, rawURL)
			if err == nil {
				return entries, nil
			}

			lastErr = err
			e.logf("[dns_enum] attempt %d/%d for query %s failed: %v", attempt, maxRetries, rawURL, err)

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt) * time.Second):
			}
		}
	}

	return nil, lastErr
}

func (e *Enumerator) fetchCrtShURL(ctx context.Context, rawURL string) ([]crtShEntry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; AssetWatch/1.0; +https://github.com/13cast/assetwatch)")

	resp, err := e.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP GET: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP status %d", resp.StatusCode)
	}

	var entries []crtShEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("decoding crt.sh JSON: %w", err)
	}

	return entries, nil
}

// deduplicateAndFilter expands multi-value NameValue fields, normalises each
// name, discards wildcard prefixes and unrelated domains, and returns a
// sorted, deduplicated slice.
func deduplicateAndFilter(entries []crtShEntry, rootDomain string) []string {
	seen := make(map[string]struct{}, len(entries)*2)

	for _, entry := range entries {
		for _, raw := range strings.Split(entry.NameValue, "\n") {
			name := canonicaliseDomain(raw)
			if name == "" {
				continue
			}
			name = strings.TrimPrefix(name, "*.")

			if name != rootDomain && !strings.HasSuffix(name, "."+rootDomain) {
				continue
			}

			seen[name] = struct{}{}
		}
	}

	result := make([]string, 0, len(seen))
	for name := range seen {
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}

func canonicaliseDomain(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	d = strings.TrimSuffix(d, ".")
	return d
}
