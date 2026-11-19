// Package http_inspector performs concurrent probing of HTTP/HTTPS endpoints,
// evaluating reachability, response codes, security headers, and TLS certificates.
package http_inspector

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/13cast/assetwatch/pkg/tech_detector"
)

// SecurityHeaders represents the presence and status of standard security headers.
type SecurityHeaders struct {
	HSTS                 bool   `json:"hsts"`
	HSTSValue            string `json:"hsts_value,omitempty"`
	CSP                  bool   `json:"csp"`
	CSPValue             string `json:"csp_value,omitempty"`
	XFrameOptions        bool   `json:"x_frame_options"`
	XFrameOptionsValue   string `json:"x_frame_options_value,omitempty"`
	XContentTypeOptions  bool   `json:"x_content_type_options"`
}

// TLSSummary captures essential TLS certificate status.
type TLSSummary struct {
	Valid       bool      `json:"valid"`
	Issuer      string    `json:"issuer,omitempty"`
	Subject     string    `json:"subject,omitempty"`
	Expiry      time.Time `json:"expiry,omitempty"`
	DaysLeft    int       `json:"days_left"`
	ErrorString string    `json:"error,omitempty"`
}

// HostAuditResult contains the full inspection data for a single domain/subdomain.
type HostAuditResult struct {
	Host            string          `json:"host"`
	URL             string          `json:"url"`
	Reachable       bool            `json:"reachable"`
	StatusCode      int             `json:"status_code"`
	SecurityHeaders SecurityHeaders `json:"security_headers"`
	TLS             TLSSummary      `json:"tls"`
	Technologies    []string        `json:"technologies"`
	Error           string          `json:"error,omitempty"`
}

// Config controls inspector behavior and concurrency.
type Config struct {
	Workers int
	Timeout time.Duration
}

// Inspector orchestrates parallel probes against target hosts.
type Inspector struct {
	cfg      Config
	detector *tech_detector.Detector
}

// New creates a new Inspector with the given configuration.
func New(cfg Config) *Inspector {
	if cfg.Workers < 1 {
		cfg.Workers = 10
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 8 * time.Second
	}
	return &Inspector{
		cfg:      cfg,
		detector: tech_detector.New(),
	}
}

// InspectBatch inspects a slice of hosts concurrently using a worker pool.
func (ins *Inspector) InspectBatch(ctx context.Context, hosts []string) []HostAuditResult {
	if len(hosts) == 0 {
		return nil
	}

	tasks := make(chan string, len(hosts))
	resultsChan := make(chan HostAuditResult, len(hosts))

	for _, h := range hosts {
		tasks <- h
	}
	close(tasks)

	numWorkers := ins.cfg.Workers
	if numWorkers > len(hosts) {
		numWorkers = len(hosts)
	}

	var wg sync.WaitGroup
	wg.Add(numWorkers)

	for i := 0; i < numWorkers; i++ {
		go func() {
			defer wg.Done()
			for host := range tasks {
				select {
				case <-ctx.Done():
					resultsChan <- HostAuditResult{
						Host:  host,
						Error: ctx.Err().Error(),
					}
				default:
					res := ins.InspectHost(ctx, host)
					resultsChan <- res
				}
			}
		}()
	}

	wg.Wait()
	close(resultsChan)

	results := make([]HostAuditResult, 0, len(hosts))
	for r := range resultsChan {
		results = append(results, r)
	}

	return results
}

// InspectHost checks a single hostname, attempting HTTPS first, falling back to HTTP.
func (ins *Inspector) InspectHost(ctx context.Context, host string) HostAuditResult {
	res := HostAuditResult{
		Host: host,
	}

	// Try HTTPS first
	res = ins.probeScheme(ctx, host, "https")
	if res.Reachable {
		return res
	}

	// Fallback to HTTP
	httpRes := ins.probeScheme(ctx, host, "http")
	if httpRes.Reachable {
		return httpRes
	}

	// If both failed, keep error details
	return res
}

func (ins *Inspector) probeScheme(ctx context.Context, host, scheme string) HostAuditResult {
	targetURL := scheme + "://" + host
	res := HostAuditResult{
		Host: host,
		URL:  targetURL,
	}

	client := &http.Client{
		Timeout: ins.cfg.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false, // Verify certificates properly
			},
			DisableKeepAlives: true,
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	req.Header.Set("User-Agent", "AssetWatch/1.0 (+https://github.com/13cast/assetwatch)")
	req.Header.Set("Accept", "*/*")

	resp, err := client.Do(req)
	if err != nil {
		// If HTTPS TLS failed due to certificate errors, record TLS issue and retry with skip verify to get status
		if scheme == "https" && strings.Contains(err.Error(), "certificate") {
			res.TLS.Valid = false
			res.TLS.ErrorString = err.Error()

			// Retry with InsecureSkipVerify to check if server is reachable
			insecureClient := &http.Client{
				Timeout: ins.cfg.Timeout,
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
					},
					DisableKeepAlives: true,
				},
			}
			respInsecure, errInsecure := insecureClient.Do(req)
			if errInsecure == nil {
				defer respInsecure.Body.Close()
				populateResponseData(&res, respInsecure, ins.detector)
				return res
			}
		}
		res.Error = err.Error()
		return res
	}
	defer resp.Body.Close()

	populateResponseData(&res, resp, ins.detector)
	return res
}

func populateResponseData(res *HostAuditResult, resp *http.Response, detector *tech_detector.Detector) {
	res.Reachable = true
	res.StatusCode = resp.StatusCode

	// Extract TLS details if HTTPS connection
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		cert := resp.TLS.PeerCertificates[0]
		now := time.Now()
		daysLeft := int(cert.NotAfter.Sub(now).Hours() / 24)

		res.TLS.Valid = (res.TLS.ErrorString == "") && now.After(cert.NotBefore) && now.Before(cert.NotAfter)
		res.TLS.Issuer = cert.Issuer.CommonName
		if res.TLS.Issuer == "" && len(cert.Issuer.Organization) > 0 {
			res.TLS.Issuer = cert.Issuer.Organization[0]
		}
		res.TLS.Subject = cert.Subject.CommonName
		res.TLS.Expiry = cert.NotAfter
		res.TLS.DaysLeft = daysLeft
	}

	// Security Headers Audit
	hsts := resp.Header.Get("Strict-Transport-Security")
	if hsts != "" {
		res.SecurityHeaders.HSTS = true
		res.SecurityHeaders.HSTSValue = hsts
	}

	csp := resp.Header.Get("Content-Security-Policy")
	if csp != "" {
		res.SecurityHeaders.CSP = true
		res.SecurityHeaders.CSPValue = csp
	}

	xfo := resp.Header.Get("X-Frame-Options")
	if xfo != "" {
		res.SecurityHeaders.XFrameOptions = true
		res.SecurityHeaders.XFrameOptionsValue = xfo
	}

	xcto := resp.Header.Get("X-Content-Type-Options")
	if strings.EqualFold(xcto, "nosniff") {
		res.SecurityHeaders.XContentTypeOptions = true
	}

	// Read small snippet of body for fingerprinting (up to 32KB)
	lr := io.LimitReader(resp.Body, 32*1024)
	bodySnippet, _ := io.ReadAll(lr)

	// Fingerprint technologies
	res.Technologies = detector.Detect(resp.Header, resp.Cookies(), bodySnippet)
}
