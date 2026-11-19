// Package orchestrator coordinates the complete asset discovery and audit pipeline.
package orchestrator

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/fatih/color"

	"github.com/13cast/assetwatch/pkg/dns_enum"
	"github.com/13cast/assetwatch/pkg/http_inspector"
	"github.com/13cast/assetwatch/pkg/reporter"
)

// Config carries all runtime parameters for an audit run.
type Config struct {
	Domain  string
	Workers int
	Timeout time.Duration
	JSONOut string
	CSVOut  string
	Verbose bool
}

// Run executes the complete audit pipeline:
// 1. Passive subdomain enumeration via crt.sh
// 2. Concurrent HTTP/HTTPS probing, security headers, and TLS validation
// 3. Technology fingerprinting
// 4. File export (JSON/CSV)
func Run(ctx context.Context, cfg Config) (*reporter.Report, error) {
	logf := buildLogger(cfg.Verbose, os.Stderr)

	// Step 1: Passive Subdomain Enumeration
	logf("[1/3] Starting passive subdomain discovery for %s via crt.sh...", color.CyanString(cfg.Domain))

	enumOpts := []dns_enum.Option{
		dns_enum.WithTimeout(cfg.Timeout * 4),
	}
	if cfg.Verbose {
		enumOpts = append(enumOpts, dns_enum.WithVerboseLogger(logf))
	}

	enumerator := dns_enum.New(enumOpts...)
	dnsResult, err := enumerator.Enumerate(ctx, cfg.Domain)
	if err != nil {
		return nil, fmt.Errorf("subdomain enumeration: %w", err)
	}

	// Always ensure the root domain is included in the inspection target list
	targets := dnsResult.Subdomains
	hasRoot := false
	for _, s := range targets {
		if s == cfg.Domain {
			hasRoot = true
			break
		}
	}
	if !hasRoot {
		targets = append([]string{cfg.Domain}, targets...)
	}

	logf("✓ Discovered %d target host(s) for %s", len(targets), cfg.Domain)

	// Step 2: Concurrent HTTP & Security Inspection
	logf("[2/3] Probing %d hosts with %d concurrent workers (timeout=%v)...", len(targets), cfg.Workers, cfg.Timeout)

	inspector := http_inspector.New(http_inspector.Config{
		Workers: cfg.Workers,
		Timeout: cfg.Timeout,
	})

	auditResults := inspector.InspectBatch(ctx, targets)

	// Step 3: Build Report & Exporters
	logf("[3/3] Generating audit report...")
	report := reporter.NewReport(cfg.Domain, auditResults)

	if cfg.JSONOut != "" {
		if err := report.WriteJSON(cfg.JSONOut); err != nil {
			return nil, fmt.Errorf("saving json report to %s: %w", cfg.JSONOut, err)
		}
		logf("✓ JSON report saved to %s", color.GreenString(cfg.JSONOut))
	}

	if cfg.CSVOut != "" {
		if err := report.WriteCSV(cfg.CSVOut); err != nil {
			return nil, fmt.Errorf("saving csv report to %s: %w", cfg.CSVOut, err)
		}
		logf("✓ CSV report saved to %s", color.GreenString(cfg.CSVOut))
	}

	return report, nil
}

func buildLogger(verbose bool, w io.Writer) func(string, ...any) {
	if !verbose {
		return func(string, ...any) {}
	}
	return func(format string, args ...any) {
		fmt.Fprintf(w, format+"\n", args...)
	}
}
