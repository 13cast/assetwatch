// Package reporter formats and exports AssetWatch audit results
// to terminal tables, JSON files, and CSV spreadsheets.
package reporter

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/fatih/color"

	"github.com/13cast/assetwatch/pkg/http_inspector"
)

// Report aggregates all audit results for a root domain.
type Report struct {
	Domain     string                          `json:"domain"`
	ScanTime   time.Time                       `json:"scan_time"`
	TotalHosts int                             `json:"total_hosts"`
	Reachable  int                             `json:"reachable"`
	Results    []http_inspector.HostAuditResult `json:"results"`
}

// NewReport constructs a Report from domain and inspection results.
func NewReport(domain string, results []http_inspector.HostAuditResult) *Report {
	sort.Slice(results, func(i, j int) bool {
		return results[i].Host < results[j].Host
	})

	reachableCount := 0
	for _, r := range results {
		if r.Reachable {
			reachableCount++
		}
	}

	return &Report{
		Domain:     domain,
		ScanTime:   time.Now().UTC(),
		TotalHosts: len(results),
		Reachable:  reachableCount,
		Results:    results,
	}
}

// PrintTable formats the results into an aligned, colorised terminal table.
func (r *Report) PrintTable(w io.Writer) {
	fmt.Fprintf(w, "\n%s %s (%d hosts discovered, %d active)\n\n",
		color.New(color.FgCyan, color.Bold).Sprint("AUDIT REPORT:"),
		r.Domain,
		r.TotalHosts,
		r.Reachable,
	)

	tw := tabwriter.NewWriter(w, 0, 0, 3, ' ', 0)
	defer tw.Flush()

	header := fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s\t%s",
		"HOST", "STATUS", "HSTS", "CSP", "XFO", "TLS DAYS", "TECH STACK",
	)
	fmt.Fprintln(tw, color.New(color.Bold).Sprint(header))

	divider := "----\t------\t----\t---\t---\t--------\t----------"
	fmt.Fprintln(tw, divider)

	for _, res := range r.Results {
		statusStr := formatStatus(res.StatusCode, res.Reachable)
		hstsStr := formatHeader(res.SecurityHeaders.HSTS, res.Reachable)
		cspStr := formatHeader(res.SecurityHeaders.CSP, res.Reachable)
		xfoStr := formatHeader(res.SecurityHeaders.XFrameOptions, res.Reachable)
		tlsStr := formatTLS(res.TLS, res.Reachable)
		techStr := strings.Join(res.Technologies, ", ")
		if techStr == "" {
			techStr = "-"
		}

		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			res.Host,
			statusStr,
			hstsStr,
			cspStr,
			xfoStr,
			tlsStr,
			techStr,
		)
	}

	fmt.Fprintln(tw)
}

// WriteJSON exports the report as indented JSON to the target file path.
func (r *Report) WriteJSON(filePath string) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling json: %w", err)
	}
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("writing json file: %w", err)
	}
	return nil
}

// WriteCSV exports the audit results to a CSV file.
func (r *Report) WriteCSV(filePath string) error {
	f, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("creating csv file: %w", err)
	}
	defer f.Close()

	writer := csv.NewWriter(f)
	defer writer.Flush()

	header := []string{
		"Host", "URL", "Reachable", "StatusCode",
		"HSTS", "CSP", "XFrameOptions", "XContentTypeOptions",
		"TLSValid", "TLSIssuer", "TLSDaysLeft", "TLSExpiry",
		"Technologies", "Error",
	}
	if err := writer.Write(header); err != nil {
		return err
	}

	for _, res := range r.Results {
		expiryStr := ""
		if !res.TLS.Expiry.IsZero() {
			expiryStr = res.TLS.Expiry.Format(time.RFC3339)
		}

		row := []string{
			res.Host,
			res.URL,
			strconv.FormatBool(res.Reachable),
			strconv.Itoa(res.StatusCode),
			strconv.FormatBool(res.SecurityHeaders.HSTS),
			strconv.FormatBool(res.SecurityHeaders.CSP),
			strconv.FormatBool(res.SecurityHeaders.XFrameOptions),
			strconv.FormatBool(res.SecurityHeaders.XContentTypeOptions),
			strconv.FormatBool(res.TLS.Valid),
			res.TLS.Issuer,
			strconv.Itoa(res.TLS.DaysLeft),
			expiryStr,
			strings.Join(res.Technologies, "; "),
			res.Error,
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return nil
}

func formatStatus(code int, reachable bool) string {
	if !reachable {
		return color.RedString("UNREACHABLE")
	}
	str := strconv.Itoa(code)
	switch {
	case code >= 200 && code < 300:
		return color.GreenString(str)
	case code >= 300 && code < 400:
		return color.CyanString(str)
	case code >= 400 && code < 500:
		return color.YellowString(str)
	default:
		return color.RedString(str)
	}
}

func formatHeader(b bool, reachable bool) string {
	if !reachable {
		return "-"
	}
	if b {
		return color.GreenString("✓")
	}
	return color.RedString("✗")
}

func formatTLS(t http_inspector.TLSSummary, reachable bool) string {
	if !reachable || t.Expiry.IsZero() {
		return "-"
	}
	if !t.Valid {
		return color.RedString("INVALID")
	}
	if t.DaysLeft <= 0 {
		return color.RedString("EXPIRED")
	}
	if t.DaysLeft < 14 {
		return color.YellowString("%dd", t.DaysLeft)
	}
	return color.GreenString("%dd", t.DaysLeft)
}
