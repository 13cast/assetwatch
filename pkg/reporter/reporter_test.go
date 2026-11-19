package reporter_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/13cast/assetwatch/pkg/http_inspector"
	"github.com/13cast/assetwatch/pkg/reporter"
)

func TestReporter_Outputs(t *testing.T) {
	results := []http_inspector.HostAuditResult{
		{
			Host:       "app.example.com",
			URL:        "https://app.example.com",
			Reachable:  true,
			StatusCode: 200,
			SecurityHeaders: http_inspector.SecurityHeaders{
				HSTS:          true,
				CSP:           true,
				XFrameOptions: true,
			},
			TLS: http_inspector.TLSSummary{
				Valid:    true,
				Issuer:   "Let's Encrypt",
				DaysLeft: 65,
				Expiry:   time.Now().Add(65 * 24 * time.Hour),
			},
			Technologies: []string{"Nginx", "React"},
		},
		{
			Host:       "dead.example.com",
			URL:        "https://dead.example.com",
			Reachable:  false,
			StatusCode: 0,
			Error:      "dial tcp: lookup dead.example.com: no such host",
		},
	}

	rep := reporter.NewReport("example.com", results)

	// Test Table Output
	var buf bytes.Buffer
	rep.PrintTable(&buf)
	tableStr := buf.String()
	if len(tableStr) == 0 {
		t.Fatalf("expected non-empty table output")
	}

	// Test JSON Output
	tmpDir := t.TempDir()
	jsonPath := filepath.Join(tmpDir, "report.json")
	if err := rep.WriteJSON(jsonPath); err != nil {
		t.Fatalf("failed to write json: %v", err)
	}
	jsonData, err := os.ReadFile(jsonPath)
	if err != nil || len(jsonData) == 0 {
		t.Fatalf("failed reading written json: %v", err)
	}

	// Test CSV Output
	csvPath := filepath.Join(tmpDir, "report.csv")
	if err := rep.WriteCSV(csvPath); err != nil {
		t.Fatalf("failed to write csv: %v", err)
	}
	csvData, err := os.ReadFile(csvPath)
	if err != nil || len(csvData) == 0 {
		t.Fatalf("failed reading written csv: %v", err)
	}
}
