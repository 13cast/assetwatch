// Package cmd wires up the AssetWatch CLI using cobra.
// All subcommands are registered here and delegate to the orchestrator.
package cmd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/13cast/assetwatch/internal/orchestrator"
)

// Global flags shared across commands.
var (
	flagDomain  string
	flagWorkers int
	flagTimeout time.Duration
	flagJSON    string
	flagCSV     string
	flagVerbose bool
)

// rootCmd is the base command. Without a subcommand it prints help and banner.
var rootCmd = &cobra.Command{
	Use:   "assetwatch",
	Short: "AssetWatch — web asset inventory and domain configuration monitor",
	Long: color.New(color.FgCyan, color.Bold).Sprint(`
 █████╗ ███████╗███████╗███████╗████████╗██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗
██╔══██╗██╔════╝██╔════╝██╔════╝╚══██╔══╝██║    ██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║
███████║███████╗███████╗█████╗     ██║   ██║ █╗ ██║███████║   ██║   ██║     ███████║
██╔══██║╚════██║╚════██║██╔══╝     ██║   ██║███╗██║██╔══██║   ██║   ██║     ██╔══██║
██║  ██║███████║███████║███████╗   ██║   ╚███╔███╔╝██║  ██║   ██║   ╚██████╗██║  ██║
╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝   ╚═╝    ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝
`) + `
Web Asset Inventory & Domain Configuration Monitor
`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

// auditCmd runs the full asset audit pipeline for a given domain.
var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Run a full audit: subdomain discovery + HTTP inspection + reporting",
	Example: `  assetwatch audit -d example.com
  assetwatch audit -d example.com --workers 20 --timeout 10s
  assetwatch audit -d example.com --json report.json --csv report.csv`,
	RunE: runAudit,
}

func init() {
	auditCmd.Flags().StringVarP(&flagDomain, "domain", "d", "", "Target root domain to audit (required, e.g. example.com)")
	auditCmd.Flags().IntVar(&flagWorkers, "workers", 10, "Number of parallel HTTP workers")
	auditCmd.Flags().DurationVar(&flagTimeout, "timeout", 8*time.Second, "HTTP request timeout per host")
	auditCmd.Flags().StringVar(&flagJSON, "json", "", "Path to save the JSON report (e.g. report.json)")
	auditCmd.Flags().StringVar(&flagCSV, "csv", "", "Path to save the CSV report (e.g. report.csv)")
	auditCmd.Flags().BoolVarP(&flagVerbose, "verbose", "v", false, "Print verbose progress to stderr")

	if err := auditCmd.MarkFlagRequired("domain"); err != nil {
		panic(err)
	}

	rootCmd.AddCommand(auditCmd)
}

// Execute is the default entry point.
func Execute() error {
	return ExecuteContext(context.Background())
}

// ExecuteContext executes the command tree with cancellation context.
func ExecuteContext(ctx context.Context) error {
	return rootCmd.ExecuteContext(ctx)
}

// runAudit is the cobra RunE handler for the audit subcommand.
func runAudit(cmd *cobra.Command, _ []string) error {
	if flagWorkers < 1 {
		return errors.New("--workers must be >= 1")
	}
	if flagTimeout < time.Second {
		return errors.New("--timeout must be >= 1s")
	}

	domain, err := sanitizeDomain(flagDomain)
	if err != nil {
		return err
	}

	cfg := orchestrator.Config{
		Domain:  domain,
		Workers: flagWorkers,
		Timeout: flagTimeout,
		JSONOut: flagJSON,
		CSVOut:  flagCSV,
		Verbose: flagVerbose,
	}

	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	report, err := orchestrator.Run(ctx, cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, color.RedString("✗ Audit failed: %v", err))
		return err
	}

	report.PrintTable(os.Stdout)
	return nil
}

// sanitizeDomain cleans and validates the user-supplied domain string.
// It strips protocols, paths, ports and whitespace.
func sanitizeDomain(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("domain name cannot be empty")
	}

	// Strip protocol if user pasted a full URL
	lower := strings.ToLower(raw)
	if strings.HasPrefix(lower, "http://") {
		raw = raw[7:]
	} else if strings.HasPrefix(lower, "https://") {
		raw = raw[8:]
	}

	// Strip trailing path/query/fragment
	if idx := strings.IndexAny(raw, "/?#"); idx != -1 {
		raw = raw[:idx]
	}

	// Strip port if provided (e.g. example.com:443)
	if host, _, err := net.SplitHostPort(raw); err == nil {
		raw = host
	}

	raw = strings.Trim(strings.ToLower(raw), ".")
	if strings.ContainsAny(raw, " \t\r\n") || !strings.Contains(raw, ".") {
		return "", fmt.Errorf("invalid domain %q (expected format like example.com)", raw)
	}

	return raw, nil
}
