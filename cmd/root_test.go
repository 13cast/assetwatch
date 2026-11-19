package cmd

import (
	"testing"
)

func TestRootCommand(t *testing.T) {
	if rootCmd == nil {
		t.Fatal("expected rootCmd to be initialized")
	}

	if auditCmd == nil {
		t.Fatal("expected auditCmd to be initialized")
	}

	flag := auditCmd.Flags().Lookup("domain")
	if flag == nil {
		t.Error("expected --domain flag to exist")
	}

	workersFlag := auditCmd.Flags().Lookup("workers")
	if workersFlag == nil || workersFlag.DefValue != "10" {
		t.Errorf("expected default workers 10, got %v", workersFlag)
	}
}

func TestSanitizeDomain(t *testing.T) {
	cases := []struct {
		input   string
		want    string
		wantErr bool
	}{
		{"example.com", "example.com", false},
		{"  EXAMPLE.COM  ", "example.com", false},
		{"https://example.com", "example.com", false},
		{"http://api.example.com:8080/v1/test?q=1#frag", "api.example.com", false},
		{"sub.domain.co.uk.", "sub.domain.co.uk", false},
		{"", "", true},
		{"nodotdomain", "", true},
		{"has space.com", "", true},
	}

	for _, tc := range cases {
		got, err := sanitizeDomain(tc.input)
		if (err != nil) != tc.wantErr {
			t.Errorf("sanitizeDomain(%q) unexpected err status: %v", tc.input, err)
			continue
		}
		if got != tc.want {
			t.Errorf("sanitizeDomain(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}
