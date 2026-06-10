package secrets

import (
	"strings"
	"testing"
)

func TestScanFindsKnownSecrets(t *testing.T) {
	body := []byte(`
		const aws = "` + "AKIA" + `IOSFODNN7EXAMPLE";
		const gh = "` + "ghp_" + `0123456789abcdefghijklmnopqrstuvwxyz";
		const stripe = "` + "sk_live_" + `0123456789abcdefghijABCD";
		var notASecret = "just some text here";
	`)
	matches := Scan(body)

	names := map[string]bool{}
	for _, m := range matches {
		names[m.Pattern.Name] = true
		if m.Value == m.Redacted {
			t.Errorf("secret %q was not redacted", m.Pattern.Name)
		}
	}
	if !names["AWS access key ID"] {
		t.Errorf("missing AWS key; found %v", names)
	}
	if !names["GitHub token"] {
		t.Errorf("missing GitHub token; found %v", names)
	}
	if !names["Stripe secret key"] {
		t.Errorf("missing Stripe key; found %v", names)
	}
}

func TestScanRedacts(t *testing.T) {
	body := []byte(`key="` + "AKIA" + `IOSFODNN7EXAMPLE"`)
	matches := Scan(body)
	if len(matches) == 0 {
		t.Fatal("expected a match")
	}
	for _, m := range matches {
		if strings.Contains(m.Redacted, "IOSFODNN7") {
			t.Error("redaction leaked the secret body")
		}
		if !strings.Contains(m.Redacted, "*") {
			t.Error("expected redaction asterisks")
		}
		if m.Pattern.Validation == "" {
			t.Error("pattern should carry a validation hint")
		}
	}
}

func TestScanClean(t *testing.T) {
	if m := Scan([]byte("nothing secret here, just normal text 12345")); len(m) != 0 {
		t.Errorf("clean body produced %d false positives", len(m))
	}
}

func TestPatternsCompile(t *testing.T) {
	if len(Patterns) < 25 {
		t.Errorf("expected a substantial pattern set, got %d", len(Patterns))
	}
}