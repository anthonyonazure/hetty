package template

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

const gitConfigTemplate = `
id: exposed-git-config
info:
  name: Exposed .git/config
  severity: medium
  description: A .git/config file is publicly accessible.
requests:
  - method: GET
    path:
      - "{{BaseURL}}/.git/config"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - "[core]"
          - "repositoryformatversion"
        condition: and
`

func TestParseAndRunMatch(t *testing.T) {
	tmpl, err := Parse([]byte(gitConfigTemplate))
	if err != nil {
		t.Fatal(err)
	}
	if tmpl.ID != "exposed-git-config" || tmpl.Info.Severity != "medium" {
		t.Errorf("template parsed wrong: %+v", tmpl.Info)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.git/config" {
			_, _ = w.Write([]byte("[core]\n\trepositoryformatversion = 0\n"))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	results, err := New().Run(context.Background(), srv.URL, []*Template{tmpl}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 match, got %d", len(results))
	}
	if results[0].TemplateID != "exposed-git-config" {
		t.Errorf("wrong match: %+v", results[0])
	}
}

func TestRunNoMatch(t *testing.T) {
	tmpl, _ := Parse([]byte(gitConfigTemplate))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r) // no .git/config
	}))
	defer srv.Close()

	results, err := New().Run(context.Background(), srv.URL, []*Template{tmpl}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Errorf("expected no matches, got %d", len(results))
	}
}

func TestMatchersConditionOr(t *testing.T) {
	tmpl, _ := Parse([]byte(`
id: or-test
info:
  name: Or test
  severity: info
http:
  - method: GET
    path: ["{{BaseURL}}/"]
    matchers-condition: or
    matchers:
      - type: word
        words: ["nonexistent-marker"]
      - type: status
        status: [200]
`))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello"))
	}))
	defer srv.Close()

	results, _ := New().Run(context.Background(), srv.URL, []*Template{tmpl}, Options{})
	if len(results) != 1 {
		t.Errorf("OR condition should match on status 200; got %d results", len(results))
	}
}

func TestRegexMatcherAndNegative(t *testing.T) {
	tmpl, _ := Parse([]byte(`
id: regex-test
info:
  name: Regex test
  severity: high
requests:
  - method: GET
    path: ["{{BaseURL}}/etc"]
    matchers:
      - type: regex
        part: body
        regex:
          - "root:.*:0:0:"
`))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("root:x:0:0:root:/root:/bin/bash\n"))
	}))
	defer srv.Close()

	results, _ := New().Run(context.Background(), srv.URL, []*Template{tmpl}, Options{})
	if len(results) != 1 {
		t.Errorf("regex matcher should match passwd; got %d", len(results))
	}
}

func TestParseErrors(t *testing.T) {
	if _, err := Parse([]byte(`info:\n  name: x`)); err == nil {
		t.Error("expected error for template without id")
	}
	if _, err := Parse([]byte(`id: x`)); err == nil {
		t.Error("expected error for template without requests")
	}
}
