package scan_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/dstotijn/hetty/pkg/scan"
)

func findPoint(points []scan.InsertionPoint, typ scan.InsertionPointType, name string) (scan.InsertionPoint, bool) {
	for _, p := range points {
		if p.Type == typ && p.Name == name {
			return p, true
		}
	}
	return scan.InsertionPoint{}, false
}

func TestBuildInsertionPoints(t *testing.T) {
	u, _ := url.Parse("https://example.com/search?q=hello&page=2")
	h := http.Header{}
	h.Set("Content-Type", "application/x-www-form-urlencoded")
	h.Set("Cookie", "session=abc; theme=dark")

	rt := scan.NewRequestTemplate(http.MethodPost, u, "HTTP/1.1", h, []byte("user=bob&team=red"))

	opts := scan.DefaultOptions()
	points := scan.BuildInsertionPoints(rt, opts)

	for _, want := range []struct {
		typ  scan.InsertionPointType
		name string
	}{
		{scan.InsertionQuery, "q"},
		{scan.InsertionQuery, "page"},
		{scan.InsertionForm, "user"},
		{scan.InsertionForm, "team"},
		{scan.InsertionCookie, "session"},
		{scan.InsertionCookie, "theme"},
	} {
		if _, ok := findPoint(points, want.typ, want.name); !ok {
			t.Errorf("missing insertion point %s:%s", want.typ, want.name)
		}
	}
}

func TestBuildInsertionPointsJSON(t *testing.T) {
	u, _ := url.Parse("https://example.com/api")
	h := http.Header{}
	h.Set("Content-Type", "application/json")

	rt := scan.NewRequestTemplate(http.MethodPost, u, "HTTP/1.1", h,
		[]byte(`{"name":"bob","nested":{"team":"red"},"items":["a","b"]}`))

	points := scan.BuildInsertionPoints(rt, scan.DefaultOptions())

	for _, name := range []string{"name", "nested.team", "items[0]", "items[1]"} {
		if _, ok := findPoint(points, scan.InsertionJSON, name); !ok {
			t.Errorf("missing JSON insertion point %q in %v", name, points)
		}
	}
}

func TestApplyPayloadQuery(t *testing.T) {
	u, _ := url.Parse("https://example.com/s?q=hello&page=2")
	rt := scan.NewRequestTemplate(http.MethodGet, u, "HTTP/1.1", http.Header{}, nil)

	point := scan.InsertionPoint{Type: scan.InsertionQuery, Name: "q", Value: "hello"}
	out := scan.ApplyPayload(rt, point, "INJ", false)

	if got := out.URL.Query().Get("q"); got != "INJ" {
		t.Errorf("q = %q, want INJ", got)
	}
	if got := out.URL.Query().Get("page"); got != "2" {
		t.Errorf("page = %q, want 2 (other params must be preserved)", got)
	}
	// Original must be untouched.
	if got := rt.URL.Query().Get("q"); got != "hello" {
		t.Errorf("original mutated: q = %q", got)
	}
}

func TestApplyPayloadAppend(t *testing.T) {
	u, _ := url.Parse("https://example.com/s?id=42")
	rt := scan.NewRequestTemplate(http.MethodGet, u, "HTTP/1.1", http.Header{}, nil)

	point := scan.InsertionPoint{Type: scan.InsertionQuery, Name: "id", Value: "42"}
	out := scan.ApplyPayload(rt, point, "'", true)

	if got := out.URL.Query().Get("id"); got != "42'" {
		t.Errorf("id = %q, want 42'", got)
	}
}

func TestApplyPayloadJSON(t *testing.T) {
	u, _ := url.Parse("https://example.com/api")
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	rt := scan.NewRequestTemplate(http.MethodPost, u, "HTTP/1.1", h, []byte(`{"nested":{"team":"blue"}}`))

	point := scan.InsertionPoint{Type: scan.InsertionJSON, Name: "nested.team", Value: "blue"}
	out := scan.ApplyPayload(rt, point, "red", false)

	if !strings.Contains(string(out.Body), `"red"`) {
		t.Errorf("JSON body = %s, want nested.team replaced with red", out.Body)
	}
}

func TestApplyPayloadCookie(t *testing.T) {
	u, _ := url.Parse("https://example.com/")
	h := http.Header{}
	h.Set("Cookie", "session=abc; theme=dark")
	rt := scan.NewRequestTemplate(http.MethodGet, u, "HTTP/1.1", h, nil)

	point := scan.InsertionPoint{Type: scan.InsertionCookie, Name: "session", Value: "abc"}
	out := scan.ApplyPayload(rt, point, "INJ", false)

	cookie := out.Header.Get("Cookie")
	if !strings.Contains(cookie, "session=INJ") {
		t.Errorf("cookie = %q, want session=INJ", cookie)
	}
	if !strings.Contains(cookie, "theme=dark") {
		t.Errorf("cookie = %q, want theme=dark preserved", cookie)
	}
}
