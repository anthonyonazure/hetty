package msf

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// mockMSF decodes the incoming MessagePack RPC and dispatches a canned reply.
func mockMSF(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		req, err := mpDecode(body)
		if err != nil {
			t.Errorf("server decode: %v", err)
		}
		arr, _ := req.([]interface{})
		if len(arr) == 0 {
			t.Errorf("empty rpc array")
			return
		}
		method, _ := arr[0].(string)

		var reply interface{}
		switch method {
		case "auth.login":
			reply = map[string]interface{}{"result": "success", "token": "TOK-123"}
		case "core.version":
			reply = map[string]interface{}{"version": "6.3.0", "ruby": "3.0"}
		case "module.search":
			reply = []interface{}{
				map[string]interface{}{"fullname": "exploit/unix/ftp/vsftpd_234_backdoor"},
			}
		case "module.execute":
			reply = map[string]interface{}{"job_id": int64(7), "uuid": "abcd"}
		case "boom":
			reply = map[string]interface{}{"error": true, "error_message": "kaboom"}
		default:
			reply = map[string]interface{}{"ok": true}
		}
		w.Header().Set("Content-Type", "binary/message-pack")
		w.Write(mpEncode(reply))
	}))
}

func TestMSFLoginAndCalls(t *testing.T) {
	srv := mockMSF(t)
	defer srv.Close()

	c := New(Config{URL: srv.URL, User: "msf", Pass: "pw"})
	if !c.Enabled() {
		t.Fatal("client should be enabled")
	}

	if err := c.Login(context.Background()); err != nil {
		t.Fatalf("login: %v", err)
	}
	if c.token != "TOK-123" {
		t.Fatalf("token = %q, want TOK-123", c.token)
	}

	ver, err := c.Version(context.Background())
	if err != nil {
		t.Fatalf("version: %v", err)
	}
	if ver["version"] != "6.3.0" {
		t.Errorf("version = %v", ver["version"])
	}

	mods, err := c.SearchModules(context.Background(), "vsftpd")
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(mods) != 1 || mods[0] != "exploit/unix/ftp/vsftpd_234_backdoor" {
		t.Errorf("modules = %v", mods)
	}

	res, err := c.Execute(context.Background(), "exploit/unix/ftp/vsftpd_234_backdoor",
		map[string]interface{}{"RHOSTS": "10.0.0.5"})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if res["job_id"] != int64(7) {
		t.Errorf("job_id = %v", res["job_id"])
	}
}

func TestMSFErrorResponse(t *testing.T) {
	srv := mockMSF(t)
	defer srv.Close()
	c := New(Config{URL: srv.URL, User: "msf", Pass: "pw"})
	if _, err := c.call(context.Background(), "boom"); err == nil {
		t.Fatal("expected error from error response")
	}
}

func TestMSFDisabled(t *testing.T) {
	c := New(Config{})
	if c.Enabled() {
		t.Fatal("no URL should be disabled")
	}
	if err := c.Login(context.Background()); err == nil {
		t.Fatal("disabled login should error")
	}
}

func TestSplitModule(t *testing.T) {
	tp, ref := splitModule("exploit/unix/ftp/vsftpd_234_backdoor")
	if tp != "exploit" || ref != "unix/ftp/vsftpd_234_backdoor" {
		t.Errorf("split = %q/%q", tp, ref)
	}
	tp, ref = splitModule("auxiliary/scanner/http/title")
	if tp != "auxiliary" || ref != "scanner/http/title" {
		t.Errorf("split = %q/%q", tp, ref)
	}
}
