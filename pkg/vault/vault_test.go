package vault

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLocalBackend(t *testing.T) {
	dir := t.TempDir()
	loc, err := Save(context.Background(), Config{Kind: "local", Dir: dir}, "reports/2026/scan.json", []byte(`{"ok":true}`), "application/json")
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "reports", "2026", "scan.json"))
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(data) != `{"ok":true}` {
		t.Errorf("content mismatch: %s", data)
	}
	if !strings.Contains(loc, "scan.json") {
		t.Errorf("location = %q", loc)
	}
}

func TestS3SigV4(t *testing.T) {
	var gotAuth, gotDate, gotSha string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotDate = r.Header.Get("X-Amz-Date")
		gotSha = r.Header.Get("X-Amz-Content-Sha256")
		if r.Method != http.MethodPut || !strings.HasSuffix(r.URL.Path, "/mybucket/k/obj.txt") {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	_, err := Save(context.Background(), Config{
		Kind: "s3", Endpoint: srv.URL, Region: "us-east-1", Bucket: "mybucket",
		AccessKey: "AKIA", SecretKey: "secret",
	}, "k/obj.txt", []byte("hello"), "text/plain")
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if !strings.HasPrefix(gotAuth, "AWS4-HMAC-SHA256 Credential=AKIA/") {
		t.Errorf("bad auth header: %q", gotAuth)
	}
	if gotDate == "" || gotSha == "" {
		t.Errorf("missing amz headers")
	}
}

func TestAzureSharedKey(t *testing.T) {
	var gotAuth, gotBlobType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotBlobType = r.Header.Get("x-ms-blob-type")
		w.WriteHeader(201)
	}))
	defer srv.Close()

	_, err := Save(context.Background(), Config{
		Kind: "azure", Endpoint: srv.URL, Account: "acct", Container: "cont",
		AccountKey: "c2VjcmV0a2V5", // base64("secretkey")
	}, "report.json", []byte("{}"), "application/json")
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if !strings.HasPrefix(gotAuth, "SharedKey acct:") {
		t.Errorf("bad auth header: %q", gotAuth)
	}
	if gotBlobType != "BlockBlob" {
		t.Errorf("missing blob type header")
	}
}

func TestGDriveBearer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok123" {
			t.Errorf("bad bearer: %q", r.Header.Get("Authorization"))
		}
		if !strings.Contains(r.Header.Get("Content-Type"), "multipart/related") {
			t.Errorf("expected multipart/related, got %q", r.Header.Get("Content-Type"))
		}
		fmt.Fprint(w, `{"id":"file-abc","name":"report.json"}`)
	}))
	defer srv.Close()

	loc, err := Save(context.Background(), Config{Kind: "gdrive", Token: "tok123", Endpoint: srv.URL}, "report.json", []byte("{}"), "application/json")
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if !strings.Contains(loc, "file-abc") {
		t.Errorf("location = %q", loc)
	}
}

func TestBoxBearer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer boxtok" {
			t.Errorf("bad bearer")
		}
		fmt.Fprint(w, `{"entries":[{"id":"99","name":"report.json"}]}`)
	}))
	defer srv.Close()

	loc, err := Save(context.Background(), Config{Kind: "box", Token: "boxtok", Endpoint: srv.URL}, "report.json", []byte("{}"), "application/json")
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if !strings.Contains(loc, "99") {
		t.Errorf("location = %q", loc)
	}
}

func TestGDriveOAuthRefresh(t *testing.T) {
	refreshed := false
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.FormValue("grant_type") == "refresh_token" && r.FormValue("refresh_token") == "rtok" {
			refreshed = true
			fmt.Fprint(w, `{"access_token":"fresh-token","expires_in":3600}`)
			return
		}
		w.WriteHeader(400)
	}))
	defer tokenSrv.Close()

	uploadSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fresh-token" {
			t.Errorf("expected refreshed bearer, got %q", r.Header.Get("Authorization"))
		}
		fmt.Fprint(w, `{"id":"file-1","name":"f.txt"}`)
	}))
	defer uploadSrv.Close()

	_, err := Save(context.Background(), Config{
		Kind: "gdrive", Endpoint: uploadSrv.URL,
		RefreshToken: "rtok", ClientID: "cid", ClientSecret: "sec", TokenURL: tokenSrv.URL,
	}, "f.txt", []byte("x"), "text/plain")
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if !refreshed {
		t.Error("expected an OAuth token refresh before upload")
	}
}

func TestUnknownKind(t *testing.T) {
	if _, err := New(Config{Kind: "dropbox"}); err == nil {
		t.Fatal("expected error for unknown kind")
	}
}

func TestStoreRedactAndPersist(t *testing.T) {
	s := NewStore()
	if err := s.Set(Destination{Name: "myS3", Config: Config{Kind: "s3", Bucket: "b", AccessKey: "AK", SecretKey: "SECRET"}}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	// List redacts secrets.
	for _, d := range s.List() {
		if d.Config.SecretKey == "SECRET" {
			t.Error("secret should be redacted in List")
		}
	}
	// Snapshot keeps the real secret for persistence.
	blob, _ := s.Snapshot()
	if !strings.Contains(string(blob), "SECRET") {
		t.Error("snapshot should retain the secret")
	}
	s2 := NewStore()
	if err := s2.Restore(blob); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	d, ok := s2.Get("myS3")
	if !ok || d.Config.SecretKey != "SECRET" {
		t.Error("restored destination should keep the secret")
	}
}
