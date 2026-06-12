package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
)

// oauth carries an OAuth bearer token and, optionally, a refresh-token grant so
// the access token can be renewed before each upload.
type oauth struct {
	token        string
	refreshToken string
	clientID     string
	clientSecret string
	tokenURL     string
}

// accessToken returns a usable bearer token, refreshing via the refresh-token
// grant when one is configured.
func (o oauth) accessToken() (string, error) {
	if o.refreshToken == "" || o.clientID == "" {
		return o.token, nil
	}
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {o.refreshToken},
		"client_id":     {o.clientID},
		"client_secret": {o.clientSecret},
	}
	resp, err := httpClient.PostForm(o.tokenURL, form)
	if err != nil {
		return "", fmt.Errorf("vault: oauth refresh: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("vault: oauth refresh failed: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var r struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &r); err != nil || r.AccessToken == "" {
		return "", fmt.Errorf("vault: oauth refresh returned no access_token")
	}
	return r.AccessToken, nil
}

// Google Drive and Box backends upload with a user-supplied OAuth bearer token.
// We use simple (non-resumable) multipart uploads, which suit the report/export
// sizes Hetty produces.

// --- Google Drive ----------------------------------------------------------

type gdriveBackend struct {
	oauth    oauth
	folderID string
	endpoint string // overridable in tests
}

func newGDrive(cfg Config) *gdriveBackend {
	ep := cfg.Endpoint
	if ep == "" {
		ep = "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart"
	}
	tokenURL := cfg.TokenURL
	if tokenURL == "" {
		tokenURL = "https://oauth2.googleapis.com/token"
	}
	return &gdriveBackend{
		oauth:    oauth{token: cfg.Token, refreshToken: cfg.RefreshToken, clientID: cfg.ClientID, clientSecret: cfg.ClientSecret, tokenURL: tokenURL},
		folderID: cfg.FolderID,
		endpoint: ep,
	}
}

func (b *gdriveBackend) Kind() string { return "gdrive" }

func (b *gdriveBackend) Put(ctx context.Context, key string, data []byte, contentType string) (string, error) {
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	tok, err := b.oauth.accessToken()
	if err != nil {
		return "", err
	}
	name := key[strings.LastIndex(key, "/")+1:]

	meta := map[string]interface{}{"name": name}
	if b.folderID != "" {
		meta["parents"] = []string{b.folderID}
	}
	metaJSON, _ := json.Marshal(meta)

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	metaPart, _ := mw.CreatePart(textHeader("application/json; charset=UTF-8"))
	metaPart.Write(metaJSON)
	filePart, _ := mw.CreatePart(textHeader(contentType))
	filePart.Write(data)
	mw.Close()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.endpoint, &body)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "multipart/related; boundary="+mw.Boundary())

	return doUpload(req, "gdrive")
}

func textHeader(contentType string) map[string][]string {
	return map[string][]string{"Content-Type": {contentType}}
}

// --- Box -------------------------------------------------------------------

type boxBackend struct {
	oauth    oauth
	folderID string
	endpoint string
}

func newBox(cfg Config) *boxBackend {
	ep := cfg.Endpoint
	if ep == "" {
		ep = "https://upload.box.com/api/2.0/files/content"
	}
	folder := cfg.FolderID
	if folder == "" {
		folder = "0" // Box root folder
	}
	tokenURL := cfg.TokenURL
	if tokenURL == "" {
		tokenURL = "https://api.box.com/oauth2/token"
	}
	return &boxBackend{
		oauth:    oauth{token: cfg.Token, refreshToken: cfg.RefreshToken, clientID: cfg.ClientID, clientSecret: cfg.ClientSecret, tokenURL: tokenURL},
		folderID: folder,
		endpoint: ep,
	}
}

func (b *boxBackend) Kind() string { return "box" }

func (b *boxBackend) Put(ctx context.Context, key string, data []byte, contentType string) (string, error) {
	tok, err := b.oauth.accessToken()
	if err != nil {
		return "", err
	}
	name := key[strings.LastIndex(key, "/")+1:]

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	attrs, _ := json.Marshal(map[string]interface{}{
		"name":   name,
		"parent": map[string]string{"id": b.folderID},
	})
	mw.WriteField("attributes", string(attrs))
	fw, _ := mw.CreateFormFile("file", name)
	fw.Write(data)
	mw.Close()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.endpoint, &body)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", mw.FormDataContentType())

	return doUpload(req, "box")
}

func doUpload(req *http.Request, kind string) (string, error) {
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("vault(%s): %w", kind, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("vault(%s): %s: %s", kind, resp.Status, strings.TrimSpace(string(respBody)))
	}

	// Try to surface the created file id/name.
	var parsed struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Entries []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"entries"`
	}
	_ = json.Unmarshal(respBody, &parsed)
	if parsed.ID != "" {
		return fmt.Sprintf("%s:%s (%s)", kind, parsed.ID, parsed.Name), nil
	}
	if len(parsed.Entries) > 0 {
		return fmt.Sprintf("%s:%s (%s)", kind, parsed.Entries[0].ID, parsed.Entries[0].Name), nil
	}
	return kind + ": uploaded", nil
}
