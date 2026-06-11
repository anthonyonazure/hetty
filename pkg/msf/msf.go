// Package msf is an optional driver for an external Metasploit Framework RPC
// daemon (msfrpcd), enabling Sn1per-style auto-exploitation ("NUKE"). It speaks
// Metasploit's MessagePack RPC over HTTP. When no URL is configured the client
// is disabled and every call returns a clear error rather than failing hard.
package msf

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Config configures the Metasploit RPC client.
type Config struct {
	URL      string // full RPC endpoint, e.g. https://127.0.0.1:55553/api/
	User     string
	Pass     string
	Insecure bool // skip TLS verification (msfrpcd uses a self-signed cert)
}

// Client talks to msfrpcd.
type Client struct {
	url   string
	user  string
	pass  string
	token string
	http  *http.Client
}

// New returns a Metasploit RPC client. An empty URL leaves it disabled.
func New(cfg Config) *Client {
	transport := &http.Transport{}
	if cfg.Insecure {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	}
	return &Client{
		url:  cfg.URL,
		user: cfg.User,
		pass: cfg.Pass,
		http: &http.Client{Transport: transport, Timeout: 60 * time.Second},
	}
}

// Enabled reports whether an RPC endpoint is configured.
func (c *Client) Enabled() bool { return c != nil && c.url != "" }

// Login authenticates and stores the session token.
func (c *Client) Login(ctx context.Context) error {
	if !c.Enabled() {
		return fmt.Errorf("msf: RPC endpoint not configured")
	}
	m, err := c.call(ctx, "auth.login", c.user, c.pass)
	if err != nil {
		return err
	}
	tok, _ := m["token"].(string)
	if tok == "" {
		return fmt.Errorf("msf: login did not return a token")
	}
	c.token = tok
	return nil
}

// Version returns the Metasploit/Ruby/API version map (core.version).
func (c *Client) Version(ctx context.Context) (map[string]interface{}, error) {
	return c.call(ctx, "core.version")
}

// SearchModules returns module full-names matching query (module.search).
func (c *Client) SearchModules(ctx context.Context, query string) ([]string, error) {
	v, err := c.rawCall(ctx, "module.search", query)
	if err != nil {
		return nil, err
	}
	arr, ok := v.([]interface{})
	if !ok {
		return nil, fmt.Errorf("msf: unexpected module.search response")
	}
	var out []string
	for _, item := range arr {
		if m, ok := item.(map[string]interface{}); ok {
			if name, ok := m["fullname"].(string); ok {
				out = append(out, name)
			}
		}
	}
	return out, nil
}

// Execute runs a module (module.execute). fullName is e.g.
// "exploit/unix/ftp/vsftpd_234_backdoor"; opts holds datastore values such as
// RHOSTS/RPORT/LHOST. Returns the launched job id (when the framework reports one).
func (c *Client) Execute(ctx context.Context, fullName string, opts map[string]interface{}) (map[string]interface{}, error) {
	modType, modRef := splitModule(fullName)
	return c.call(ctx, "module.execute", modType, modRef, opts)
}

// Sessions lists active sessions (session.list).
func (c *Client) Sessions(ctx context.Context) (map[string]interface{}, error) {
	return c.call(ctx, "session.list")
}

func splitModule(fullName string) (modType, ref string) {
	parts := strings.SplitN(fullName, "/", 2)
	if len(parts) == 2 {
		switch parts[0] {
		case "exploit", "auxiliary", "post", "payload", "encoder", "nop", "evasion":
			return parts[0], parts[1]
		}
	}
	return "exploit", fullName
}

// call issues an RPC and requires a map response.
func (c *Client) call(ctx context.Context, method string, args ...interface{}) (map[string]interface{}, error) {
	v, err := c.rawCall(ctx, method, args...)
	if err != nil {
		return nil, err
	}
	m, ok := v.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("msf: %s returned a non-map response", method)
	}
	return m, nil
}

// rawCall issues an RPC and returns the decoded value (map or array).
func (c *Client) rawCall(ctx context.Context, method string, args ...interface{}) (interface{}, error) {
	if !c.Enabled() {
		return nil, fmt.Errorf("msf: RPC endpoint not configured")
	}

	arr := []interface{}{method}
	if method != "auth.login" && c.token != "" {
		arr = append(arr, c.token)
	}
	arr = append(arr, args...)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(mpEncode(arr)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "binary/message-pack")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("msf: RPC request failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))

	decoded, err := mpDecode(body)
	if err != nil {
		return nil, fmt.Errorf("msf: decode RPC response: %w", err)
	}

	if m, ok := decoded.(map[string]interface{}); ok {
		if isErr(m) {
			return nil, fmt.Errorf("msf: %s", errMsg(m))
		}
	}
	return decoded, nil
}

func isErr(m map[string]interface{}) bool {
	e, _ := m["error"].(bool)
	return e
}

func errMsg(m map[string]interface{}) string {
	if s, ok := m["error_message"].(string); ok && s != "" {
		return s
	}
	if s, ok := m["error_string"].(string); ok && s != "" {
		return s
	}
	return "Metasploit RPC error"
}
