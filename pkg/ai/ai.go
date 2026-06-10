// Package ai is an optional LLM analyst for Hetty, backed by the Anthropic
// Messages API. It triages scanner findings (scoring false-positive risk),
// suggests attack payloads, and drafts a proof-of-concept report. The feature
// is disabled unless an API key is configured (via --ai-key or the
// ANTHROPIC_API_KEY environment variable), and every call degrades gracefully.
//
// This uses a minimal raw HTTP client (one endpoint, POST /v1/messages) rather
// than the full SDK to keep Hetty's dependency surface small; the request shape
// and headers follow the documented Messages API.
package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DefaultModel is the model used when none is configured. Per Anthropic
// guidance, the most capable model is the default; override with --ai-model.
const DefaultModel = "claude-opus-4-8"

const (
	apiURL         = "https://api.anthropic.com/v1/messages"
	anthropicVer   = "2023-06-01"
	defaultTimeout = 90 * time.Second
)

// Client talks to the Anthropic Messages API.
type Client struct {
	apiKey     string
	model      string
	baseURL    string
	httpClient *http.Client
}

// Config configures a Client.
type Config struct {
	APIKey     string
	Model      string
	BaseURL    string // overridable for testing
	HTTPClient *http.Client
}

// NewClient returns an AI client. With no API key the client is disabled and
// all calls return ErrDisabled.
func NewClient(cfg Config) *Client {
	c := &Client{
		apiKey:     cfg.APIKey,
		model:      cfg.Model,
		baseURL:    cfg.BaseURL,
		httpClient: cfg.HTTPClient,
	}
	if c.model == "" {
		c.model = DefaultModel
	}
	if c.baseURL == "" {
		c.baseURL = apiURL
	}
	if c.httpClient == nil {
		c.httpClient = &http.Client{Timeout: defaultTimeout}
	}
	return c
}

// ErrDisabled is returned when the client has no API key configured.
var ErrDisabled = fmt.Errorf("ai: no API key configured")

// Enabled reports whether an API key is configured.
func (c *Client) Enabled() bool { return c != nil && c.apiKey != "" }

// Model returns the configured model ID.
func (c *Client) Model() string {
	if c == nil {
		return ""
	}
	return c.model
}

type messageRequest struct {
	Model     string         `json:"model"`
	MaxTokens int            `json:"max_tokens"`
	System    string         `json:"system,omitempty"`
	Messages  []apiMessage   `json:"messages"`
	Thinking  *thinkingParam `json:"thinking,omitempty"`
}

type thinkingParam struct {
	Type string `json:"type"`
}

type apiMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type messageResponse struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	StopReason string `json:"stop_reason"`
	Error      *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
}

// complete makes a single Messages API call and returns the concatenated text
// content. When think is true, adaptive thinking is enabled for higher-quality
// analysis (thinking blocks are ignored; only text is returned).
func (c *Client) complete(ctx context.Context, system, user string, maxTokens int, think bool) (string, error) {
	if !c.Enabled() {
		return "", ErrDisabled
	}

	reqBody := messageRequest{
		Model:     c.model,
		MaxTokens: maxTokens,
		System:    system,
		Messages:  []apiMessage{{Role: "user", Content: user}},
	}
	if think {
		reqBody.Thinking = &thinkingParam{Type: "adaptive"}
	}

	b, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL, bytes.NewReader(b))
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("x-api-key", c.apiKey)
	httpReq.Header.Set("anthropic-version", anthropicVer)
	httpReq.Header.Set("content-type", "application/json")

	res, err := c.httpClient.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("ai: request failed: %w", err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if err != nil {
		return "", err
	}

	var parsed messageResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", fmt.Errorf("ai: invalid response (status %d): %s", res.StatusCode, truncate(string(body), 200))
	}

	if res.StatusCode != http.StatusOK {
		if parsed.Error != nil {
			return "", fmt.Errorf("ai: API error (%s): %s", parsed.Error.Type, parsed.Error.Message)
		}
		return "", fmt.Errorf("ai: API returned status %d", res.StatusCode)
	}

	var sb strings.Builder
	for _, block := range parsed.Content {
		if block.Type == "text" {
			sb.WriteString(block.Text)
		}
	}
	return sb.String(), nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// extractJSON pulls the first complete JSON object out of a model response,
// tolerating markdown code fences or surrounding prose.
func extractJSON(s string) string {
	s = strings.TrimSpace(s)
	// Strip code fences.
	if i := strings.Index(s, "```"); i >= 0 {
		rest := s[i+3:]
		if nl := strings.IndexByte(rest, '\n'); nl >= 0 {
			rest = rest[nl+1:]
		}
		if j := strings.Index(rest, "```"); j >= 0 {
			rest = rest[:j]
		}
		s = strings.TrimSpace(rest)
	}
	start := strings.IndexByte(s, '{')
	end := strings.LastIndexByte(s, '}')
	if start >= 0 && end > start {
		return s[start : end+1]
	}
	return s
}
