package ext

// This file defines the small provider interfaces the extension engine depends
// on for its richer host API (proxy history, sitemap, collaborator, intruder
// payload hooks). They are implemented by adapters in cmd/hetty so that pkg/ext
// stays decoupled from the concrete engine packages (no import cycles).

// HistoryProvider exposes recent proxy history to extensions.
type HistoryProvider interface {
	Recent(limit int) []HistoryItem
}

// HistoryItem is a single proxy-history entry surfaced to JS.
type HistoryItem struct {
	Method      string `json:"method"`
	URL         string `json:"url"`
	Status      int    `json:"status"`
	ContentType string `json:"contentType"`
	Length      int    `json:"length"`
}

// SitemapProvider exposes the discovered sitemap to extensions.
type SitemapProvider interface {
	Entries() []SitemapItem
}

// SitemapItem is a flattened sitemap node surfaced to JS.
type SitemapItem struct {
	URL      string   `json:"url"`
	Methods  []string `json:"methods"`
	Statuses []int    `json:"statuses"`
	Params   []string `json:"params"`
}

// CollabProvider exposes the OOB collaborator to extensions.
type CollabProvider interface {
	NewToken() (token, url string)
	Interactions(token string) []CollabItem
}

// CollabItem is one recorded OOB interaction surfaced to JS.
type CollabItem struct {
	Protocol   string `json:"protocol"`
	RemoteAddr string `json:"remoteAddr"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	Time       string `json:"time"`
}

// PayloadRegistry lets extensions register Intruder payload generators and
// processors. Implemented by *intruder.Engine.
type PayloadRegistry interface {
	RegisterProcessor(id string, fn func(string) (string, error))
	RegisterGenerator(id string, fn func() ([]string, error))
}

// ActionInfo describes an extension-registered send-to/context action.
type ActionInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Ext  string `json:"ext"`
}

// ActionRequest is the request handed to an action's run() function.
type ActionRequest struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

// ActionResult is what an action returns (its run()'s return value as text).
type ActionResult struct {
	Output string `json:"output"`
}
