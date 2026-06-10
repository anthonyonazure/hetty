// Package wordlists bundles curated wordlists for content discovery, parameter
// mining, subdomain enumeration and fuzzing — a compact, embedded subset of the
// kind of lists found in SecLists and PayloadsAllTheThings, so Hetty is useful
// out of the box without an external file. Users can still supply their own
// lists to any tool.
package wordlists

import "sort"

// List is a named, categorized wordlist.
type List struct {
	Name        string   `json:"name"`
	Category    string   `json:"category"` // paths | params | subdomains | payloads
	Description string   `json:"description"`
	Entries     []string `json:"-"`
}

// Info is list metadata without the (potentially large) entries.
type Info struct {
	Name        string `json:"name"`
	Category    string `json:"category"`
	Description string `json:"description"`
	Size        int    `json:"size"`
}

// registry holds all built-in lists by name.
var registry = map[string]List{}

func register(l List) {
	registry[l.Name] = l
}

// Names returns metadata for every built-in list, sorted by name.
func Names() []Info {
	out := make([]Info, 0, len(registry))
	for _, l := range registry {
		out = append(out, Info{Name: l.Name, Category: l.Category, Description: l.Description, Size: len(l.Entries)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Get returns the entries for a named list.
func Get(name string) ([]string, bool) {
	l, ok := registry[name]
	if !ok {
		return nil, false
	}
	return l.Entries, true
}

func init() {
	register(List{Name: "paths-common", Category: "paths", Description: "Common web paths and files", Entries: pathsCommon})
	register(List{Name: "params-common", Category: "params", Description: "Common request parameter names", Entries: paramsCommon})
	register(List{Name: "subdomains-common", Category: "subdomains", Description: "Common subdomain labels", Entries: subdomainsCommon})
	register(List{Name: "xss", Category: "payloads", Description: "Cross-site scripting payloads", Entries: payloadsXSS})
	register(List{Name: "sqli", Category: "payloads", Description: "SQL injection payloads", Entries: payloadsSQLi})
	register(List{Name: "lfi", Category: "payloads", Description: "Local file inclusion / path traversal payloads", Entries: payloadsLFI})
}
