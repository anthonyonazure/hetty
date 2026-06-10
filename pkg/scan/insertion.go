package scan

import (
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// InsertionPointType identifies where in a request a value lives.
type InsertionPointType string

const (
	InsertionQuery  InsertionPointType = "query"
	InsertionForm   InsertionPointType = "form"
	InsertionJSON   InsertionPointType = "json"
	InsertionCookie InsertionPointType = "cookie"
	InsertionHeader InsertionPointType = "header"
)

// InsertionPoint is a single location in a request that the scanner can inject
// payloads into.
type InsertionPoint struct {
	Type  InsertionPointType
	Name  string
	Value string
}

// String returns a label like "query:id".
func (ip InsertionPoint) String() string {
	return string(ip.Type) + ":" + ip.Name
}

// injectableHeaders are the request headers treated as insertion points when
// Options.IncludeHeaders is set.
var injectableHeaders = []string{"User-Agent", "Referer", "X-Forwarded-For"}

// BuildInsertionPoints discovers the insertion points in a request based on
// its URL, body, cookies, and (optionally) headers.
func BuildInsertionPoints(rt *RequestTemplate, opts Options) []InsertionPoint {
	var points []InsertionPoint

	// Query parameters.
	if rt.URL != nil {
		for name, vals := range rt.URL.Query() {
			val := ""
			if len(vals) > 0 {
				val = vals[0]
			}
			points = append(points, InsertionPoint{Type: InsertionQuery, Name: name, Value: val})
		}
	}

	contentType := ""
	if rt.Header != nil {
		contentType = strings.ToLower(rt.Header.Get("Content-Type"))
	}

	switch {
	case strings.Contains(contentType, "application/x-www-form-urlencoded") && len(rt.Body) > 0:
		if vals, err := url.ParseQuery(string(rt.Body)); err == nil {
			for name, v := range vals {
				val := ""
				if len(v) > 0 {
					val = v[0]
				}
				points = append(points, InsertionPoint{Type: InsertionForm, Name: name, Value: val})
			}
		}
	case strings.Contains(contentType, "json") && len(rt.Body) > 0:
		points = append(points, jsonInsertionPoints(rt.Body)...)
	}

	// Cookies.
	if opts.IncludeCookies && rt.Header != nil {
		for _, c := range readCookies(rt.Header) {
			points = append(points, InsertionPoint{Type: InsertionCookie, Name: c.Name, Value: c.Value})
		}
	}

	// Headers.
	if opts.IncludeHeaders && rt.Header != nil {
		for _, h := range injectableHeaders {
			if v := rt.Header.Get(h); v != "" {
				points = append(points, InsertionPoint{Type: InsertionHeader, Name: h, Value: v})
			}
		}
	}

	// Stable ordering for deterministic scans/tests.
	sort.SliceStable(points, func(i, j int) bool {
		if points[i].Type != points[j].Type {
			return points[i].Type < points[j].Type
		}
		return points[i].Name < points[j].Name
	})

	return points
}

// jsonInsertionPoints walks a JSON document and returns a leaf insertion point
// for every string/number value, keyed by a dot/bracket path.
func jsonInsertionPoints(body []byte) []InsertionPoint {
	var doc interface{}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil
	}

	var points []InsertionPoint

	var walk func(prefix string, v interface{})
	walk = func(prefix string, v interface{}) {
		switch t := v.(type) {
		case map[string]interface{}:
			for k, child := range t {
				p := k
				if prefix != "" {
					p = prefix + "." + k
				}
				walk(p, child)
			}
		case []interface{}:
			for i, child := range t {
				walk(prefix+"["+strconv.Itoa(i)+"]", child)
			}
		case string:
			points = append(points, InsertionPoint{Type: InsertionJSON, Name: prefix, Value: t})
		case float64:
			points = append(points, InsertionPoint{Type: InsertionJSON, Name: prefix, Value: strconv.FormatFloat(t, 'f', -1, 64)})
		}
	}

	walk("", doc)

	return points
}

// ApplyPayload returns a clone of base with the insertion point's value
// replaced (or, when appendMode is true, suffixed) by payload.
func ApplyPayload(base *RequestTemplate, point InsertionPoint, payload string, appendMode bool) *RequestTemplate {
	value := payload
	if appendMode {
		value = point.Value + payload
	}

	clone := base.Clone()

	switch point.Type {
	case InsertionQuery:
		if clone.URL != nil {
			q := clone.URL.Query()
			q.Set(point.Name, value)
			clone.URL.RawQuery = q.Encode()
		}
	case InsertionForm:
		vals, err := url.ParseQuery(string(clone.Body))
		if err == nil {
			vals.Set(point.Name, value)
			clone.Body = []byte(vals.Encode())
		}
	case InsertionJSON:
		if updated, ok := setJSONPath(clone.Body, point.Name, value); ok {
			clone.Body = updated
		}
	case InsertionCookie:
		setCookie(clone.Header, point.Name, value)
	case InsertionHeader:
		clone.Header.Set(point.Name, value)
	}

	return clone
}

// setJSONPath sets the value at a dot/bracket path in a JSON document. It
// preserves the original value's JSON type (string vs number) where possible.
func setJSONPath(body []byte, path, value string) ([]byte, bool) {
	var doc interface{}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, false
	}

	tokens := parseJSONPath(path)
	if len(tokens) == 0 {
		return nil, false
	}

	// Decide the replacement type: if the existing leaf is a number and the
	// payload still parses as a number, keep it numeric; otherwise use a string.
	var newVal interface{} = value
	if existing, ok := getJSONPath(doc, tokens); ok {
		if _, isNum := existing.(float64); isNum {
			if f, err := strconv.ParseFloat(value, 64); err == nil {
				newVal = f
			}
		}
	}

	if !assignJSONPath(&doc, tokens, newVal) {
		return nil, false
	}

	out, err := json.Marshal(doc)
	if err != nil {
		return nil, false
	}

	return out, true
}

type jsonToken struct {
	key   string
	index int
	isIdx bool
}

func parseJSONPath(path string) []jsonToken {
	var tokens []jsonToken

	for _, part := range strings.Split(path, ".") {
		seg := part
		for {
			open := strings.IndexByte(seg, '[')
			if open == -1 {
				if seg != "" {
					tokens = append(tokens, jsonToken{key: seg})
				}
				break
			}

			if open > 0 {
				tokens = append(tokens, jsonToken{key: seg[:open]})
			}

			close := strings.IndexByte(seg, ']')
			if close == -1 || close < open {
				return tokens
			}

			idx, err := strconv.Atoi(seg[open+1 : close])
			if err != nil {
				return tokens
			}

			tokens = append(tokens, jsonToken{index: idx, isIdx: true})
			seg = seg[close+1:]
		}
	}

	return tokens
}

func getJSONPath(doc interface{}, tokens []jsonToken) (interface{}, bool) {
	cur := doc
	for _, tok := range tokens {
		if tok.isIdx {
			arr, ok := cur.([]interface{})
			if !ok || tok.index < 0 || tok.index >= len(arr) {
				return nil, false
			}
			cur = arr[tok.index]
		} else {
			obj, ok := cur.(map[string]interface{})
			if !ok {
				return nil, false
			}
			cur, ok = obj[tok.key]
			if !ok {
				return nil, false
			}
		}
	}

	return cur, true
}

func assignJSONPath(doc *interface{}, tokens []jsonToken, value interface{}) bool {
	if len(tokens) == 0 {
		return false
	}

	cur := *doc
	for i := 0; i < len(tokens)-1; i++ {
		tok := tokens[i]
		if tok.isIdx {
			arr, ok := cur.([]interface{})
			if !ok || tok.index < 0 || tok.index >= len(arr) {
				return false
			}
			cur = arr[tok.index]
		} else {
			obj, ok := cur.(map[string]interface{})
			if !ok {
				return false
			}
			child, ok := obj[tok.key]
			if !ok {
				return false
			}
			cur = child
		}
	}

	last := tokens[len(tokens)-1]
	if last.isIdx {
		arr, ok := cur.([]interface{})
		if !ok || last.index < 0 || last.index >= len(arr) {
			return false
		}
		arr[last.index] = value
		return true
	}

	obj, ok := cur.(map[string]interface{})
	if !ok {
		return false
	}
	obj[last.key] = value

	return true
}

// readCookies parses the request Cookie header.
func readCookies(header http.Header) []*http.Cookie {
	req := http.Request{Header: header}
	return req.Cookies()
}

// setCookie replaces a single cookie value within the Cookie header, leaving
// the others intact.
func setCookie(header http.Header, name, value string) {
	cookies := readCookies(header)

	var b strings.Builder
	for i, c := range cookies {
		if i > 0 {
			b.WriteString("; ")
		}
		b.WriteString(c.Name)
		b.WriteByte('=')
		if c.Name == name {
			b.WriteString(value)
		} else {
			b.WriteString(c.Value)
		}
	}

	header.Set("Cookie", b.String())
}
