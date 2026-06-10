// Package sitemap aggregates observed HTTP traffic into a per-host path tree —
// Hetty's analogue of Burp's site map / target tree. It is fed automatically
// from proxied responses and can also ingest spider and content-discovery
// results, giving the tester a single organized view of a target's surface:
// which endpoints exist, what methods and status codes they answer, which
// parameters they take, and what technology each host appears to run.
package sitemap

import (
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
)

// Entry is a single observation to fold into the map.
type Entry struct {
	URL         string
	Method      string
	Status      int
	ContentType string
	Params      []string
	Server      string
	Powered     string
	Source      string // "proxy", "spider", "discovery", "sender", ...
}

// Node is a node in the rendered tree.
type Node struct {
	Name         string  `json:"name"`
	Path         string  `json:"path"`
	URL          string  `json:"url,omitempty"`
	Methods      []string `json:"methods,omitempty"`
	Statuses     []int    `json:"statuses,omitempty"`
	Params       []string `json:"params,omitempty"`
	ContentTypes []string `json:"contentTypes,omitempty"`
	Sources      []string `json:"sources,omitempty"`
	Count        int      `json:"count"`
	Children     []*Node  `json:"children,omitempty"`
}

// Tech is detected technology for a host.
type Tech struct {
	Host    string   `json:"host"`
	Servers []string `json:"servers,omitempty"`
	Powered []string `json:"powered,omitempty"`
}

// Tree is the rendered site map.
type Tree struct {
	Hosts []*Node `json:"hosts"`
	Tech  []Tech  `json:"tech"`
}

type set struct {
	strs map[string]struct{}
	ints map[int]struct{}
}

func newSet() *set { return &set{strs: map[string]struct{}{}, ints: map[int]struct{}{}} }

func (s *set) addStr(v string) {
	if v != "" {
		s.strs[v] = struct{}{}
	}
}
func (s *set) addInt(v int) {
	if v != 0 {
		s.ints[v] = struct{}{}
	}
}
func (s *set) sortedStr() []string {
	out := make([]string, 0, len(s.strs))
	for v := range s.strs {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
func (s *set) sortedInt() []int {
	out := make([]int, 0, len(s.ints))
	for v := range s.ints {
		out = append(out, v)
	}
	sort.Ints(out)
	return out
}

type node struct {
	name     string
	path     string
	url      string
	methods  *set
	statuses *set
	params   *set
	ctypes   *set
	sources  *set
	count    int
	children map[string]*node
}

func newNode(name, path string) *node {
	return &node{
		name:     name,
		path:     path,
		methods:  newSet(),
		statuses: newSet(),
		params:   newSet(),
		ctypes:   newSet(),
		sources:  newSet(),
		children: map[string]*node{},
	}
}

type hostAgg struct {
	root    *node
	servers *set
	powered *set
}

// Store accumulates observations and renders the tree on demand.
type Store struct {
	mu    sync.Mutex
	hosts map[string]*hostAgg
}

// New returns an empty site map store.
func New() *Store {
	return &Store{hosts: map[string]*hostAgg{}}
}

// Add folds one observation into the map.
func (s *Store) Add(e Entry) {
	u, err := url.Parse(e.URL)
	if err != nil || u.Host == "" {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	ha, ok := s.hosts[u.Host]
	if !ok {
		ha = &hostAgg{root: newNode(u.Host, ""), servers: newSet(), powered: newSet()}
		s.hosts[u.Host] = ha
	}
	ha.servers.addStr(e.Server)
	ha.powered.addStr(e.Powered)

	// Walk/extend the path tree.
	cur := ha.root
	segs := splitPath(u.Path)
	accum := ""
	for _, seg := range segs {
		accum += "/" + seg
		child, ok := cur.children[seg]
		if !ok {
			child = newNode(seg, accum)
			cur.children[seg] = child
		}
		cur = child
	}

	cur.url = scheme(u) + "://" + u.Host + u.Path
	cur.count++
	cur.methods.addStr(strings.ToUpper(e.Method))
	cur.statuses.addInt(e.Status)
	cur.ctypes.addStr(shortContentType(e.ContentType))
	cur.sources.addStr(e.Source)
	for _, p := range e.Params {
		cur.params.addStr(p)
	}
	// Query params from the URL itself.
	for k := range u.Query() {
		cur.params.addStr(k)
	}
}

// ObserveResponse folds a live proxied response into the map.
func (s *Store) ObserveResponse(res *http.Response, source string) {
	if res == nil || res.Request == nil || res.Request.URL == nil {
		return
	}
	req := res.Request
	var params []string
	if err := req.ParseForm(); err == nil {
		for k := range req.PostForm {
			params = append(params, k)
		}
	}
	s.Add(Entry{
		URL:         req.URL.String(),
		Method:      req.Method,
		Status:      res.StatusCode,
		ContentType: res.Header.Get("Content-Type"),
		Params:      params,
		Server:      res.Header.Get("Server"),
		Powered:     res.Header.Get("X-Powered-By"),
		Source:      source,
	})
}

// Tree renders the accumulated observations.
func (s *Store) Tree() Tree {
	s.mu.Lock()
	defer s.mu.Unlock()

	var t Tree
	hostNames := make([]string, 0, len(s.hosts))
	for h := range s.hosts {
		hostNames = append(hostNames, h)
	}
	sort.Strings(hostNames)

	for _, h := range hostNames {
		ha := s.hosts[h]
		t.Hosts = append(t.Hosts, render(ha.root))
		t.Tech = append(t.Tech, Tech{
			Host:    h,
			Servers: ha.servers.sortedStr(),
			Powered: ha.powered.sortedStr(),
		})
	}
	return t
}

// HostCount returns the number of distinct hosts observed.
func (s *Store) HostCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.hosts)
}

// Clear empties the store.
func (s *Store) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hosts = map[string]*hostAgg{}
}

// Snapshot serializes the rendered tree (which carries all aggregated state)
// for persistence.
func (s *Store) Snapshot() ([]byte, error) {
	return json.Marshal(s.Tree())
}

// Restore rebuilds the internal aggregation tree from a snapshot.
func (s *Store) Restore(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	var tree Tree
	if err := json.Unmarshal(data, &tree); err != nil {
		return err
	}

	techByHost := make(map[string]Tech, len(tree.Tech))
	for _, t := range tree.Tech {
		techByHost[t.Host] = t
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.hosts = make(map[string]*hostAgg, len(tree.Hosts))
	for _, hostNode := range tree.Hosts {
		ha := &hostAgg{root: rebuildNode(hostNode), servers: newSet(), powered: newSet()}
		if t, ok := techByHost[hostNode.Name]; ok {
			for _, srv := range t.Servers {
				ha.servers.addStr(srv)
			}
			for _, pw := range t.Powered {
				ha.powered.addStr(pw)
			}
		}
		s.hosts[hostNode.Name] = ha
	}
	return nil
}

// rebuildNode reconstructs an internal node (with its aggregation sets) from a
// rendered Node.
func rebuildNode(n *Node) *node {
	nd := newNode(n.Name, n.Path)
	nd.url = n.URL
	nd.count = n.Count
	for _, m := range n.Methods {
		nd.methods.addStr(m)
	}
	for _, st := range n.Statuses {
		nd.statuses.addInt(st)
	}
	for _, p := range n.Params {
		nd.params.addStr(p)
	}
	for _, ct := range n.ContentTypes {
		nd.ctypes.addStr(ct)
	}
	for _, src := range n.Sources {
		nd.sources.addStr(src)
	}
	for _, c := range n.Children {
		nd.children[c.Name] = rebuildNode(c)
	}
	return nd
}

func render(n *node) *Node {
	out := &Node{
		Name:         n.name,
		Path:         n.path,
		URL:          n.url,
		Methods:      n.methods.sortedStr(),
		Statuses:     n.statuses.sortedInt(),
		Params:       n.params.sortedStr(),
		ContentTypes: n.ctypes.sortedStr(),
		Sources:      n.sources.sortedStr(),
		Count:        n.count,
	}

	childNames := make([]string, 0, len(n.children))
	for name := range n.children {
		childNames = append(childNames, name)
	}
	sort.Strings(childNames)
	for _, name := range childNames {
		out.Children = append(out.Children, render(n.children[name]))
	}
	return out
}

func splitPath(p string) []string {
	p = strings.Trim(p, "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

func scheme(u *url.URL) string {
	if u.Scheme != "" {
		return u.Scheme
	}
	return "http"
}

func shortContentType(ct string) string {
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		return strings.TrimSpace(ct[:i])
	}
	return strings.TrimSpace(ct)
}
