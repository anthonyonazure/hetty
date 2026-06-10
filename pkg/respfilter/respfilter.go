// Package respfilter implements ffuf-style match/filter rules over HTTP
// responses, shared by the intruder and content-discovery engines. A response
// is kept only if it passes every configured rule: "match" rules require the
// value to be in the set, "filter" rules require it to be absent. Empty rule
// sets are no-ops, so the zero Filter keeps everything.
package respfilter

import (
	"bytes"
	"fmt"
	"regexp"
)

// Filter holds match/filter rules. Status/size/words/lines take integer sets;
// regex rules take a single expression each.
type Filter struct {
	MatchStatus  []int  `json:"matchStatus"`
	FilterStatus []int  `json:"filterStatus"`
	MatchSizes   []int  `json:"matchSizes"`
	FilterSizes  []int  `json:"filterSizes"`
	MatchWords   []int  `json:"matchWords"`
	FilterWords  []int  `json:"filterWords"`
	MatchLines   []int  `json:"matchLines"`
	FilterLines  []int  `json:"filterLines"`
	MatchRegex   string `json:"matchRegex"`
	FilterRegex  string `json:"filterRegex"`

	matchRe  *regexp.Regexp
	filterRe *regexp.Regexp
}

// Compile validates and pre-compiles the regex rules. Call once before Keep.
func (f *Filter) Compile() error {
	if f.MatchRegex != "" {
		re, err := regexp.Compile(f.MatchRegex)
		if err != nil {
			return fmt.Errorf("respfilter: invalid matchRegex: %w", err)
		}
		f.matchRe = re
	}
	if f.FilterRegex != "" {
		re, err := regexp.Compile(f.FilterRegex)
		if err != nil {
			return fmt.Errorf("respfilter: invalid filterRegex: %w", err)
		}
		f.filterRe = re
	}
	return nil
}

// Active reports whether any rule is configured.
func (f *Filter) Active() bool {
	if f == nil {
		return false
	}
	return len(f.MatchStatus)+len(f.FilterStatus)+len(f.MatchSizes)+len(f.FilterSizes)+
		len(f.MatchWords)+len(f.FilterWords)+len(f.MatchLines)+len(f.FilterLines) > 0 ||
		f.MatchRegex != "" || f.FilterRegex != ""
}

func contains(set []int, v int) bool {
	for _, x := range set {
		if x == v {
			return true
		}
	}
	return false
}

// Words counts whitespace-delimited tokens in body.
func Words(body []byte) int { return len(bytes.Fields(body)) }

// Lines counts newline-terminated lines in body.
func Lines(body []byte) int {
	if len(body) == 0 {
		return 0
	}
	return bytes.Count(body, []byte{'\n'}) + 1
}

// Keep reports whether a response with the given attributes passes the filter.
// A nil filter keeps everything. body may be nil if regex rules are unused.
func (f *Filter) Keep(status, size, words, lines int, body []byte) bool {
	if f == nil {
		return true
	}

	if len(f.MatchStatus) > 0 && !contains(f.MatchStatus, status) {
		return false
	}
	if contains(f.FilterStatus, status) {
		return false
	}
	if len(f.MatchSizes) > 0 && !contains(f.MatchSizes, size) {
		return false
	}
	if contains(f.FilterSizes, size) {
		return false
	}
	if len(f.MatchWords) > 0 && !contains(f.MatchWords, words) {
		return false
	}
	if contains(f.FilterWords, words) {
		return false
	}
	if len(f.MatchLines) > 0 && !contains(f.MatchLines, lines) {
		return false
	}
	if contains(f.FilterLines, lines) {
		return false
	}
	if f.matchRe != nil && !f.matchRe.Match(body) {
		return false
	}
	if f.filterRe != nil && f.filterRe.Match(body) {
		return false
	}
	return true
}
