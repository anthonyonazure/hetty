// Package comparer implements Hetty's Comparer tool: a longest-common-
// subsequence diff between two payloads at word or byte granularity, producing
// aligned equal/insert/delete segments suitable for rendering a side-by-side
// or inline comparison.
package comparer

import "strings"

// Op is the kind of a diff segment.
type Op string

const (
	OpEqual  Op = "equal"
	OpInsert Op = "insert" // present in B, not A
	OpDelete Op = "delete" // present in A, not B
)

// Segment is a contiguous run of tokens sharing one Op.
type Segment struct {
	Op   Op     `json:"op"`
	Text string `json:"text"`
}

// Summary counts tokens by disposition.
type Summary struct {
	Equal    int `json:"equal"`
	Inserted int `json:"inserted"`
	Deleted  int `json:"deleted"`
}

// Result is a complete comparison.
type Result struct {
	Segments []Segment `json:"segments"`
	Summary  Summary   `json:"summary"`
}

// DiffWords compares a and b at word granularity (runs of non-space and runs
// of space are treated as tokens, so whitespace changes are visible).
func DiffWords(a, b string) Result {
	return diff(tokenizeWords(a), tokenizeWords(b))
}

// DiffBytes compares a and b rune-by-rune.
func DiffBytes(a, b string) Result {
	return diff(tokenizeRunes(a), tokenizeRunes(b))
}

func tokenizeWords(s string) []string {
	var tokens []string
	var cur strings.Builder
	var curSpace bool
	started := false

	flush := func() {
		if cur.Len() > 0 {
			tokens = append(tokens, cur.String())
			cur.Reset()
		}
	}

	for _, r := range s {
		isSpace := r == ' ' || r == '\t' || r == '\n' || r == '\r'
		if started && isSpace != curSpace {
			flush()
		}
		cur.WriteRune(r)
		curSpace = isSpace
		started = true
	}
	flush()

	return tokens
}

func tokenizeRunes(s string) []string {
	tokens := make([]string, 0, len(s))
	for _, r := range s {
		tokens = append(tokens, string(r))
	}
	return tokens
}

// diff computes an LCS alignment of two token slices and merges runs of the
// same Op into segments.
func diff(a, b []string) Result {
	n, m := len(a), len(b)

	// dp[i][j] = LCS length of a[i:] and b[j:].
	dp := make([][]int, n+1)
	for i := range dp {
		dp[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if a[i] == b[j] {
				dp[i][j] = dp[i+1][j+1] + 1
			} else if dp[i+1][j] >= dp[i][j+1] {
				dp[i][j] = dp[i+1][j]
			} else {
				dp[i][j] = dp[i][j+1]
			}
		}
	}

	var (
		res  Result
		segs []Segment
	)

	add := func(op Op, text string) {
		if k := len(segs); k > 0 && segs[k-1].Op == op {
			segs[k-1].Text += text
		} else {
			segs = append(segs, Segment{Op: op, Text: text})
		}
	}

	i, j := 0, 0
	for i < n && j < m {
		switch {
		case a[i] == b[j]:
			add(OpEqual, a[i])
			res.Summary.Equal++
			i++
			j++
		case dp[i+1][j] >= dp[i][j+1]:
			add(OpDelete, a[i])
			res.Summary.Deleted++
			i++
		default:
			add(OpInsert, b[j])
			res.Summary.Inserted++
			j++
		}
	}
	for ; i < n; i++ {
		add(OpDelete, a[i])
		res.Summary.Deleted++
	}
	for ; j < m; j++ {
		add(OpInsert, b[j])
		res.Summary.Inserted++
	}

	res.Segments = segs

	return res
}
