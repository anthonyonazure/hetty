// Package sequencer implements Hetty's Sequencer tool: a statistical analysis
// of the randomness of a set of tokens (e.g. session IDs, CSRF tokens, password
// reset tokens). It reports Shannon entropy overall and per character position,
// duplicate counts, and an overall quality verdict.
package sequencer

import (
	"math"
	"sort"
)

// Analysis is the result of analyzing a token sample.
type Analysis struct {
	SampleCount    int     `json:"sampleCount"`
	UniqueTokens   int     `json:"uniqueTokens"`
	DuplicateCount int     `json:"duplicateCount"`
	MinLength      int     `json:"minLength"`
	MaxLength      int     `json:"maxLength"`
	CharsetSize    int     `json:"charsetSize"`
	OverallEntropy float64 `json:"overallEntropyBits"`  // distinct-token entropy (capped by sample size)
	MeanCharBits   float64 `json:"meanCharEntropyBits"` // average per-position entropy
	EstimatedBits  float64 `json:"estimatedBitsPerToken"`
	PositionBits   []float64 `json:"positionEntropyBits"`
	Quality        string  `json:"quality"`
	Notes          []string `json:"notes,omitempty"`
}

// Quality verdicts.
const (
	QualityExcellent = "excellent"
	QualityGood      = "good"
	QualityModerate  = "moderate"
	QualityPoor      = "poor"
)

// Analyze computes randomness statistics over the provided tokens.
func Analyze(tokens []string) Analysis {
	a := Analysis{SampleCount: len(tokens)}
	if len(tokens) == 0 {
		a.Quality = QualityPoor
		a.Notes = append(a.Notes, "no tokens provided")
		return a
	}

	// Length stats and global charset.
	a.MinLength = len(tokens[0])
	a.MaxLength = len(tokens[0])
	charset := map[rune]struct{}{}
	counts := map[string]int{}

	for _, tok := range tokens {
		if len(tok) < a.MinLength {
			a.MinLength = len(tok)
		}
		if len(tok) > a.MaxLength {
			a.MaxLength = len(tok)
		}
		for _, r := range tok {
			charset[r] = struct{}{}
		}
		counts[tok]++
	}

	a.UniqueTokens = len(counts)
	a.DuplicateCount = a.SampleCount - a.UniqueTokens
	a.CharsetSize = len(charset)

	// Overall distinct-token entropy (bounded by sample diversity).
	a.OverallEntropy = shannonFromCounts(counts, a.SampleCount)

	// Per-position character entropy, over the shared prefix length.
	if a.MinLength > 0 {
		a.PositionBits = make([]float64, a.MinLength)
		for pos := 0; pos < a.MinLength; pos++ {
			posCounts := map[rune]int{}
			for _, tok := range tokens {
				posCounts[[]rune(tok)[pos]]++
			}
			a.PositionBits[pos] = shannonFromRuneCounts(posCounts, a.SampleCount)
		}

		sum := 0.0
		for _, b := range a.PositionBits {
			sum += b
		}
		a.MeanCharBits = sum / float64(a.MinLength)
		a.EstimatedBits = sum // assuming positional independence
	}

	a.Quality, a.Notes = verdict(a)

	return a
}

func shannonFromCounts(counts map[string]int, total int) float64 {
	if total == 0 {
		return 0
	}
	h := 0.0
	for _, c := range counts {
		p := float64(c) / float64(total)
		h -= p * math.Log2(p)
	}
	return h
}

func shannonFromRuneCounts(counts map[rune]int, total int) float64 {
	if total == 0 {
		return 0
	}
	h := 0.0
	for _, c := range counts {
		p := float64(c) / float64(total)
		h -= p * math.Log2(p)
	}
	return h
}

func verdict(a Analysis) (string, []string) {
	var notes []string

	if a.DuplicateCount > 0 {
		notes = append(notes, "duplicate tokens observed — a strong sign of predictable generation")
	}

	if a.MinLength != a.MaxLength {
		notes = append(notes, "token lengths vary across the sample")
	}

	// Compare the observed mean per-character entropy to the theoretical
	// maximum for the observed character set.
	maxCharBits := 0.0
	if a.CharsetSize > 1 {
		maxCharBits = math.Log2(float64(a.CharsetSize))
	}

	quality := QualityPoor
	if maxCharBits > 0 {
		ratio := a.MeanCharBits / maxCharBits
		switch {
		case a.DuplicateCount > 0:
			quality = QualityPoor
		case ratio >= 0.95:
			quality = QualityExcellent
		case ratio >= 0.80:
			quality = QualityGood
		case ratio >= 0.55:
			quality = QualityModerate
		default:
			quality = QualityPoor
		}
		notes = append(notes, ratioNote(ratio))
	}

	// Flag any near-constant positions.
	var fixed []int
	for i, b := range a.PositionBits {
		if b < 0.1 {
			fixed = append(fixed, i)
		}
	}
	if len(fixed) > 0 {
		sort.Ints(fixed)
		notes = append(notes, "character positions with little/no entropy detected (likely fixed): "+intsToString(fixed))
	}

	return quality, notes
}

func ratioNote(ratio float64) string {
	switch {
	case ratio >= 0.95:
		return "per-character entropy is near the theoretical maximum for the observed alphabet"
	case ratio >= 0.80:
		return "per-character entropy is high but below the alphabet maximum"
	default:
		return "per-character entropy is well below the alphabet maximum — tokens may be predictable"
	}
}

func intsToString(xs []int) string {
	if len(xs) == 0 {
		return ""
	}
	out := ""
	for i, x := range xs {
		if i > 0 {
			out += ", "
		}
		out += itoa(x)
	}
	return out
}

func itoa(x int) string {
	if x == 0 {
		return "0"
	}
	neg := x < 0
	if neg {
		x = -x
	}
	var buf [20]byte
	i := len(buf)
	for x > 0 {
		i--
		buf[i] = byte('0' + x%10)
		x /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
