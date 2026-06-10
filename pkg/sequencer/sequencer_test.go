package sequencer_test

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/dstotijn/hetty/pkg/sequencer"
)

func randomTokens(t *testing.T, n, byteLen int) []string {
	t.Helper()
	out := make([]string, n)
	for i := range out {
		b := make([]byte, byteLen)
		if _, err := rand.Read(b); err != nil {
			t.Fatalf("rand: %v", err)
		}
		out[i] = hex.EncodeToString(b)
	}
	return out
}

func TestRandomTokensScoreWell(t *testing.T) {
	a := sequencer.Analyze(randomTokens(t, 200, 16))

	if a.DuplicateCount != 0 {
		t.Errorf("unexpected duplicates in random sample: %d", a.DuplicateCount)
	}
	if a.Quality != sequencer.QualityExcellent && a.Quality != sequencer.QualityGood {
		t.Errorf("random tokens rated %q, want good/excellent", a.Quality)
	}
	if a.MeanCharBits < 3.0 {
		t.Errorf("mean char entropy = %.2f bits, want >= 3 for hex alphabet", a.MeanCharBits)
	}
}

func TestConstantTokensRatePoor(t *testing.T) {
	tokens := make([]string, 50)
	for i := range tokens {
		tokens[i] = "AAAAAAAA"
	}

	a := sequencer.Analyze(tokens)

	if a.Quality != sequencer.QualityPoor {
		t.Errorf("constant tokens rated %q, want poor", a.Quality)
	}
	if a.DuplicateCount == 0 {
		t.Error("expected duplicates to be counted for constant tokens")
	}
	if a.MeanCharBits != 0 {
		t.Errorf("constant tokens mean char entropy = %.2f, want 0", a.MeanCharBits)
	}
}

func TestFixedPrefixDetected(t *testing.T) {
	tokens := []string{"FIXEDaaaa", "FIXEDbbbb", "FIXEDcccc", "FIXEDdddd"}

	a := sequencer.Analyze(tokens)

	// The first five positions are constant, so their entropy must be ~0.
	for i := 0; i < 5; i++ {
		if a.PositionBits[i] > 0.01 {
			t.Errorf("position %d entropy = %.3f, want ~0 (fixed prefix)", i, a.PositionBits[i])
		}
	}
}

func TestEmptyInput(t *testing.T) {
	a := sequencer.Analyze(nil)
	if a.Quality != sequencer.QualityPoor {
		t.Errorf("empty input quality = %q, want poor", a.Quality)
	}
}
