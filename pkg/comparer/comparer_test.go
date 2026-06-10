package comparer_test

import (
	"strings"
	"testing"

	"github.com/dstotijn/hetty/pkg/comparer"
)

// reconstruct rebuilds the A and B sides from the diff segments.
func reconstruct(res comparer.Result) (a, b string) {
	for _, seg := range res.Segments {
		switch seg.Op {
		case comparer.OpEqual:
			a += seg.Text
			b += seg.Text
		case comparer.OpDelete:
			a += seg.Text
		case comparer.OpInsert:
			b += seg.Text
		}
	}
	return a, b
}

func TestDiffWordsReconstructs(t *testing.T) {
	a := "the quick brown fox jumps"
	b := "the slow brown cat jumps"

	res := comparer.DiffWords(a, b)

	gotA, gotB := reconstruct(res)
	if gotA != a {
		t.Errorf("reconstructed A = %q, want %q", gotA, a)
	}
	if gotB != b {
		t.Errorf("reconstructed B = %q, want %q", gotB, b)
	}
}

func TestDiffWordsDetectsChange(t *testing.T) {
	res := comparer.DiffWords("admin=false", "admin=true")

	hasInsert := false
	hasDelete := false
	for _, seg := range res.Segments {
		if seg.Op == comparer.OpInsert {
			hasInsert = true
		}
		if seg.Op == comparer.OpDelete {
			hasDelete = true
		}
	}
	if !hasInsert || !hasDelete {
		t.Errorf("expected both insert and delete segments; got %+v", res.Segments)
	}
}

func TestDiffEqual(t *testing.T) {
	res := comparer.DiffWords("identical text", "identical text")

	if res.Summary.Inserted != 0 || res.Summary.Deleted != 0 {
		t.Errorf("identical inputs produced changes: %+v", res.Summary)
	}
	if len(res.Segments) != 1 || res.Segments[0].Op != comparer.OpEqual {
		t.Errorf("expected single equal segment, got %+v", res.Segments)
	}
}

func TestDiffBytes(t *testing.T) {
	res := comparer.DiffBytes("password", "passw0rd")

	gotA, gotB := reconstruct(res)
	if gotA != "password" || gotB != "passw0rd" {
		t.Errorf("byte diff reconstruct failed: a=%q b=%q", gotA, gotB)
	}
	if !strings.Contains(string(res.Segments[0].Op), "equal") {
		t.Errorf("expected leading equal segment, got %+v", res.Segments[0])
	}
}
