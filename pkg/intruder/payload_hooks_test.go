package intruder

import (
	"reflect"
	"testing"
)

func TestExpandGenerators(t *testing.T) {
	e := NewEngine()
	e.RegisterGenerator("nums", func() ([]string, error) { return []string{"1", "2", "3"}, nil })

	out, err := e.expandGenerators([][]string{{"a", "@gen:nums", "b"}})
	if err != nil {
		t.Fatalf("expandGenerators: %v", err)
	}
	want := [][]string{{"a", "1", "2", "3", "b"}}
	if !reflect.DeepEqual(out, want) {
		t.Fatalf("got %v, want %v", out, want)
	}
}

func TestExpandUnknownGenerator(t *testing.T) {
	e := NewEngine()
	// Register an unrelated generator so the expansion path is active.
	e.RegisterGenerator("other", func() ([]string, error) { return []string{"x"}, nil })
	if _, err := e.expandGenerators([][]string{{"@gen:missing"}}); err == nil {
		t.Fatal("expected error for unknown generator")
	}
}

func TestApplyCustomProcessor(t *testing.T) {
	e := NewEngine()
	e.RegisterProcessor("exclaim", func(s string) (string, error) { return s + "!", nil })

	// Custom processor then a built-in, chained.
	got, err := e.applyProcessors("hi", []string{"exclaim", "upper"})
	if err != nil {
		t.Fatalf("applyProcessors: %v", err)
	}
	if got != "HI!" {
		t.Fatalf("got %q, want HI!", got)
	}
}

func TestUnknownProcessorStillErrors(t *testing.T) {
	e := NewEngine()
	if _, err := e.applyProcessors("x", []string{"nope"}); err == nil {
		t.Fatal("expected error for unknown processor")
	}
}
