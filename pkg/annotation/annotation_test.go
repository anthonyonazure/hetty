package annotation

import "testing"

func TestSetGet(t *testing.T) {
	s := New()
	if _, err := s.Set(Annotation{TargetID: "abc", Color: "red", Note: "interesting"}); err != nil {
		t.Fatal(err)
	}
	a, ok := s.Get("abc")
	if !ok {
		t.Fatal("annotation not found")
	}
	if a.Color != "red" || a.Note != "interesting" {
		t.Errorf("got %+v", a)
	}
	if a.UpdatedAt.IsZero() {
		t.Error("UpdatedAt should be set")
	}
}

func TestValidation(t *testing.T) {
	s := New()
	if _, err := s.Set(Annotation{TargetID: "", Color: "red"}); err == nil {
		t.Error("expected error for empty target ID")
	}
	if _, err := s.Set(Annotation{TargetID: "x", Color: "chartreuse"}); err == nil {
		t.Error("expected error for invalid color")
	}
}

func TestEmptyRemoves(t *testing.T) {
	s := New()
	_, _ = s.Set(Annotation{TargetID: "abc", Color: "red", Note: "x"})
	if _, err := s.Set(Annotation{TargetID: "abc", Color: "", Note: ""}); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Get("abc"); ok {
		t.Error("empty annotation should remove the entry")
	}
}

func TestAllAndDelete(t *testing.T) {
	s := New()
	_, _ = s.Set(Annotation{TargetID: "a", Color: "red"})
	_, _ = s.Set(Annotation{TargetID: "b", Note: "note"})
	if len(s.All()) != 2 {
		t.Errorf("All len = %d, want 2", len(s.All()))
	}
	s.Delete("a")
	if len(s.All()) != 1 {
		t.Errorf("after delete, All len = %d, want 1", len(s.All()))
	}
}
