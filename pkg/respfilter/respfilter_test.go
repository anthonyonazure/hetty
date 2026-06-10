package respfilter

import "testing"

func TestNilAndEmptyKeepEverything(t *testing.T) {
	var f *Filter
	if !f.Keep(200, 100, 10, 5, nil) {
		t.Error("nil filter should keep")
	}
	empty := &Filter{}
	if empty.Active() {
		t.Error("empty filter should be inactive")
	}
	if !empty.Keep(500, 0, 0, 0, nil) {
		t.Error("empty filter should keep everything")
	}
}

func TestMatchAndFilterStatus(t *testing.T) {
	f := &Filter{MatchStatus: []int{200, 301}}
	if !f.Keep(200, 0, 0, 0, nil) {
		t.Error("200 should match")
	}
	if f.Keep(404, 0, 0, 0, nil) {
		t.Error("404 should be excluded by matchStatus")
	}

	g := &Filter{FilterStatus: []int{404, 403}}
	if g.Keep(404, 0, 0, 0, nil) {
		t.Error("404 should be filtered out")
	}
	if !g.Keep(200, 0, 0, 0, nil) {
		t.Error("200 should pass when only filtering 404/403")
	}
}

func TestSizeAndWordFilters(t *testing.T) {
	f := &Filter{FilterSizes: []int{0, 1234}}
	if f.Keep(200, 1234, 0, 0, nil) {
		t.Error("size 1234 should be filtered")
	}
	if !f.Keep(200, 500, 0, 0, nil) {
		t.Error("size 500 should pass")
	}

	g := &Filter{MatchWords: []int{42}}
	if !g.Keep(200, 0, 42, 0, nil) {
		t.Error("42 words should match")
	}
	if g.Keep(200, 0, 7, 0, nil) {
		t.Error("7 words should be excluded")
	}
}

func TestRegexFilters(t *testing.T) {
	f := &Filter{MatchRegex: "admin|secret"}
	if err := f.Compile(); err != nil {
		t.Fatal(err)
	}
	if !f.Keep(200, 0, 0, 0, []byte("welcome to the admin panel")) {
		t.Error("body with 'admin' should match")
	}
	if f.Keep(200, 0, 0, 0, []byte("nothing here")) {
		t.Error("body without match should be excluded")
	}

	g := &Filter{FilterRegex: "Not Found"}
	_ = g.Compile()
	if g.Keep(200, 0, 0, 0, []byte("404 Not Found")) {
		t.Error("body matching filterRegex should be excluded")
	}
}

func TestWordsLinesHelpers(t *testing.T) {
	if Words([]byte("one two three")) != 3 {
		t.Error("word count wrong")
	}
	if Lines([]byte("a\nb\nc")) != 3 {
		t.Error("line count wrong")
	}
	if Lines(nil) != 0 {
		t.Error("empty body has 0 lines")
	}
}

func TestInvalidRegex(t *testing.T) {
	f := &Filter{MatchRegex: "("}
	if err := f.Compile(); err == nil {
		t.Error("expected compile error for invalid regex")
	}
}
