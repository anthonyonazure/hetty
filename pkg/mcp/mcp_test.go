package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestServeInitializeAndToolsList(t *testing.T) {
	s := NewServer("hetty-test", "1.0")
	s.Register(Tool{
		Name:        "echo",
		Description: "Echoes the input",
		InputSchema: map[string]interface{}{"type": "object"},
		Handler: func(ctx context.Context, args json.RawMessage) (string, error) {
			var a struct {
				Text string `json:"text"`
			}
			_ = json.Unmarshal(args, &a)
			return "echo: " + a.Text, nil
		},
	})

	input := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}}}`,
	}, "\n")

	var out strings.Builder
	if err := s.Serve(context.Background(), strings.NewReader(input), &out); err != nil {
		t.Fatal(err)
	}

	responses := readResponses(t, out.String())
	// The notification must NOT produce a response → 3 responses for 4 inputs.
	if len(responses) != 3 {
		t.Fatalf("expected 3 responses (notification yields none), got %d", len(responses))
	}

	// initialize
	if responses[0]["id"].(float64) != 1 {
		t.Errorf("first response id = %v", responses[0]["id"])
	}
	result := responses[0]["result"].(map[string]interface{})
	if result["protocolVersion"] != protocolVersion {
		t.Errorf("protocolVersion = %v", result["protocolVersion"])
	}

	// tools/list
	tools := responses[1]["result"].(map[string]interface{})["tools"].([]interface{})
	if len(tools) != 1 || tools[0].(map[string]interface{})["name"] != "echo" {
		t.Errorf("tools/list wrong: %v", tools)
	}

	// tools/call
	callRes := responses[2]["result"].(map[string]interface{})
	content := callRes["content"].([]interface{})
	text := content[0].(map[string]interface{})["text"].(string)
	if text != "echo: hi" {
		t.Errorf("tool call text = %q", text)
	}
}

func TestToolCallErrorIsReported(t *testing.T) {
	s := NewServer("t", "1")
	s.Register(Tool{Name: "boom", Handler: func(ctx context.Context, args json.RawMessage) (string, error) {
		return "", errBoom
	}})

	var out strings.Builder
	_ = s.Serve(context.Background(),
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"boom","arguments":{}}}`), &out)

	resp := readResponses(t, out.String())[0]
	result := resp["result"].(map[string]interface{})
	if result["isError"] != true {
		t.Error("tool error should set isError")
	}
}

func TestUnknownMethod(t *testing.T) {
	s := NewServer("t", "1")
	var out strings.Builder
	_ = s.Serve(context.Background(), strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"bogus"}`), &out)
	resp := readResponses(t, out.String())[0]
	if resp["error"] == nil {
		t.Error("unknown method should return an error")
	}
}

var errBoom = &testErr{"boom"}

type testErr struct{ s string }

func (e *testErr) Error() string { return e.s }

func readResponses(t *testing.T, s string) []map[string]interface{} {
	t.Helper()
	var out []map[string]interface{}
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var m map[string]interface{}
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("invalid response line %q: %v", line, err)
		}
		out = append(out, m)
	}
	return out
}
