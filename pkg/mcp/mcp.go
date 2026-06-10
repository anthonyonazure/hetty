// Package mcp implements a minimal Model Context Protocol (MCP) server over a
// stdio JSON-RPC transport, with no external SDK. It lets an MCP client — Claude
// Desktop, Claude Code, or any agent — drive Hetty's engines (scan, discover,
// mine params, fingerprint, …) by natural-language tasking. The cmd/hetty `mcp`
// subcommand registers Hetty's tools and serves on stdin/stdout.
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"
)

// protocolVersion is the MCP revision this server speaks.
const protocolVersion = "2024-11-05"

// ToolHandler executes a tool call and returns text output.
type ToolHandler func(ctx context.Context, args json.RawMessage) (string, error)

// Tool is a registered MCP tool.
type Tool struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"inputSchema"`
	Handler     ToolHandler            `json:"-"`
}

// Server is a stdio MCP server.
type Server struct {
	name    string
	version string

	mu    sync.RWMutex
	tools map[string]Tool
	order []string
}

// NewServer returns an MCP server.
func NewServer(name, version string) *Server {
	return &Server{name: name, version: version, tools: make(map[string]Tool)}
}

// Register adds a tool.
func (s *Server) Register(t Tool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.tools[t.Name]; !ok {
		s.order = append(s.order, t.Name)
	}
	s.tools[t.Name] = t
}

// --- JSON-RPC wire types ---------------------------------------------------

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  interface{}     `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Serve runs the JSON-RPC loop, reading newline-delimited messages from r and
// writing responses to w, until r is exhausted or ctx is cancelled.
func (s *Server) Serve(ctx context.Context, r io.Reader, w io.Writer) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)

	enc := json.NewEncoder(w)
	var writeMu sync.Mutex
	send := func(resp rpcResponse) {
		writeMu.Lock()
		defer writeMu.Unlock()
		_ = enc.Encode(resp)
	}

	for scanner.Scan() {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var req rpcRequest
		if err := json.Unmarshal(line, &req); err != nil {
			send(rpcResponse{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{Code: -32700, Message: "parse error"}})
			continue
		}

		// Notifications (no id) get no response.
		isNotification := len(req.ID) == 0

		resp, ok := s.handle(ctx, req)
		if isNotification || !ok {
			continue
		}
		send(resp)
	}
	return scanner.Err()
}

func (s *Server) handle(ctx context.Context, req rpcRequest) (rpcResponse, bool) {
	resp := rpcResponse{JSONRPC: "2.0", ID: req.ID}

	switch req.Method {
	case "initialize":
		resp.Result = map[string]interface{}{
			"protocolVersion": protocolVersion,
			"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
			"serverInfo":      map[string]interface{}{"name": s.name, "version": s.version},
		}
		return resp, true

	case "notifications/initialized", "initialized":
		return resp, false // notification, no response

	case "ping":
		resp.Result = map[string]interface{}{}
		return resp, true

	case "tools/list":
		resp.Result = map[string]interface{}{"tools": s.toolList()}
		return resp, true

	case "tools/call":
		resp.Result = s.callTool(ctx, req.Params)
		return resp, true

	default:
		resp.Error = &rpcError{Code: -32601, Message: "method not found: " + req.Method}
		return resp, true
	}
}

func (s *Server) toolList() []Tool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Tool, 0, len(s.order))
	for _, name := range s.order {
		out = append(out, s.tools[name])
	}
	return out
}

// callResult is the MCP tool-call result shape.
type callResult struct {
	Content []contentBlock `json:"content"`
	IsError bool           `json:"isError,omitempty"`
}

type contentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

func textResult(text string, isErr bool) callResult {
	return callResult{Content: []contentBlock{{Type: "text", Text: text}}, IsError: isErr}
}

func (s *Server) callTool(ctx context.Context, params json.RawMessage) callResult {
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return textResult("invalid tool call params: "+err.Error(), true)
	}

	s.mu.RLock()
	tool, ok := s.tools[p.Name]
	s.mu.RUnlock()
	if !ok {
		return textResult(fmt.Sprintf("unknown tool: %s", p.Name), true)
	}

	out, err := tool.Handler(ctx, p.Arguments)
	if err != nil {
		return textResult("error: "+err.Error(), true)
	}
	return textResult(out, false)
}
