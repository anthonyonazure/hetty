package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"

	"github.com/peterbourgon/ff/v3/ffcli"

	"github.com/dstotijn/hetty/pkg/decoder"
	"github.com/dstotijn/hetty/pkg/discovery"
	"github.com/dstotijn/hetty/pkg/gql"
	"github.com/dstotijn/hetty/pkg/mcp"
	"github.com/dstotijn/hetty/pkg/paramminer"
	"github.com/dstotijn/hetty/pkg/recon"
	"github.com/dstotijn/hetty/pkg/scan"
	"github.com/dstotijn/hetty/pkg/smuggle"
	"github.com/dstotijn/hetty/pkg/template"
)

// newMCPCommand returns the `hetty mcp` subcommand: a stdio MCP server that
// exposes Hetty's engines as tools for an AI agent (Claude Desktop, Claude
// Code, etc.) to drive by natural language.
func newMCPCommand() *ffcli.Command {
	fs := flag.NewFlagSet("hetty mcp", flag.ExitOnError)
	return &ffcli.Command{
		Name:       "mcp",
		ShortUsage: "hetty mcp",
		ShortHelp:  "Run an MCP (Model Context Protocol) server exposing Hetty's tools over stdio.",
		FlagSet:    fs,
		Exec:       execMCP,
	}
}

func obj(props map[string]interface{}, required ...string) map[string]interface{} {
	schema := map[string]interface{}{"type": "object", "properties": props}
	if len(required) > 0 {
		schema["required"] = required
	}
	return schema
}

func strProp(desc string) map[string]interface{} { return map[string]interface{}{"type": "string", "description": desc} }

func toJSON(v interface{}) (string, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	return string(b), err
}

func execMCP(ctx context.Context, _ []string) error {
	srv := mcp.NewServer("hetty", version)

	scanSvc := scan.NewService(scan.Config{Repository: newMemScanRepo(), Options: scan.DefaultOptions()})
	discoveryEngine := discovery.New()
	paramEngine := paramminer.New()
	smuggleProbe := smuggle.Probe
	reconEngine := recon.New()
	tmplEngine := template.New()
	tmpls := template.Builtins()

	srv.Register(mcp.Tool{
		Name:        "scan_url",
		Description: "Actively scan a single URL for web vulnerabilities (XSS, SQLi, command injection, SSTI, path traversal, open redirect, etc.) and return the findings.",
		InputSchema: obj(map[string]interface{}{
			"url":    strProp("The absolute URL to scan, including any query parameters to test."),
			"method": strProp("HTTP method (default GET)."),
		}, "url"),
		Handler: func(ctx context.Context, args json.RawMessage) (string, error) {
			var a struct{ URL, Method string }
			if err := json.Unmarshal(args, &a); err != nil {
				return "", err
			}
			u, err := url.Parse(a.URL)
			if err != nil {
				return "", fmt.Errorf("invalid url")
			}
			method := a.Method
			if method == "" {
				method = http.MethodGet
			}
			tmpl := scan.NewRequestTemplate(method, u, "", http.Header{}, nil)
			res, err := scanSvc.ScanRequest(ctx, scanULID(), tmpl)
			if err != nil {
				return "", err
			}
			return toJSON(map[string]interface{}{"tasksRun": res.TasksRun, "issues": res.Issues})
		},
	})

	srv.Register(mcp.Tool{
		Name:        "discover_content",
		Description: "Brute-force hidden paths and files on a target (forced browsing). Returns discovered URLs with their status codes.",
		InputSchema: obj(map[string]interface{}{
			"seed": strProp("The base URL to discover content under, e.g. https://example.com/"),
		}, "seed"),
		Handler: func(ctx context.Context, args json.RawMessage) (string, error) {
			var a struct{ Seed string }
			if err := json.Unmarshal(args, &a); err != nil {
				return "", err
			}
			res, err := discoveryEngine.Discover(ctx, a.Seed, discovery.Options{Concurrency: 10})
			if err != nil {
				return "", err
			}
			return toJSON(res)
		},
	})

	srv.Register(mcp.Tool{
		Name:        "mine_parameters",
		Description: "Discover hidden/unlinked request parameters on a target (Param Miner). Returns parameters that are reflected or change the response.",
		InputSchema: obj(map[string]interface{}{
			"target":   strProp("The target URL."),
			"location": strProp("Where to inject: query, body, or header (default query)."),
		}, "target"),
		Handler: func(ctx context.Context, args json.RawMessage) (string, error) {
			var a struct{ Target, Location string }
			if err := json.Unmarshal(args, &a); err != nil {
				return "", err
			}
			res, err := paramEngine.Mine(ctx, a.Target, paramminer.Options{Location: paramminer.Location(a.Location), Concurrency: 10})
			if err != nil {
				return "", err
			}
			return toJSON(res)
		},
	})

	srv.Register(mcp.Tool{
		Name:        "graphql_introspect",
		Description: "Run the GraphQL introspection query against an endpoint, returning whether introspection is exposed and the schema.",
		InputSchema: obj(map[string]interface{}{
			"endpoint": strProp("The GraphQL endpoint URL, e.g. https://example.com/graphql"),
		}, "endpoint"),
		Handler: func(ctx context.Context, args json.RawMessage) (string, error) {
			var a struct{ Endpoint string }
			if err := json.Unmarshal(args, &a); err != nil {
				return "", err
			}
			res, err := gql.Introspect(ctx, a.Endpoint, gql.Options{})
			if err != nil {
				return "", err
			}
			return toJSON(res)
		},
	})

	srv.Register(mcp.Tool{
		Name:        "smuggle_probe",
		Description: "Timing-based HTTP request smuggling probe (CL.TE / TE.CL desync detection) against an authorized target.",
		InputSchema: obj(map[string]interface{}{
			"target": strProp("The target URL."),
		}, "target"),
		Handler: func(ctx context.Context, args json.RawMessage) (string, error) {
			var a struct{ Target string }
			if err := json.Unmarshal(args, &a); err != nil {
				return "", err
			}
			res, err := smuggleProbe(ctx, a.Target, smuggle.Options{})
			if err != nil {
				return "", err
			}
			return toJSON(res)
		},
	})

	srv.Register(mcp.Tool{
		Name:        "recon_subdomains",
		Description: "Enumerate a domain's subdomains from Certificate Transparency logs (crt.sh) and resolve which are live.",
		InputSchema: obj(map[string]interface{}{
			"domain": strProp("The bare apex domain, e.g. example.com"),
		}, "domain"),
		Handler: func(ctx context.Context, args json.RawMessage) (string, error) {
			var a struct{ Domain string }
			if err := json.Unmarshal(args, &a); err != nil {
				return "", err
			}
			res, err := reconEngine.EnumerateSubdomains(ctx, a.Domain, recon.Options{Resolve: true, Concurrency: 20})
			if err != nil {
				return "", err
			}
			return toJSON(res)
		},
	})

	srv.Register(mcp.Tool{
		Name:        "fingerprint",
		Description: "Fingerprint the technology stack of a URL (server, framework, CMS, libraries) from headers, cookies and body signatures.",
		InputSchema: obj(map[string]interface{}{
			"url": strProp("The URL to fingerprint."),
		}, "url"),
		Handler: func(ctx context.Context, args json.RawMessage) (string, error) {
			var a struct{ URL string }
			if err := json.Unmarshal(args, &a); err != nil {
				return "", err
			}
			res, err := reconEngine.Fingerprint(ctx, a.URL)
			if err != nil {
				return "", err
			}
			return toJSON(res)
		},
	})

	srv.Register(mcp.Tool{
		Name:        "run_templates",
		Description: "Run Hetty's built-in nuclei-style detection templates (exposed .git/.env, actuator, phpinfo, directory listing) against a target.",
		InputSchema: obj(map[string]interface{}{
			"target": strProp("The base URL to scan."),
		}, "target"),
		Handler: func(ctx context.Context, args json.RawMessage) (string, error) {
			var a struct{ Target string }
			if err := json.Unmarshal(args, &a); err != nil {
				return "", err
			}
			res, err := tmplEngine.Run(ctx, a.Target, tmpls, template.Options{})
			if err != nil {
				return "", err
			}
			return toJSON(map[string]interface{}{"results": res})
		},
	})

	srv.Register(mcp.Tool{
		Name:        "decode",
		Description: "Decode or transform a string. With no codec, auto-detects and recursively decodes (smart decode). Codecs: base64, url, hex, html, gzip, jwt, md5, sha1, sha256.",
		InputSchema: obj(map[string]interface{}{
			"input": strProp("The string to decode."),
			"codec": strProp("The codec to apply, or empty for smart auto-decode."),
			"op":    strProp("encode or decode (default decode)."),
		}, "input"),
		Handler: func(ctx context.Context, args json.RawMessage) (string, error) {
			var a struct{ Input, Codec, Op string }
			if err := json.Unmarshal(args, &a); err != nil {
				return "", err
			}
			if a.Codec == "" {
				return toJSON(map[string]interface{}{"steps": decoder.SmartDecode([]byte(a.Input))})
			}
			op := decoder.OpDecode
			if a.Op == "encode" {
				op = decoder.OpEncode
			}
			out, err := decoder.Apply(a.Codec, op, []byte(a.Input))
			if err != nil {
				return "", err
			}
			return string(out), nil
		},
	})

	fmt.Fprintln(os.Stderr, "hetty MCP server ready on stdio.")
	return srv.Serve(ctx, os.Stdin, os.Stdout)
}
