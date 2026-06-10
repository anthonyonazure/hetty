// Package gql is a client-side GraphQL testing tool — Hetty's analogue of the
// InQL extension. It runs the standard introspection query against a target
// GraphQL endpoint, reports whether introspection is (insecurely) enabled,
// parses the schema into types/queries/mutations, and synthesizes example
// queries the tester can drop straight into the Sender. (This is distinct from
// pkg/api, which serves Hetty's own admin GraphQL API.)
package gql

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// introspectionQuery is a compact form of the standard GraphQL introspection
// query — enough to enumerate types, fields, and argument names.
const introspectionQuery = `query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind
      name
      fields(includeDeprecated: true) {
        name
        args { name type { ...TypeRef } }
        type { ...TypeRef }
      }
    }
  }
}
fragment TypeRef on __Type {
  kind
  name
  ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } }
}`

// Options configures an introspection run.
type Options struct {
	Headers   map[string]string `json:"headers"`
	TimeoutMs int               `json:"timeoutMs"`
}

// Field is a field on a GraphQL type.
type Field struct {
	Name string   `json:"name"`
	Type string   `json:"type"`
	Args []string `json:"args,omitempty"`
}

// Type is a GraphQL type (object, scalar, enum, ...).
type Type struct {
	Kind   string  `json:"kind"`
	Name   string  `json:"name"`
	Fields []Field `json:"fields,omitempty"`
}

// Schema is the parsed introspection result.
type Schema struct {
	QueryType        string `json:"queryType"`
	MutationType     string `json:"mutationType"`
	SubscriptionType string `json:"subscriptionType"`
	Types            []Type `json:"types"`
}

// Result is the full output of Introspect.
type Result struct {
	Endpoint             string   `json:"endpoint"`
	IntrospectionEnabled bool     `json:"introspectionEnabled"`
	Schema               *Schema  `json:"schema,omitempty"`
	QueryNames           []string `json:"queryNames,omitempty"`
	MutationNames        []string `json:"mutationNames,omitempty"`
	SuggestedQueries     []string `json:"suggestedQueries,omitempty"`
	Note                 string   `json:"note,omitempty"`
}

// Introspect queries a GraphQL endpoint for its schema.
func Introspect(ctx context.Context, endpoint string, opts Options) (Result, error) {
	if endpoint == "" {
		return Result{}, fmt.Errorf("gql: endpoint required")
	}

	timeout := time.Duration(opts.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	client := &http.Client{Timeout: timeout}

	reqBody, _ := json.Marshal(map[string]string{"query": introspectionQuery})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(reqBody))
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range opts.Headers {
		req.Header.Set(k, v)
	}

	res, err := client.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("gql: request failed: %w", err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(io.LimitReader(res.Body, 16<<20))
	if err != nil {
		return Result{}, err
	}

	result := Result{Endpoint: endpoint}

	var parsed introspectionResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		result.Note = "response was not valid JSON; endpoint may not be GraphQL"
		return result, nil
	}

	if parsed.Data.Schema == nil {
		result.Note = "introspection appears disabled (no __schema in response)"
		return result, nil
	}

	result.IntrospectionEnabled = true
	result.Schema = buildSchema(parsed.Data.Schema)
	result.QueryNames = fieldNames(result.Schema, result.Schema.QueryType)
	result.MutationNames = fieldNames(result.Schema, result.Schema.MutationType)
	result.SuggestedQueries = suggestQueries(result.Schema)

	return result, nil
}

// --- introspection JSON shapes ---------------------------------------------

type introspectionResponse struct {
	Data struct {
		Schema *rawSchema `json:"__schema"`
	} `json:"data"`
}

type rawSchema struct {
	QueryType        *rawNamed `json:"queryType"`
	MutationType     *rawNamed `json:"mutationType"`
	SubscriptionType *rawNamed `json:"subscriptionType"`
	Types            []rawType `json:"types"`
}

type rawNamed struct {
	Name string `json:"name"`
}

type rawType struct {
	Kind   string     `json:"kind"`
	Name   string     `json:"name"`
	Fields []rawField `json:"fields"`
}

type rawField struct {
	Name string    `json:"name"`
	Args []rawArg  `json:"args"`
	Type rawTypeRef `json:"type"`
}

type rawArg struct {
	Name string     `json:"name"`
	Type rawTypeRef `json:"type"`
}

type rawTypeRef struct {
	Kind   string      `json:"kind"`
	Name   string      `json:"name"`
	OfType *rawTypeRef `json:"ofType"`
}

// typeName resolves a (possibly wrapped LIST/NON_NULL) type reference to its
// underlying named type, annotated with ! and [] wrappers.
func typeName(ref *rawTypeRef) string {
	if ref == nil {
		return ""
	}
	switch ref.Kind {
	case "NON_NULL":
		return typeName(ref.OfType) + "!"
	case "LIST":
		return "[" + typeName(ref.OfType) + "]"
	default:
		return ref.Name
	}
}

func buildSchema(rs *rawSchema) *Schema {
	s := &Schema{}
	if rs.QueryType != nil {
		s.QueryType = rs.QueryType.Name
	}
	if rs.MutationType != nil {
		s.MutationType = rs.MutationType.Name
	}
	if rs.SubscriptionType != nil {
		s.SubscriptionType = rs.SubscriptionType.Name
	}

	for _, rt := range rs.Types {
		if strings.HasPrefix(rt.Name, "__") {
			continue // skip introspection meta-types
		}
		t := Type{Kind: rt.Kind, Name: rt.Name}
		for _, rf := range rt.Fields {
			f := Field{Name: rf.Name, Type: typeName(&rf.Type)}
			for _, a := range rf.Args {
				f.Args = append(f.Args, a.Name+": "+typeName(&a.Type))
			}
			t.Fields = append(t.Fields, f)
		}
		s.Types = append(s.Types, t)
	}

	sort.Slice(s.Types, func(i, j int) bool { return s.Types[i].Name < s.Types[j].Name })
	return s
}

func findType(s *Schema, name string) *Type {
	for i := range s.Types {
		if s.Types[i].Name == name {
			return &s.Types[i]
		}
	}
	return nil
}

func fieldNames(s *Schema, typeName string) []string {
	t := findType(s, typeName)
	if t == nil {
		return nil
	}
	var out []string
	for _, f := range t.Fields {
		out = append(out, f.Name)
	}
	sort.Strings(out)
	return out
}

// suggestQueries builds skeleton operations for each root query/mutation field.
func suggestQueries(s *Schema) []string {
	var out []string
	out = append(out, buildSkeletons(s, s.QueryType, "query")...)
	out = append(out, buildSkeletons(s, s.MutationType, "mutation")...)
	return out
}

func buildSkeletons(s *Schema, rootType, op string) []string {
	t := findType(s, rootType)
	if t == nil {
		return nil
	}
	var out []string
	for _, f := range t.Fields {
		var args string
		if len(f.Args) > 0 {
			args = "(" + strings.Join(f.Args, ", ") + ")"
		}
		out = append(out, fmt.Sprintf("%s { %s%s }", op, f.Name, args))
	}
	return out
}
