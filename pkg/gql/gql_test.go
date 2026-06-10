package gql

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

const introspectionJSON = `{
  "data": {
    "__schema": {
      "queryType": { "name": "Query" },
      "mutationType": { "name": "Mutation" },
      "subscriptionType": null,
      "types": [
        {
          "kind": "OBJECT",
          "name": "Query",
          "fields": [
            { "name": "user", "args": [ { "name": "id", "type": { "kind": "NON_NULL", "name": null, "ofType": { "kind": "SCALAR", "name": "ID", "ofType": null } } } ], "type": { "kind": "OBJECT", "name": "User", "ofType": null } },
            { "name": "users", "args": [], "type": { "kind": "LIST", "name": null, "ofType": { "kind": "OBJECT", "name": "User", "ofType": null } } }
          ]
        },
        {
          "kind": "OBJECT",
          "name": "Mutation",
          "fields": [
            { "name": "createUser", "args": [ { "name": "name", "type": { "kind": "SCALAR", "name": "String", "ofType": null } } ], "type": { "kind": "OBJECT", "name": "User", "ofType": null } }
          ]
        },
        {
          "kind": "OBJECT",
          "name": "User",
          "fields": [
            { "name": "id", "args": [], "type": { "kind": "SCALAR", "name": "ID", "ofType": null } },
            { "name": "email", "args": [], "type": { "kind": "SCALAR", "name": "String", "ofType": null } }
          ]
        },
        { "kind": "OBJECT", "name": "__Directive", "fields": [] }
      ]
    }
  }
}`

func TestIntrospectParsesSchema(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(introspectionJSON))
	}))
	defer srv.Close()

	res, err := Introspect(context.Background(), srv.URL+"/graphql", Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IntrospectionEnabled {
		t.Fatal("introspection should be detected as enabled")
	}
	if res.Schema.QueryType != "Query" || res.Schema.MutationType != "Mutation" {
		t.Errorf("root types wrong: %+v", res.Schema)
	}

	// Meta-type __Directive must be filtered out.
	for _, ty := range res.Schema.Types {
		if ty.Name == "__Directive" {
			t.Error("introspection meta-types should be filtered")
		}
	}

	// Query names.
	if len(res.QueryNames) != 2 {
		t.Errorf("query names = %v, want user+users", res.QueryNames)
	}

	// NON_NULL / LIST wrapping should be rendered.
	var userField *Field
	for i := range res.Schema.Types {
		if res.Schema.Types[i].Name == "Query" {
			for j := range res.Schema.Types[i].Fields {
				if res.Schema.Types[i].Fields[j].Name == "user" {
					userField = &res.Schema.Types[i].Fields[j]
				}
			}
		}
	}
	if userField == nil {
		t.Fatal("user field not found")
	}
	if len(userField.Args) != 1 || userField.Args[0] != "id: ID!" {
		t.Errorf("user args = %v, want [id: ID!]", userField.Args)
	}

	// Suggested queries include a skeleton for createUser.
	foundMutation := false
	for _, q := range res.SuggestedQueries {
		if q == "mutation { createUser(name: String) }" {
			foundMutation = true
		}
	}
	if !foundMutation {
		t.Errorf("missing createUser skeleton; got %v", res.SuggestedQueries)
	}
}

func TestIntrospectionDisabled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"errors":[{"message":"introspection is disabled"}]}`))
	}))
	defer srv.Close()

	res, err := Introspect(context.Background(), srv.URL+"/graphql", Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.IntrospectionEnabled {
		t.Error("should report introspection disabled")
	}
	if res.Note == "" {
		t.Error("expected an explanatory note")
	}
}

func TestIntrospectNonGraphQL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html>not graphql</html>`))
	}))
	defer srv.Close()

	res, err := Introspect(context.Background(), srv.URL, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.IntrospectionEnabled {
		t.Error("non-GraphQL endpoint should not report introspection enabled")
	}
}
