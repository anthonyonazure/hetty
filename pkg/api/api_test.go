// Package api_test drives the GraphQL API the way a client does: real HTTP
// POSTs against the handler returned by HTTPHandler, asserting on the JSON that
// comes back.
//
// It deliberately does not touch the resolver methods directly. Most of
// pkg/api is machine-generated from schema.graphql, and regenerating it is
// routine maintenance; a suite bound to internal types would have to be
// rewritten every time. Going through the HTTP surface means these tests keep
// their meaning across generator upgrades, which is exactly when the resolver
// layer is most at risk of silently losing its implementations.
package api_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.etcd.io/bbolt"

	"github.com/dstotijn/hetty/pkg/api"
	"github.com/dstotijn/hetty/pkg/db/bolt"
	"github.com/dstotijn/hetty/pkg/proj"
	"github.com/dstotijn/hetty/pkg/proxy/intercept"
	"github.com/dstotijn/hetty/pkg/reqlog"
	"github.com/dstotijn/hetty/pkg/scope"
	"github.com/dstotijn/hetty/pkg/sender"
)

// gqlResponse is the GraphQL envelope: data and errors are peers, and a 200
// with a populated errors array is the normal way this API reports failure.
type gqlResponse struct {
	Data   json.RawMessage `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

type testAPI struct {
	handler http.Handler
	scope   *scope.Scope
}

// newTestAPI wires the same object graph cmd/hetty builds, against a bolt
// database in the test's temp dir. Everything is torn down via t.Cleanup so
// individual tests do not have to remember to close anything.
func newTestAPI(t *testing.T) *testAPI {
	t.Helper()

	boltDB, err := bbolt.Open(t.TempDir()+"/bolt.db", 0o600, nil)
	if err != nil {
		t.Fatalf("failed to open bolt database: %v", err)
	}
	t.Cleanup(func() { boltDB.Close() })

	db, err := bolt.DatabaseFromBoltDB(boltDB)
	if err != nil {
		t.Fatalf("failed to create database: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	scp := &scope.Scope{}

	reqLogSvc := reqlog.NewService(reqlog.Config{Repository: db, Scope: scp})
	interceptSvc := intercept.NewService(intercept.Config{})
	senderSvc := sender.NewService(sender.Config{Repository: db, ReqLogService: reqLogSvc, Scope: scp})

	projSvc, err := proj.NewService(proj.Config{
		Repository:       db,
		InterceptService: interceptSvc,
		ReqLogService:    reqLogSvc,
		SenderService:    senderSvc,
		Scope:            scp,
	})
	if err != nil {
		t.Fatalf("failed to create project service: %v", err)
	}

	resolver := &api.Resolver{
		ProjectService:    projSvc,
		RequestLogService: reqLogSvc,
		InterceptService:  interceptSvc,
		SenderService:     senderSvc,
	}

	return &testAPI{
		handler: api.HTTPHandler(resolver, "/api/graphql/"),
		scope:   scp,
	}
}

// exec runs one GraphQL operation and returns the decoded envelope. Transport
// level failures fail the test; GraphQL level errors are returned so callers
// can assert on them, since some tests are about the error path.
func (a *testAPI) exec(t *testing.T, query string) gqlResponse {
	t.Helper()

	body, err := json.Marshal(map[string]string{"query": query})
	if err != nil {
		t.Fatalf("failed to marshal request body: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/graphql/", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	a.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var res gqlResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("failed to decode response %q: %v", rec.Body.String(), err)
	}

	return res
}

// mustExec is exec plus the assertion that the operation carried no GraphQL
// errors. A resolver replaced by a "not implemented" stub panics, which gqlgen
// converts into exactly such an error, so this is the assertion that catches a
// regenerated-but-gutted resolver layer.
func (a *testAPI) mustExec(t *testing.T, query string) json.RawMessage {
	t.Helper()

	res := a.exec(t, query)
	if len(res.Errors) > 0 {
		t.Fatalf("unexpected GraphQL errors for query %q: %v", query, res.Errors)
	}

	return res.Data
}

func decode[T any](t *testing.T, raw json.RawMessage) T {
	t.Helper()

	var v T
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("failed to decode %q: %v", string(raw), err)
	}

	return v
}

type project struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	IsActive bool   `json:"isActive"`
}

func createProject(t *testing.T, a *testAPI, name string) project {
	t.Helper()

	data := a.mustExec(t, fmt.Sprintf(`mutation { createProject(name: %q) { id name isActive } }`, name))

	return decode[struct {
		CreateProject project `json:"createProject"`
	}](t, data).CreateProject
}

func TestProjectLifecycle(t *testing.T) {
	t.Parallel()

	a := newTestAPI(t)

	created := createProject(t, a, "test project")
	if created.ID == "" {
		t.Fatal("expected created project to have an id")
	}

	if created.Name != "test project" {
		t.Errorf("expected name %q, got %q", "test project", created.Name)
	}

	t.Run("appears in the projects list", func(t *testing.T) {
		data := a.mustExec(t, `query { projects { id name isActive } }`)
		projects := decode[struct {
			Projects []project `json:"projects"`
		}](t, data).Projects

		if len(projects) != 1 {
			t.Fatalf("expected 1 project, got %d", len(projects))
		}

		if projects[0].ID != created.ID {
			t.Errorf("expected project id %q, got %q", created.ID, projects[0].ID)
		}
	})

	t.Run("is not active until opened", func(t *testing.T) {
		data := a.mustExec(t, `query { activeProject { id } }`)
		active := decode[struct {
			ActiveProject *project `json:"activeProject"`
		}](t, data).ActiveProject

		if active != nil {
			t.Errorf("expected no active project, got %q", active.ID)
		}
	})

	t.Run("becomes active when opened", func(t *testing.T) {
		a.mustExec(t, fmt.Sprintf(`mutation { openProject(id: %q) { id isActive } }`, created.ID))

		data := a.mustExec(t, `query { activeProject { id isActive } }`)
		active := decode[struct {
			ActiveProject *project `json:"activeProject"`
		}](t, data).ActiveProject

		if active == nil {
			t.Fatal("expected an active project after opening one")
		}

		if active.ID != created.ID {
			t.Errorf("expected active project %q, got %q", created.ID, active.ID)
		}

		if !active.IsActive {
			t.Error("expected the active project to report isActive")
		}
	})

	t.Run("is no longer active once closed", func(t *testing.T) {
		data := a.mustExec(t, `mutation { closeProject { success } }`)
		if !decode[struct {
			CloseProject struct {
				Success bool `json:"success"`
			} `json:"closeProject"`
		}](t, data).CloseProject.Success {
			t.Error("expected closeProject to report success")
		}

		data = a.mustExec(t, `query { activeProject { id } }`)
		if decode[struct {
			ActiveProject *project `json:"activeProject"`
		}](t, data).ActiveProject != nil {
			t.Error("expected no active project after closing")
		}
	})

	t.Run("can be deleted", func(t *testing.T) {
		data := a.mustExec(t, fmt.Sprintf(`mutation { deleteProject(id: %q) { success } }`, created.ID))
		if !decode[struct {
			DeleteProject struct {
				Success bool `json:"success"`
			} `json:"deleteProject"`
		}](t, data).DeleteProject.Success {
			t.Error("expected deleteProject to report success")
		}

		data = a.mustExec(t, `query { projects { id } }`)
		if projects := decode[struct {
			Projects []project `json:"projects"`
		}](t, data).Projects; len(projects) != 0 {
			t.Errorf("expected no projects after deletion, got %d", len(projects))
		}
	})
}

// The name is validated before anything is written, and the failure has to
// reach the client as a GraphQL error rather than a 500 or a silent success.
func TestCreateProjectRejectsInvalidName(t *testing.T) {
	t.Parallel()

	a := newTestAPI(t)

	res := a.exec(t, `mutation { createProject(name: "not/a/valid/name") { id } }`)
	if len(res.Errors) == 0 {
		t.Fatal("expected a GraphQL error for an invalid project name, got none")
	}

	data := a.mustExec(t, `query { projects { id } }`)
	if projects := decode[struct {
		Projects []project `json:"projects"`
	}](t, data).Projects; len(projects) != 0 {
		t.Errorf("expected the rejected project not to be stored, found %d", len(projects))
	}
}

// Queries that read per-project state need an open project. Asking without one
// is a normal client mistake, and it must produce an error rather than a panic.
func TestQueriesWithoutAnOpenProject(t *testing.T) {
	t.Parallel()

	a := newTestAPI(t)

	for _, query := range []string{
		`query { httpRequestLogs { id } }`,
		`query { senderRequests { id } }`,
		`mutation { clearHTTPRequestLog { success } }`,
	} {
		res := a.exec(t, query)
		if len(res.Errors) == 0 {
			t.Errorf("expected an error for %q without an open project, got none", query)
		}
	}
}

// interceptedRequests is served from memory rather than the project database,
// so it answers with an empty list instead of erroring.
func TestInterceptedRequestsIsEmptyByDefault(t *testing.T) {
	t.Parallel()

	a := newTestAPI(t)

	data := a.mustExec(t, `query { interceptedRequests { id url method } }`)
	if reqs := decode[struct {
		InterceptedRequests []struct {
			ID string `json:"id"`
		} `json:"interceptedRequests"`
	}](t, data).InterceptedRequests; len(reqs) != 0 {
		t.Errorf("expected no intercepted requests, got %d", len(reqs))
	}
}

func TestSetScope(t *testing.T) {
	t.Parallel()

	a := newTestAPI(t)

	project := createProject(t, a, "scope project")
	a.mustExec(t, fmt.Sprintf(`mutation { openProject(id: %q) { id } }`, project.ID))

	data := a.mustExec(t, `mutation { setScope(scope: [{ url: "^https://example.com" }]) { url } }`)
	rules := decode[struct {
		SetScope []struct {
			URL string `json:"url"`
		} `json:"setScope"`
	}](t, data).SetScope

	if len(rules) != 1 {
		t.Fatalf("expected 1 scope rule, got %d", len(rules))
	}

	if rules[0].URL != "^https://example.com" {
		t.Errorf("expected the rule to round-trip, got %q", rules[0].URL)
	}

	t.Run("is readable back through the scope query", func(t *testing.T) {
		data := a.mustExec(t, `query { scope { url } }`)
		if got := decode[struct {
			Scope []struct {
				URL string `json:"url"`
			} `json:"scope"`
		}](t, data).Scope; len(got) != 1 || got[0].URL != "^https://example.com" {
			t.Errorf("expected the stored rule back, got %+v", got)
		}
	})

	t.Run("reaches the live scope, not just storage", func(t *testing.T) {
		if len(a.scope.Rules()) != 1 {
			t.Errorf("expected the running scope to hold 1 rule, got %d", len(a.scope.Rules()))
		}
	})
}

// updateInterceptSettings both persists and flips the running service. Reading
// it back through the service proves the resolver is wired to the real object
// and not just echoing its input.
func TestUpdateInterceptSettings(t *testing.T) {
	t.Parallel()

	a := newTestAPI(t)

	project := createProject(t, a, "intercept project")
	a.mustExec(t, fmt.Sprintf(`mutation { openProject(id: %q) { id } }`, project.ID))

	data := a.mustExec(t, `mutation {
		updateInterceptSettings(input: { requestsEnabled: true, responsesEnabled: false }) {
			requestsEnabled
			responsesEnabled
		}
	}`)

	settings := decode[struct {
		UpdateInterceptSettings struct {
			RequestsEnabled  bool `json:"requestsEnabled"`
			ResponsesEnabled bool `json:"responsesEnabled"`
		} `json:"updateInterceptSettings"`
	}](t, data).UpdateInterceptSettings

	if !settings.RequestsEnabled {
		t.Error("expected requestsEnabled to be true")
	}

	if settings.ResponsesEnabled {
		t.Error("expected responsesEnabled to be false")
	}
}

// A GET is the playground, not the API. Keeping this pinned means a routing
// change cannot quietly turn every query into a 404.
func TestGetServesThePlayground(t *testing.T) {
	t.Parallel()

	a := newTestAPI(t)

	req := httptest.NewRequest(http.MethodGet, "/api/graphql/", nil)
	rec := httptest.NewRecorder()
	a.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200 for the playground, got %d", rec.Code)
	}

	if !strings.Contains(rec.Body.String(), "GraphQL Playground") {
		t.Error("expected the playground HTML to be served on GET")
	}
}
