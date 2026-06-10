package main

import (
	"context"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/oklog/ulid"

	"github.com/dstotijn/hetty/pkg/annotation"
	"github.com/dstotijn/hetty/pkg/authz"
	"github.com/dstotijn/hetty/pkg/discovery"
	"github.com/dstotijn/hetty/pkg/gql"
	"github.com/dstotijn/hetty/pkg/intruder"
	"github.com/dstotijn/hetty/pkg/jwt"
	"github.com/dstotijn/hetty/pkg/paramminer"
	"github.com/dstotijn/hetty/pkg/session"
	"github.com/dstotijn/hetty/pkg/sitemap"
	"github.com/dstotijn/hetty/pkg/smuggle"
	"github.com/dstotijn/hetty/pkg/template"
	"github.com/dstotijn/hetty/pkg/wordlists"
)

// --- Templated scanner -----------------------------------------------------

func (a *restAPI) handleTemplateList(w http.ResponseWriter, r *http.Request) {
	type info struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Severity    string `json:"severity"`
		Description string `json:"description"`
	}
	out := make([]info, 0, len(a.templates))
	for _, t := range a.templates {
		out = append(out, info{ID: t.ID, Name: t.Info.Name, Severity: t.Info.Severity, Description: t.Info.Description})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"templates": out})
}

func (a *restAPI) handleTemplateRun(w http.ResponseWriter, r *http.Request) {
	if a.tmplEngine == nil {
		writeErr(w, http.StatusServiceUnavailable, "templated scanner is disabled")
		return
	}
	var body struct {
		Target     string           `json:"target"`
		TemplateID string           `json:"templateId"`
		Template   string           `json:"template"`
		Options    template.Options `json:"options"`
	}
	if err := readJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if body.Target == "" {
		writeErr(w, http.StatusBadRequest, "target is required")
		return
	}

	var tmpls []*template.Template
	switch {
	case body.Template != "":
		t, err := template.Parse([]byte(body.Template))
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		tmpls = []*template.Template{t}
	case body.TemplateID != "":
		for _, t := range a.templates {
			if t.ID == body.TemplateID {
				tmpls = append(tmpls, t)
			}
		}
	default:
		tmpls = a.templates
	}

	results, err := a.tmplEngine.Run(r.Context(), body.Target, tmpls, body.Options)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"results": results, "templatesRun": len(tmpls)})
}

// --- Wordlists -------------------------------------------------------------

func (a *restAPI) handleWordlists(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{"lists": wordlists.Names()})
}

func (a *restAPI) handleWordlist(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	entries, ok := wordlists.Get(name)
	if !ok {
		writeErr(w, http.StatusNotFound, "unknown wordlist")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"name": name, "entries": entries})
}

// resolveProfile looks up a named auth profile, returning nil when the name is
// empty or unknown.
func (a *restAPI) resolveProfile(name string) *session.Profile {
	if name == "" || a.sessions == nil {
		return nil
	}
	if p, ok := a.sessions.Get(name); ok {
		return &p
	}
	return nil
}

// applyProfileToHeader injects a resolved profile's identity (headers, cookies,
// bearer, CSRF token) into h. A nil profile is a no-op.
func applyProfileToHeader(ctx context.Context, p *session.Profile, h http.Header) {
	if p == nil {
		return
	}
	p.Inject(ctx, http.DefaultClient, h)
}

// applyProfileToIntruderBase merges a profile into an intruder base request's
// header list (via an http.Header so cookies merge and duplicates collapse).
func applyProfileToIntruderBase(ctx context.Context, p *session.Profile, base *intruder.RequestSpec) {
	if p == nil {
		return
	}
	h := make(http.Header)
	for _, hdr := range base.Headers {
		if hdr.Name != "" {
			h.Add(hdr.Name, hdr.Value)
		}
	}
	p.Inject(ctx, http.DefaultClient, h)

	var out []intruder.Header
	for name, vals := range h {
		for _, v := range vals {
			out = append(out, intruder.Header{Name: name, Value: v})
		}
	}
	base.Headers = out
}

// --- Authorization tester --------------------------------------------------

func (a *restAPI) handleAuthzAnalyze(w http.ResponseWriter, r *http.Request) {
	if a.authz == nil {
		writeErr(w, http.StatusServiceUnavailable, "authz is disabled")
		return
	}
	var body struct {
		Base       authz.RequestSpec `json:"base"`
		Identities []struct {
			Label   string `json:"label"`
			Profile string `json:"profile"` // name of a stored session profile, or empty for unauth
		} `json:"identities"`
	}
	if err := readJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	var identities []authz.Identity
	for _, id := range body.Identities {
		ai := authz.Identity{Label: id.Label}
		if id.Profile != "" && a.sessions != nil {
			if p, ok := a.sessions.Get(id.Profile); ok {
				pp := p
				ai.Profile = &pp
			}
		}
		identities = append(identities, ai)
	}

	result, err := a.authz.Analyze(r.Context(), body.Base, identities)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// --- Session / auth profiles -----------------------------------------------

func (a *restAPI) handleSessionList(w http.ResponseWriter, r *http.Request) {
	if a.sessions == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"profiles": []session.Profile{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"profiles": a.sessions.List()})
}

func (a *restAPI) handleSessionSet(w http.ResponseWriter, r *http.Request) {
	if a.sessions == nil {
		writeErr(w, http.StatusServiceUnavailable, "sessions are disabled")
		return
	}
	var p session.Profile
	if err := readJSON(r, &p); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := a.sessions.Set(p); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"profiles": a.sessions.List()})
}

func (a *restAPI) handleSessionDelete(w http.ResponseWriter, r *http.Request) {
	if a.sessions == nil {
		writeErr(w, http.StatusServiceUnavailable, "sessions are disabled")
		return
	}
	name := r.URL.Query().Get("name")
	if name == "" {
		writeErr(w, http.StatusBadRequest, "name query parameter required")
		return
	}
	a.sessions.Delete(name)
	writeJSON(w, http.StatusOK, map[string]interface{}{"profiles": a.sessions.List()})
}

// --- Content discovery -----------------------------------------------------

func (a *restAPI) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	if a.discovery == nil {
		writeErr(w, http.StatusServiceUnavailable, "discovery is disabled")
		return
	}
	var body struct {
		Seed         string            `json:"seed"`
		Options      discovery.Options `json:"options"`
		WordlistName string            `json:"wordlistName"`
	}
	if err := readJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if body.Seed == "" {
		writeErr(w, http.StatusBadRequest, "seed is required")
		return
	}
	if body.WordlistName != "" && len(body.Options.Wordlist) == 0 {
		if entries, ok := wordlists.Get(body.WordlistName); ok {
			body.Options.Wordlist = entries
		}
	}

	result, err := a.discovery.Discover(r.Context(), body.Seed, body.Options)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	// Feed hits into the site map.
	if a.sitemap != nil {
		for _, h := range result.Hits {
			a.sitemap.Add(sitemap.Entry{URL: h.URL, Method: "GET", Status: h.Status, ContentType: h.ContentType, Source: "discovery"})
		}
	}

	writeJSON(w, http.StatusOK, result)
}

// --- GraphQL introspection -------------------------------------------------

func (a *restAPI) handleGQLIntrospect(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Endpoint string      `json:"endpoint"`
		Options  gql.Options `json:"options"`
	}
	if err := readJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if body.Endpoint == "" {
		writeErr(w, http.StatusBadRequest, "endpoint is required")
		return
	}
	result, err := gql.Introspect(r.Context(), body.Endpoint, body.Options)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// --- AI analyst ------------------------------------------------------------

func (a *restAPI) handleAIStatus(w http.ResponseWriter, r *http.Request) {
	enabled := a.ai != nil && a.ai.Enabled()
	model := ""
	if a.ai != nil {
		model = a.ai.Model()
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"enabled": enabled, "model": model})
}

func (a *restAPI) aiReady(w http.ResponseWriter) bool {
	if a.ai == nil || !a.ai.Enabled() {
		writeErr(w, http.StatusServiceUnavailable, "AI analyst is not configured (set --ai-key or ANTHROPIC_API_KEY)")
		return false
	}
	return true
}

func (a *restAPI) handleAITriage(w http.ResponseWriter, r *http.Request) {
	if !a.aiReady(w) {
		return
	}
	projectID, ok := a.activeProjectID(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "no active project")
		return
	}
	var body struct {
		IssueID string `json:"issueId"`
	}
	if err := readJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	id, err := ulid.Parse(body.IssueID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid issue ID")
		return
	}
	issue, err := a.scanner.FindIssueByID(r.Context(), projectID, id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "issue not found")
		return
	}
	triage, err := a.ai.TriageIssue(r.Context(), issue)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, triage)
}

func (a *restAPI) handleAIPayloads(w http.ResponseWriter, r *http.Request) {
	if !a.aiReady(w) {
		return
	}
	var body struct {
		VulnClass string `json:"vulnClass"`
		URL       string `json:"url"`
		Param     string `json:"param"`
		Context   string `json:"context"`
	}
	if err := readJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if body.VulnClass == "" {
		writeErr(w, http.StatusBadRequest, "vulnClass is required")
		return
	}
	suggestion, err := a.ai.SuggestPayloads(r.Context(), body.VulnClass, body.URL, body.Param, body.Context)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, suggestion)
}

func (a *restAPI) handleAIReport(w http.ResponseWriter, r *http.Request) {
	if !a.aiReady(w) {
		return
	}
	projectID, ok := a.activeProjectID(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "no active project")
		return
	}
	issues, err := a.scanner.FindIssues(r.Context(), projectID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	md, err := a.ai.GenerateReport(r.Context(), issues)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"markdown": md})
}

// --- WebSocket history -----------------------------------------------------

func (a *restAPI) handleWSConnections(w http.ResponseWriter, r *http.Request) {
	if a.wslog == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"connections": []interface{}{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"connections": a.wslog.Connections()})
}

func (a *restAPI) handleWSMessages(w http.ResponseWriter, r *http.Request) {
	if a.wslog == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"messages": []interface{}{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"messages": a.wslog.Messages(r.URL.Query().Get("connId")),
	})
}

func (a *restAPI) handleWSClear(w http.ResponseWriter, r *http.Request) {
	if a.wslog != nil {
		a.wslog.Clear()
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "cleared"})
}

// --- Request smuggling probe -----------------------------------------------

func (a *restAPI) handleSmuggle(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Target  string          `json:"target"`
		Options smuggle.Options `json:"options"`
	}
	if err := readJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if body.Target == "" {
		writeErr(w, http.StatusBadRequest, "target is required")
		return
	}
	result, err := smuggle.Probe(r.Context(), body.Target, body.Options)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// --- Parameter discovery ---------------------------------------------------

func (a *restAPI) handleParamMiner(w http.ResponseWriter, r *http.Request) {
	if a.paramminer == nil {
		writeErr(w, http.StatusServiceUnavailable, "parameter discovery is disabled")
		return
	}
	var body struct {
		Target       string             `json:"target"`
		Options      paramminer.Options `json:"options"`
		WordlistName string             `json:"wordlistName"`
	}
	if err := readJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if body.Target == "" {
		writeErr(w, http.StatusBadRequest, "target is required")
		return
	}
	if body.WordlistName != "" && len(body.Options.Wordlist) == 0 {
		if entries, ok := wordlists.Get(body.WordlistName); ok {
			body.Options.Wordlist = entries
		}
	}
	result, err := a.paramminer.Mine(r.Context(), body.Target, body.Options)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// --- Site map --------------------------------------------------------------

func (a *restAPI) handleSitemap(w http.ResponseWriter, r *http.Request) {
	if a.sitemap == nil {
		writeJSON(w, http.StatusOK, sitemap.Tree{})
		return
	}
	writeJSON(w, http.StatusOK, a.sitemap.Tree())
}

func (a *restAPI) handleSitemapClear(w http.ResponseWriter, r *http.Request) {
	if a.sitemap != nil {
		a.sitemap.Clear()
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "cleared"})
}

func (a *restAPI) handleSitemapIngest(w http.ResponseWriter, r *http.Request) {
	if a.sitemap == nil {
		writeErr(w, http.StatusServiceUnavailable, "site map is disabled")
		return
	}
	var body struct {
		Entries []sitemap.Entry `json:"entries"`
	}
	if err := readJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	for _, e := range body.Entries {
		a.sitemap.Add(e)
	}
	writeJSON(w, http.StatusOK, a.sitemap.Tree())
}

// --- JWT editor ------------------------------------------------------------

func (a *restAPI) handleJWTParse(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token string `json:"token"`
	}
	if err := readJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	tok, err := jwt.Parse(body.Token)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, tok)
}

func (a *restAPI) handleJWTSign(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Header  string `json:"header"`
		Payload string `json:"payload"`
		Secret  string `json:"secret"`
		Alg     string `json:"alg"`
	}
	if err := readJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if body.Alg == "" {
		body.Alg = "HS256"
	}
	out, err := jwt.SignHS(body.Header, body.Payload, body.Secret, body.Alg)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"token": out})
}

func (a *restAPI) handleJWTAlgNone(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Header  string `json:"header"`
		Payload string `json:"payload"`
		Variant string `json:"variant"`
	}
	if err := readJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	out, err := jwt.AlgNone(body.Header, body.Payload, body.Variant)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"token": out})
}

func (a *restAPI) handleJWTBrute(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token      string   `json:"token"`
		Candidates []string `json:"candidates"`
	}
	if err := readJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	res, err := jwt.BruteHS(body.Token, body.Candidates)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// --- Annotations -----------------------------------------------------------

func (a *restAPI) handleAnnotationsList(w http.ResponseWriter, r *http.Request) {
	if a.annotations == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"annotations": []annotation.Annotation{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"annotations": a.annotations.All()})
}

func (a *restAPI) handleAnnotationsSet(w http.ResponseWriter, r *http.Request) {
	if a.annotations == nil {
		writeErr(w, http.StatusServiceUnavailable, "annotations are disabled")
		return
	}
	var ann annotation.Annotation
	if err := readJSON(r, &ann); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	saved, err := a.annotations.Set(ann)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, saved)
}

func (a *restAPI) handleAnnotationsDelete(w http.ResponseWriter, r *http.Request) {
	if a.annotations == nil {
		writeErr(w, http.StatusServiceUnavailable, "annotations are disabled")
		return
	}
	id := r.URL.Query().Get("id")
	if id == "" {
		writeErr(w, http.StatusBadRequest, "id query parameter required")
		return
	}
	a.annotations.Delete(id)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
