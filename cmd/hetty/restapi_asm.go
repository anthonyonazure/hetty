package main

import (
	"net/http"
	"time"

	"github.com/dstotijn/hetty/pkg/asm"
	"github.com/dstotijn/hetty/pkg/portscan"
	"github.com/dstotijn/hetty/pkg/screenshot"
	"github.com/dstotijn/hetty/pkg/tlsscan"
	"github.com/dstotijn/hetty/pkg/wafdetect"
)

// --- Standalone recon tools -------------------------------------------------

func (a *restAPI) handlePortScan(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Host    string           `json:"host"`
		Options portscan.Options `json:"options"`
	}
	if err := readJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if body.Host == "" {
		writeErr(w, http.StatusBadRequest, "host is required")
		return
	}
	res, err := portscan.Scan(r.Context(), body.Host, body.Options)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if a.graph != nil {
		now := nowTS()
		for _, p := range res.Open {
			a.graph.IngestService(res.Host, p.Port, p.Service, p.Banner, "portscan", now)
		}
	}
	writeJSON(w, http.StatusOK, res)
}

func (a *restAPI) handleTLSScan(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Host    string          `json:"host"`
		Options tlsscan.Options `json:"options"`
	}
	if err := readJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if body.Host == "" {
		writeErr(w, http.StatusBadRequest, "host is required")
		return
	}
	res, err := tlsscan.Scan(r.Context(), body.Host, body.Options)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (a *restAPI) handleWAFDetect(w http.ResponseWriter, r *http.Request) {
	var body struct {
		URL string `json:"url"`
	}
	if err := readJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if body.URL == "" {
		writeErr(w, http.StatusBadRequest, "url is required")
		return
	}
	res, err := wafdetect.Detect(r.Context(), asmHTTPClient, body.URL)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (a *restAPI) handleScreenshot(w http.ResponseWriter, r *http.Request) {
	var body struct {
		URL     string             `json:"url"`
		Options screenshot.Options `json:"options"`
	}
	if err := readJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if body.URL == "" {
		writeErr(w, http.StatusBadRequest, "url is required")
		return
	}
	res, err := screenshot.Capture(r.Context(), body.URL, body.Options)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (a *restAPI) handleShodan(w http.ResponseWriter, r *http.Request) {
	if a.shodan == nil || !a.shodan.Enabled() {
		writeErr(w, http.StatusServiceUnavailable, "Shodan not configured (set --shodan-key or SHODAN_API_KEY)")
		return
	}
	var body struct {
		IP string `json:"ip"`
	}
	if err := readJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	host, err := a.shodan.Host(r.Context(), body.IP)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, host)
}

func (a *restAPI) handleMSFStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"enabled": a.msf != nil && a.msf.Enabled(),
	})
}

// --- Attack-surface workspaces ---------------------------------------------

type workspaceSummary struct {
	Name      string `json:"name"`
	Targets   int    `json:"targets"`
	Hosts     int    `json:"hosts"`
	LastMode  string `json:"lastMode,omitempty"`
	UpdatedAt string `json:"updatedAt,omitempty"`
}

func (a *restAPI) handleASMList(w http.ResponseWriter, r *http.Request) {
	if a.asmStore == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"workspaces": []workspaceSummary{}})
		return
	}
	var out []workspaceSummary
	for _, ws := range a.asmStore.List() {
		out = append(out, workspaceSummary{
			Name: ws.Name, Targets: len(ws.Targets), Hosts: len(ws.Hosts),
			LastMode: ws.LastMode, UpdatedAt: ws.UpdatedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"workspaces": out})
}

func (a *restAPI) handleASMGet(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	ws, ok := a.asmStore.Get(name)
	if !ok {
		writeErr(w, http.StatusNotFound, "unknown workspace")
		return
	}
	writeJSON(w, http.StatusOK, ws)
}

func (a *restAPI) handleASMSet(w http.ResponseWriter, r *http.Request) {
	if a.asmStore == nil {
		writeErr(w, http.StatusServiceUnavailable, "ASM disabled")
		return
	}
	var body struct {
		Name    string   `json:"name"`
		Targets []string `json:"targets"`
	}
	if err := readJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if body.Name == "" {
		writeErr(w, http.StatusBadRequest, "name is required")
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	ws, ok := a.asmStore.Get(body.Name)
	if !ok {
		ws = &asm.Workspace{Name: body.Name, CreatedAt: now}
	}
	ws.Targets = body.Targets
	ws.UpdatedAt = now
	a.asmStore.Save(ws)
	writeJSON(w, http.StatusOK, ws)
}

func (a *restAPI) handleASMDelete(w http.ResponseWriter, r *http.Request) {
	if a.asmStore == nil {
		writeErr(w, http.StatusServiceUnavailable, "ASM disabled")
		return
	}
	name := r.URL.Query().Get("name")
	if name == "" {
		writeErr(w, http.StatusBadRequest, "name is required")
		return
	}
	a.asmStore.Delete(name)
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
}

func (a *restAPI) handleASMRun(w http.ResponseWriter, r *http.Request) {
	if a.asmEngine == nil || a.asmStore == nil {
		writeErr(w, http.StatusServiceUnavailable, "ASM disabled")
		return
	}
	var body struct {
		Workspace string         `json:"workspace"`
		Mode      string         `json:"mode"`
		Options   asm.RunOptions `json:"options"`
	}
	if err := readJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	ws, ok := a.asmStore.Get(body.Workspace)
	if !ok {
		writeErr(w, http.StatusNotFound, "unknown workspace")
		return
	}

	mode := asm.Mode(body.Mode)
	switch mode {
	case asm.ModeRecon, asm.ModeWeb, asm.ModeFull, asm.ModeNuke:
	default:
		writeErr(w, http.StatusBadRequest, "mode must be recon|web|full|nuke")
		return
	}

	summary := a.asmEngine.Run(r.Context(), ws, mode, body.Options)
	ws.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	a.asmStore.Save(ws)

	if a.graph != nil {
		now := nowTS()
		for _, sub := range ws.Subdomains {
			for _, t := range ws.Targets {
				a.graph.IngestSubdomain(bareHost(t), sub, "asm", now)
			}
		}
		for _, h := range ws.Hosts {
			a.graph.IngestHost(h.Host, "asm", now)
			for _, p := range h.Ports {
				a.graph.IngestService(h.Host, p.Port, p.Service, p.Banner, "asm", now)
			}
			if h.Tech != nil {
				a.graph.IngestURL(h.Host, "https://"+h.Host+"/", h.Tech.Technologies, "asm", now)
			}
			for _, f := range h.Findings {
				a.graph.IngestFinding(h.Host, f.Title, f.Severity, "asm", now)
			}
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"summary": summary, "workspace": ws})
}
