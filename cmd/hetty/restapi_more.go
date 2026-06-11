package main

import (
	"net/http"

	"github.com/dstotijn/hetty/pkg/ext"
	"github.com/dstotijn/hetty/pkg/poc"
	"github.com/dstotijn/hetty/pkg/session"
	"github.com/dstotijn/hetty/pkg/sessionflow"
	"github.com/dstotijn/hetty/pkg/wsrepeater"
)

// --- Extension actions ------------------------------------------------------

func (a *restAPI) handleExtActionsList(w http.ResponseWriter, r *http.Request) {
	if a.ext == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"actions": []ext.ActionInfo{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"actions": a.ext.Actions()})
}

func (a *restAPI) handleExtActionRun(w http.ResponseWriter, r *http.Request) {
	if a.ext == nil {
		writeErr(w, http.StatusServiceUnavailable, "extensions are disabled")
		return
	}
	var body struct {
		ID      string            `json:"id"`
		Request ext.ActionRequest `json:"request"`
	}
	if err := readJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if body.ID == "" {
		writeErr(w, http.StatusBadRequest, "action id is required")
		return
	}
	res, err := a.ext.RunAction(body.ID, body.Request)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// --- Session macros ---------------------------------------------------------

func (a *restAPI) handleMacrosList(w http.ResponseWriter, r *http.Request) {
	if a.macros == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"macros": []sessionflow.Macro{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"macros": a.macros.List()})
}

func (a *restAPI) handleMacroSet(w http.ResponseWriter, r *http.Request) {
	if a.macros == nil {
		writeErr(w, http.StatusServiceUnavailable, "macros are disabled")
		return
	}
	var m sessionflow.Macro
	if err := readJSON(r, &m); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := a.macros.Set(m); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
}

func (a *restAPI) handleMacroDelete(w http.ResponseWriter, r *http.Request) {
	if a.macros == nil {
		writeErr(w, http.StatusServiceUnavailable, "macros are disabled")
		return
	}
	name := r.URL.Query().Get("name")
	if name == "" {
		writeErr(w, http.StatusBadRequest, "name is required")
		return
	}
	a.macros.Delete(name)
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
}

func (a *restAPI) handleMacroRun(w http.ResponseWriter, r *http.Request) {
	if a.macroEngine == nil {
		writeErr(w, http.StatusServiceUnavailable, "macros are disabled")
		return
	}
	var body struct {
		Name   string             `json:"name"`
		Macro  *sessionflow.Macro `json:"macro"`
		SaveAs string             `json:"saveAs"` // optionally persist the result as a session profile
	}
	if err := readJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	macro := body.Macro
	if macro == nil {
		if body.Name == "" || a.macros == nil {
			writeErr(w, http.StatusBadRequest, "provide an inline macro or a saved macro name")
			return
		}
		m, ok := a.macros.Get(body.Name)
		if !ok {
			writeErr(w, http.StatusNotFound, "unknown macro")
			return
		}
		macro = &m
	}

	result, err := a.macroEngine.Run(r.Context(), *macro)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}

	// Optionally turn the macro result into a reusable session profile so the
	// scanner/intruder/sender stay authenticated.
	if body.SaveAs != "" && a.sessions != nil {
		prof := session.Profile{Name: body.SaveAs}
		for _, c := range result.Cookies {
			prof.Cookies = append(prof.Cookies, session.Cookie{Name: c.Name, Value: c.Value})
		}
		if b, ok := result.Vars["bearer"]; ok {
			prof.Bearer = b
		}
		_ = a.sessions.Set(prof)
	}

	writeJSON(w, http.StatusOK, result)
}

// --- PoC generators ---------------------------------------------------------

func (a *restAPI) handlePoCCSRF(w http.ResponseWriter, r *http.Request) {
	var opts poc.CSRFOptions
	if err := readJSON(r, &opts); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	html, err := poc.CSRF(opts)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"html": html})
}

func (a *restAPI) handlePoCClickjacking(w http.ResponseWriter, r *http.Request) {
	var body struct {
		URL string `json:"url"`
	}
	if err := readJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	html, err := poc.Clickjacking(body.URL)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"html": html})
}

// --- WebSocket repeater -----------------------------------------------------

func (a *restAPI) handleWSRepeater(w http.ResponseWriter, r *http.Request) {
	var opts wsrepeater.Options
	if err := readJSON(r, &opts); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if opts.URL == "" {
		writeErr(w, http.StatusBadRequest, "url is required")
		return
	}
	res, err := wsrepeater.Send(r.Context(), opts)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// --- Settings ---------------------------------------------------------------

func (a *restAPI) handleSettings(w http.ResponseWriter, r *http.Request) {
	aiEnabled := a.ai != nil && a.ai.Enabled()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"upstreamProxy": a.upstream,
		"aiEnabled":     aiEnabled,
	})
}
