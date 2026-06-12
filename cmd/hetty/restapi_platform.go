package main

import (
	"net/http"
	"time"

	"github.com/dstotijn/hetty/pkg/monitor"
	"github.com/dstotijn/hetty/pkg/vault"
	"github.com/dstotijn/hetty/pkg/workflow"
)

// --- Save destinations (vault) ---------------------------------------------

func (a *restAPI) handleVaultList(w http.ResponseWriter, r *http.Request) {
	if a.vault == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"destinations": []vault.Destination{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"destinations": a.vault.List()})
}

func (a *restAPI) handleVaultSet(w http.ResponseWriter, r *http.Request) {
	var d vault.Destination
	if err := readJSON(r, &d); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := a.vault.Set(d); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
}

func (a *restAPI) handleVaultDelete(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		writeErr(w, http.StatusBadRequest, "name is required")
		return
	}
	a.vault.Delete(name)
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
}

func (a *restAPI) handleVaultSave(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Destination string `json:"destination"`
		Key         string `json:"key"`
		Data        string `json:"data"`
		ContentType string `json:"contentType"`
	}
	if err := readJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	dest, ok := a.vault.Get(body.Destination)
	if !ok {
		writeErr(w, http.StatusNotFound, "unknown destination")
		return
	}
	loc, err := vault.Save(r.Context(), dest.Config, body.Key, []byte(body.Data), body.ContentType)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"location": loc})
}

// --- Monitoring schedules ---------------------------------------------------

func (a *restAPI) handleMonitorList(w http.ResponseWriter, r *http.Request) {
	if a.monitor == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"schedules": []*monitor.Schedule{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"schedules": a.monitor.List()})
}

func (a *restAPI) handleMonitorSet(w http.ResponseWriter, r *http.Request) {
	var sc monitor.Schedule
	if err := readJSON(r, &sc); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	saved, err := a.monitor.Set(&sc)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, saved)
}

func (a *restAPI) handleMonitorDelete(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		writeErr(w, http.StatusBadRequest, "id is required")
		return
	}
	a.monitor.Delete(id)
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
}

func (a *restAPI) handleMonitorRun(w http.ResponseWriter, r *http.Request) {
	if a.monitorEngine == nil {
		writeErr(w, http.StatusServiceUnavailable, "monitoring disabled")
		return
	}
	var body struct {
		ID string `json:"id"`
	}
	if err := readJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	d, err := a.monitorEngine.RunNow(body.ID, time.Now())
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, d)
}

func (a *restAPI) handleMonitorDiffs(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	writeJSON(w, http.StatusOK, map[string]interface{}{"diffs": a.monitor.Diffs(id)})
}

// --- Workflows --------------------------------------------------------------

func (a *restAPI) handleWorkflowList(w http.ResponseWriter, r *http.Request) {
	if a.workflows == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"workflows": []workflow.Workflow{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"workflows": a.workflows.List()})
}

func (a *restAPI) handleWorkflowSet(w http.ResponseWriter, r *http.Request) {
	var wf workflow.Workflow
	if err := readJSON(r, &wf); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := a.workflows.Set(wf); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
}

func (a *restAPI) handleWorkflowDelete(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		writeErr(w, http.StatusBadRequest, "name is required")
		return
	}
	a.workflows.Delete(name)
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
}

func (a *restAPI) handleWorkflowRun(w http.ResponseWriter, r *http.Request) {
	if a.workflowEngine == nil {
		writeErr(w, http.StatusServiceUnavailable, "workflows disabled")
		return
	}
	var body struct {
		Workflow string `json:"workflow"`
		Target   string `json:"target"`
	}
	if err := readJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	wf, ok := a.workflows.Get(body.Workflow)
	if !ok {
		writeErr(w, http.StatusNotFound, "unknown workflow")
		return
	}
	if body.Target == "" {
		writeErr(w, http.StatusBadRequest, "target is required")
		return
	}
	res := a.workflowEngine.Run(r.Context(), wf, body.Target)
	writeJSON(w, http.StatusOK, res)
}
