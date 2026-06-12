package main

import (
	"net/http"
	"strings"

	"github.com/dstotijn/hetty/pkg/cluster"
)

func (a *restAPI) handleClusterList(w http.ResponseWriter, r *http.Request) {
	if a.cluster == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"workers": []cluster.Worker{}})
		return
	}
	// Redact tokens in the listing.
	workers := a.cluster.List()
	for i := range workers {
		if workers[i].Token != "" {
			workers[i].Token = "••••"
		}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"workers": workers})
}

func (a *restAPI) handleClusterSet(w http.ResponseWriter, r *http.Request) {
	if a.cluster == nil {
		writeErr(w, http.StatusServiceUnavailable, "cluster disabled")
		return
	}
	var wk cluster.Worker
	if err := readJSON(r, &wk); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := a.cluster.Set(wk); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
}

func (a *restAPI) handleClusterDelete(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		writeErr(w, http.StatusBadRequest, "name is required")
		return
	}
	a.cluster.Delete(name)
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
}

func (a *restAPI) handleClusterRun(w http.ResponseWriter, r *http.Request) {
	if a.clusterEngine == nil || a.cluster == nil {
		writeErr(w, http.StatusServiceUnavailable, "cluster disabled")
		return
	}
	var body struct {
		Targets []string `json:"targets"`
		Kind    string   `json:"kind"`
	}
	if err := readJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// Accept a newline/comma list too.
	var targets []string
	for _, t := range body.Targets {
		for _, p := range strings.FieldsFunc(t, func(r rune) bool { return r == '\n' || r == ',' }) {
			if s := strings.TrimSpace(p); s != "" {
				targets = append(targets, s)
			}
		}
	}
	if len(targets) == 0 {
		writeErr(w, http.StatusBadRequest, "at least one target is required")
		return
	}

	res, err := a.clusterEngine.Run(r.Context(), a.cluster.List(), targets, body.Kind)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}
