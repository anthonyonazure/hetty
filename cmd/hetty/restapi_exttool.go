package main

import (
	"net/http"
)

func (a *restAPI) handleExtToolsList(w http.ResponseWriter, r *http.Request) {
	if a.exttools == nil {
		writeErr(w, http.StatusServiceUnavailable, "external tools disabled")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"tools": a.exttools.Catalog().List()})
}

func (a *restAPI) handleExtToolRun(w http.ResponseWriter, r *http.Request) {
	if a.exttools == nil {
		writeErr(w, http.StatusServiceUnavailable, "external tools disabled")
		return
	}
	var body struct {
		Tool   string `json:"tool"`
		Target string `json:"target"`
		Extra  string `json:"extra"`
	}
	if err := readJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	job, err := a.exttools.Start(r.Context(), body.Tool, body.Target, body.Extra)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, job.View())
}

func (a *restAPI) handleExtToolJob(w http.ResponseWriter, r *http.Request) {
	if a.exttools == nil {
		writeErr(w, http.StatusServiceUnavailable, "external tools disabled")
		return
	}
	id := r.URL.Query().Get("id")
	job, ok := a.exttools.Job(id)
	if !ok {
		writeErr(w, http.StatusNotFound, "unknown job")
		return
	}
	writeJSON(w, http.StatusOK, job.View())
}

func (a *restAPI) handleExtToolStop(w http.ResponseWriter, r *http.Request) {
	if a.exttools == nil {
		writeErr(w, http.StatusServiceUnavailable, "external tools disabled")
		return
	}
	var body struct {
		ID string `json:"id"`
	}
	if err := readJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	ok := a.exttools.Stop(body.ID)
	writeJSON(w, http.StatusOK, map[string]interface{}{"stopped": ok})
}
