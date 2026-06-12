package main

import (
	"net/http"

	"github.com/dstotijn/hetty/pkg/assetgraph"
)

func (a *restAPI) handleAssetsList(w http.ResponseWriter, r *http.Request) {
	if a.graph == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"assets": []*assetgraph.Asset{}})
		return
	}
	kind := assetgraph.Kind(r.URL.Query().Get("kind"))
	writeJSON(w, http.StatusOK, map[string]interface{}{"assets": a.graph.List(kind)})
}

func (a *restAPI) handleAssetsStats(w http.ResponseWriter, r *http.Request) {
	if a.graph == nil {
		writeJSON(w, http.StatusOK, map[string]int{"total": 0})
		return
	}
	writeJSON(w, http.StatusOK, a.graph.Stats())
}

func (a *restAPI) handleAssetsRelated(w http.ResponseWriter, r *http.Request) {
	if a.graph == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"related": []*assetgraph.Asset{}})
		return
	}
	key := r.URL.Query().Get("key")
	writeJSON(w, http.StatusOK, map[string]interface{}{"related": a.graph.Related(key)})
}

func (a *restAPI) handleAssetsClear(w http.ResponseWriter, r *http.Request) {
	if a.graph != nil {
		a.graph.Clear()
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
}
