package main

import (
	"context"
	"time"

	"github.com/dstotijn/hetty/pkg/collab"
	"github.com/dstotijn/hetty/pkg/ext"
	"github.com/dstotijn/hetty/pkg/reqlog"
	"github.com/dstotijn/hetty/pkg/sitemap"
)

// These adapters let the extension engine read proxy history, the sitemap, and
// the OOB collaborator without pkg/ext importing those concrete packages.

type historyAdapter struct{ svc *reqlog.Service }

func (a *historyAdapter) Recent(limit int) []ext.HistoryItem {
	reqs, err := a.svc.FindRequests(context.Background())
	if err != nil {
		return nil
	}
	if limit > 0 && len(reqs) > limit {
		reqs = reqs[:limit]
	}
	out := make([]ext.HistoryItem, 0, len(reqs))
	for _, r := range reqs {
		item := ext.HistoryItem{Method: r.Method}
		if r.URL != nil {
			item.URL = r.URL.String()
		}
		if r.Response != nil {
			item.Status = r.Response.StatusCode
			item.ContentType = r.Response.Header.Get("Content-Type")
			item.Length = len(r.Response.Body)
		}
		out = append(out, item)
	}
	return out
}

type sitemapAdapter struct{ store *sitemap.Store }

func (a *sitemapAdapter) Entries() []ext.SitemapItem {
	var out []ext.SitemapItem
	var walk func(n *sitemap.Node)
	walk = func(n *sitemap.Node) {
		if n.URL != "" {
			out = append(out, ext.SitemapItem{
				URL: n.URL, Methods: n.Methods, Statuses: n.Statuses, Params: n.Params,
			})
		}
		for _, c := range n.Children {
			walk(c)
		}
	}
	for _, h := range a.store.Tree().Hosts {
		walk(h)
	}
	return out
}

type collabAdapter struct{ srv *collab.Server }

func (a *collabAdapter) NewToken() (string, string) { return a.srv.NewToken() }

func (a *collabAdapter) Interactions(token string) []ext.CollabItem {
	var out []ext.CollabItem
	for _, in := range a.srv.Interactions(token) {
		out = append(out, ext.CollabItem{
			Protocol:   in.Protocol,
			RemoteAddr: in.RemoteAddr,
			Method:     in.Method,
			Path:       in.Path,
			Time:       in.Time.Format(time.RFC3339),
		})
	}
	return out
}
