package sitemap

import (
	"net/http"

	"github.com/dstotijn/hetty/pkg/proxy"
)

// ResponseModifier returns proxy middleware that records every proxied response
// into the site map. It never alters the response or adds latency beyond a map
// insertion.
func (s *Store) ResponseModifier(next proxy.ResponseModifyFunc) proxy.ResponseModifyFunc {
	return func(res *http.Response) error {
		if err := next(res); err != nil {
			return err
		}
		s.ObserveResponse(res, "proxy")
		return nil
	}
}
