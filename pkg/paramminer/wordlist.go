package paramminer

// CommonParams is a built-in list of frequently present but often unlinked
// request parameter names — the default dictionary for parameter discovery.
var CommonParams = []string{
	"id", "page", "q", "query", "search", "s", "keyword", "term", "lang", "locale",
	"debug", "test", "admin", "adminmode", "edit", "preview", "draft", "show", "hide",
	"callback", "jsonp", "redirect", "redirect_uri", "return", "returnurl", "next",
	"url", "uri", "dest", "destination", "continue", "goto", "target", "link",
	"file", "filename", "path", "dir", "folder", "doc", "document", "template", "tpl",
	"include", "view", "action", "do", "op", "func", "function", "method", "cmd",
	"token", "api_key", "apikey", "key", "secret", "auth", "access_token", "session",
	"user", "username", "uid", "userid", "account", "email", "role", "group",
	"order", "sort", "sortby", "dir", "asc", "desc", "limit", "offset", "count", "per_page",
	"format", "type", "mode", "output", "export", "download", "filetype", "ext",
	"category", "cat", "tag", "filter", "status", "state", "active", "enabled",
	"start", "end", "from", "to", "date", "year", "month", "day", "time",
	"price", "amount", "qty", "quantity", "currency", "discount", "coupon", "promo",
	"lat", "lng", "lon", "location", "address", "zip", "country", "region",
	"width", "height", "size", "scale", "quality", "color", "theme", "style",
	"ref", "referrer", "source", "utm_source", "campaign", "affiliate", "partner",
	"version", "v", "build", "env", "environment", "stage", "feature", "flag",
}
