package discovery

// CommonWordlist is a compact built-in wordlist of frequently present paths,
// suitable as a default for quick content discovery without an external file.
// It is intentionally small (fast first pass); users can supply a larger list
// via Options.Wordlist.
var CommonWordlist = []string{
	"admin", "administrator", "login", "logout", "signin", "signup", "register",
	"dashboard", "panel", "cpanel", "wp-admin", "wp-login.php", "user", "users",
	"account", "accounts", "profile", "settings", "config", "configuration",
	"api", "api/v1", "api/v2", "graphql", "rest", "swagger", "swagger-ui",
	"openapi.json", "swagger.json", "docs", "documentation", "redoc",
	"status", "health", "healthz", "ping", "metrics", "debug", "test",
	"dev", "staging", "stage", "uat", "demo", "backup", "backups", "bak", "old",
	"tmp", "temp", "cache", "logs", "log", "error", "errors",
	"upload", "uploads", "files", "file", "download", "downloads", "media",
	"images", "img", "assets", "static", "public", "private", "internal",
	"console", "manage", "management", "portal", "secure", "auth", "oauth",
	"token", "tokens", "session", "sessions", "key", "keys", "secret", "secrets",
	"db", "database", "sql", "phpmyadmin", "adminer", "mysql", "pgadmin",
	"git", "svn", "env", "robots.txt", "sitemap.xml", "crossdomain.xml",
	".git/config", ".env", ".gitignore", ".htaccess", "web.config",
	"server-status", "actuator", "actuator/health", "actuator/env",
	"info", "version", "readme", "readme.md", "changelog", "license",
	"search", "feed", "rss", "atom", "ajax", "include", "includes", "lib",
	"vendor", "node_modules", "src", "build", "dist", "data", "store",
	"shop", "cart", "checkout", "order", "orders", "payment", "payments",
	"invoice", "invoices", "report", "reports", "export", "import",
	"webhook", "webhooks", "callback", "notify", "mail", "email", "sms",
}
