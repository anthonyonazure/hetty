// Package secrets provides a curated database of regular-expression patterns
// for detecting leaked credentials (API keys, tokens, private keys) in HTTP
// responses and JavaScript. The set is inspired by mazen160/secrets-patterns-db
// and trufflehog, favoring high-precision patterns to keep noise low, and each
// pattern carries a short hint on how to validate the credential (a la keyhacks).
package secrets

import "regexp"

// Pattern is a single secret detector.
type Pattern struct {
	Name       string
	Severity   string // "high" | "critical"
	Re         *regexp.Regexp
	Validation string // how to verify the credential is live
}

func mp(name, severity, expr, validation string) Pattern {
	return Pattern{Name: name, Severity: severity, Re: regexp.MustCompile(expr), Validation: validation}
}

// Patterns is the built-in detector set.
var Patterns = []Pattern{
	mp("AWS access key ID", "critical", `\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA)[A-Z0-9]{16}\b`,
		"Use with the secret key against sts:GetCallerIdentity."),
	mp("AWS secret access key", "critical", `(?i)aws_?secret_?access_?key["'` + "`" + `]?\s*[:=]\s*["'` + "`" + `][A-Za-z0-9/+=]{40}["'` + "`" + `]`,
		"Pair with an access key ID and call sts:GetCallerIdentity."),
	mp("Google API key", "high", `\bAIza[0-9A-Za-z_\-]{35}\b`,
		"GET https://maps.googleapis.com/maps/api/geocode/json?key=KEY."),
	mp("Google OAuth client secret", "high", `\bGOCSPX-[0-9A-Za-z_\-]{28}\b`, "Use in the Google OAuth token exchange."),
	mp("GCP service account key", "critical", `"type":\s*"service_account"`, "Authenticate with gcloud auth activate-service-account."),
	mp("Slack token", "high", `\bxox[baprs]-[0-9A-Za-z-]{10,48}\b`, "POST https://slack.com/api/auth.test."),
	mp("Slack webhook", "high", `https://hooks\.slack\.com/services/T[0-9A-Za-z_]+/B[0-9A-Za-z_]+/[0-9A-Za-z]+`, "POST a test message to the webhook URL."),
	mp("GitHub token", "high", `\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[0-9A-Za-z_]{20,}\b`, "GET https://api.github.com/user with Authorization: token KEY."),
	mp("GitLab PAT", "high", `\bglpat-[0-9A-Za-z_\-]{20}\b`, "GET https://gitlab.com/api/v4/user with PRIVATE-TOKEN: KEY."),
	mp("Stripe secret key", "critical", `\b(?:sk|rk)_live_[0-9A-Za-z]{20,}\b`, "GET https://api.stripe.com/v1/charges -u KEY:."),
	mp("Stripe publishable key", "high", `\bpk_live_[0-9A-Za-z]{20,}\b`, "Public by design; confirms a live Stripe account."),
	mp("Square access token", "high", `\bsq0atp-[0-9A-Za-z_\-]{22}\b`, "Call the Square Connect API."),
	mp("Twilio API key", "high", `\bSK[0-9a-fA-F]{32}\b`, "GET https://api.twilio.com/2010-04-01/Accounts -u SID:KEY."),
	mp("Twilio account SID", "high", `\bAC[0-9a-fA-F]{32}\b`, "Pairs with an auth token for the Twilio API."),
	mp("SendGrid API key", "high", `\bSG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}\b`, "GET https://api.sendgrid.com/v3/scopes."),
	mp("Mailgun API key", "high", `\bkey-[0-9a-f]{32}\b`, "GET https://api.mailgun.net/v3/domains -u api:KEY."),
	mp("Mailchimp API key", "high", `\b[0-9a-f]{32}-us[0-9]{1,2}\b`, "GET https://<dc>.api.mailchimp.com/3.0/ -u any:KEY."),
	mp("DigitalOcean PAT", "high", `\bdop_v1_[0-9a-f]{64}\b`, "GET https://api.digitalocean.com/v2/account."),
	mp("OpenAI API key", "high", `\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b`, "GET https://api.openai.com/v1/models."),
	mp("OpenAI project key", "high", `\bsk-proj-[A-Za-z0-9_\-]{40,}\b`, "GET https://api.openai.com/v1/models."),
	mp("Anthropic API key", "high", `\bsk-ant-[A-Za-z0-9_\-]{40,}\b`, "POST https://api.anthropic.com/v1/messages."),
	mp("npm access token", "high", `\bnpm_[0-9A-Za-z]{36}\b`, "GET https://registry.npmjs.org/-/whoami with the token."),
	mp("Datadog API key", "high", `(?i)datadog.{0,20}["'` + "`" + `][0-9a-f]{32}["'` + "`" + `]`, "GET https://api.datadoghq.com/api/v1/validate."),
	mp("New Relic key", "high", `\bNRAK-[A-Z0-9]{27}\b`, "Use against the New Relic API."),
	mp("Shopify token", "high", `\bshp(?:at|ca|pa|ss)_[0-9a-fA-F]{32}\b`, "GET /admin/api/2023-01/shop.json with X-Shopify-Access-Token."),
	mp("Discord bot token", "high", `\b[MNO][A-Za-z0-9_\-]{23}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27}\b`, "GET https://discord.com/api/users/@me with Authorization: Bot KEY."),
	mp("Telegram bot token", "high", `\b[0-9]{8,10}:[A-Za-z0-9_\-]{35}\b`, "GET https://api.telegram.org/botKEY/getMe."),
	mp("JWT", "high", `\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`, "Decode and inspect claims; test against the API."),
	mp("Private key block", "critical", `-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`, "Use the key for SSH/TLS authentication."),
	mp("Basic auth in URL", "high", `[a-zA-Z][a-zA-Z0-9+.\-]*://[^/\s:@]+:[^/\s:@]+@`, "Credentials embedded in a URL; try them directly."),
	mp("Generic high-entropy secret", "high", `(?i)\b(?:api[_-]?key|secret|token|passwd|password|access[_-]?token|client[_-]?secret)\b["'` + "`" + `]?\s*[:=]\s*["'` + "`" + `][0-9A-Za-z_\-./+]{16,}["'` + "`" + `]`, "Manually review and test the value."),
}

// Match is a found secret.
type Match struct {
	Pattern  Pattern
	Value    string
	Redacted string
}

func redact(s string) string {
	if len(s) <= 12 {
		if len(s) <= 1 {
			return s
		}
		return s[:1] + "***"
	}
	keep := 4
	out := make([]byte, 0, len(s))
	out = append(out, s[:keep]...)
	for i := keep; i < len(s)-keep; i++ {
		out = append(out, '*')
	}
	out = append(out, s[len(s)-keep:]...)
	return string(out)
}

// Scan returns unique secret matches found in body, capped per pattern.
func Scan(body []byte) []Match {
	var out []Match
	for _, p := range Patterns {
		found := p.Re.FindAll(body, -1)
		if found == nil {
			continue
		}
		seen := map[string]struct{}{}
		count := 0
		for _, m := range found {
			v := string(m)
			if _, ok := seen[v]; ok {
				continue
			}
			seen[v] = struct{}{}
			out = append(out, Match{Pattern: p, Value: v, Redacted: redact(v)})
			count++
			if count >= 5 {
				break
			}
		}
	}
	return out
}