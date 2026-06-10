package template

// builtinTemplates are a handful of high-value detection templates bundled so
// the template scanner is useful without an external template directory. Users
// can add many more (e.g. the nuclei-templates repo) under ~/.hetty/templates.
var builtinYAML = []string{
	`
id: exposed-git-config
info:
  name: Exposed .git/config
  severity: medium
  description: A publicly accessible .git/config can leak source code and history.
requests:
  - method: GET
    path: ["{{BaseURL}}/.git/config"]
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        part: body
        words: ["[core]", "repositoryformatversion"]
        condition: and
`,
	`
id: exposed-env-file
info:
  name: Exposed .env file
  severity: high
  description: A publicly accessible .env file can leak credentials and secrets.
requests:
  - method: GET
    path: ["{{BaseURL}}/.env"]
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: regex
        part: body
        regex: ["(?m)^[A-Z0-9_]+=", "(?i)(secret|key|password|token|db_)"]
        condition: and
`,
	`
id: spring-actuator-exposed
info:
  name: Spring Boot Actuator exposed
  severity: medium
  description: Spring Boot actuator endpoints are exposed and may leak configuration.
requests:
  - method: GET
    path: ["{{BaseURL}}/actuator", "{{BaseURL}}/actuator/health", "{{BaseURL}}/actuator/env"]
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        part: body
        words: ["\"status\":", "_links", "diskSpace", "propertySources"]
        condition: or
`,
	`
id: phpinfo-exposed
info:
  name: phpinfo() page exposed
  severity: low
  description: A phpinfo() page discloses PHP configuration and server details.
requests:
  - method: GET
    path: ["{{BaseURL}}/phpinfo.php", "{{BaseURL}}/info.php", "{{BaseURL}}/test.php"]
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        part: body
        words: ["PHP Version", "phpinfo()"]
        condition: or
`,
	`
id: open-redirect-common
info:
  name: Directory listing enabled
  severity: low
  description: Server directory listing is enabled, exposing file names.
requests:
  - method: GET
    path: ["{{BaseURL}}/uploads/", "{{BaseURL}}/files/", "{{BaseURL}}/backup/"]
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        part: body
        words: ["Index of /", "Directory listing for", "<title>Index of"]
        condition: or
`,
}

// Builtins returns the parsed built-in templates.
func Builtins() []*Template {
	var out []*Template
	for _, y := range builtinYAML {
		if t, err := Parse([]byte(y)); err == nil {
			out = append(out, t)
		}
	}
	return out
}
