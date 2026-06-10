# Hetty extensions

Hetty extensions are plain JavaScript files executed in an embedded, pure-Go
ECMAScript runtime. Drop `*.js` files into `~/.hetty/extensions` (created on
first run) and reload them from the **Extensions** tab in the web UI or via:

    curl -X POST http://localhost:8080/api/extensions/reload

## The `hetty` host API

| Function | Purpose |
| --- | --- |
| `hetty.meta({name, version, description})` | Set extension metadata. |
| `hetty.log(...args)` | Write to the Hetty log. |
| `hetty.on("request", fn)` | Hook every proxied request. `fn(req)` may mutate `req.method`, `req.headers`, `req.body`. |
| `hetty.on("response", fn)` | Hook every proxied response. `fn(res, req)` may mutate `res.status`, `res.headers`, `res.body`. |
| `hetty.send({method, url, headers, body})` | Send an HTTP request from the host; returns `{status, statusText, headers, body}`. |
| `hetty.registerPassiveCheck({id, name, run})` | Add a passive scan check. `run(req, res)` returns an issue, an array of issues, or null. |
| `hetty.registerActiveCheck({id, name, severity, payloads, detect})` | Add an active scan check. For each payload, `detect(payload, res, baseline)` returns an issue or null. |
| `hetty.raiseIssue({name, severity, confidence, description, evidence})` | Record an issue from a hook. |

An issue object accepts: `name`, `severity` (info/low/medium/high/critical),
`confidence` (tentative/firm/certain), `description`, `remediation`, `evidence`.

## Examples in this directory

- **add-header.js** — request/response hooks (adds headers, logs traffic).
- **secret-finder.js** — a custom passive check that flags leaked credentials.
- **host-reflection.js** — a custom active check that detects reflected input.

Copy any of these into `~/.hetty/extensions` and reload.
