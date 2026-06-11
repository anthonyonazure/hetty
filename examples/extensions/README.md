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
| `hetty.store.get/set/delete(key[, value])`, `hetty.store.keys()` | Persisted, per-extension key/value storage (survives restarts). Values are strings. |
| `hetty.history({limit, host, method})` | Read recent proxy history: `[{method, url, status, contentType, length}]`. |
| `hetty.sitemap()` | Read the discovered sitemap: `[{url, methods, statuses, params}]`. |
| `hetty.collab.generate()` / `hetty.collab.interactions(token)` | Mint an OOB collaborator payload and poll its interactions. |
| `hetty.registerAction({id, name, run})` | Register a send-to/context action. `run(request)` returns a string shown in the UI. |
| `hetty.registerPayloadProcessor({id, process})` | Add an Intruder payload processor. Reference it in an attack's `processors` as `ext:<extName>:<id>`. |
| `hetty.registerPayloadGenerator({id, generate})` | Add an Intruder payload generator. Reference it in a payload set as `@gen:ext:<extName>:<id>`. |

An issue object accepts: `name`, `severity` (info/low/medium/high/critical),
`confidence` (tentative/firm/certain), `description`, `remediation`, `evidence`.

> **Burp compatibility:** Hetty does not run Burp `.jar`/`.bapp` extensions or
> Jython `.py` files — those are JVM/Burp-API bound. Port the logic to a `.js`
> extension using the API above (most hooks map 1:1 onto Burp's listener,
> scanner-check, and payload-processor interfaces).

## Examples in this directory

- **add-header.js** — request/response hooks (adds headers, logs traffic).
- **secret-finder.js** — a custom passive check that flags leaked credentials.
- **host-reflection.js** — a custom active check that detects reflected input.
- **toolbox.js** — the expanded API: persistence, a send-to action, an Intruder
  payload generator + processor, and reading proxy history.

Copy any of these into `~/.hetty/extensions` and reload.
