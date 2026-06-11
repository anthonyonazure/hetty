// toolbox.js — demonstrates Hetty's expanded extension API:
// persistence, a send-to action, Intruder payload generator + processor,
// and reading proxy history.

hetty.meta({
  name: "toolbox",
  version: "1.0.0",
  description: "Example: persistence, actions, payload hooks, history.",
});

// --- Persistence: count how many requests we've hooked, across restarts. ----
hetty.on("request", function (req) {
  var n = parseInt(hetty.store.get("seen") || "0", 10) + 1;
  hetty.store.set("seen", "" + n);
});

// --- A send-to/context action. The UI/REST can invoke it on a request. ------
// Returns a curl command line for the given request.
hetty.registerAction({
  id: "to-curl",
  name: "Copy as curl",
  run: function (req) {
    var parts = ["curl -i -X " + (req.method || "GET")];
    var headers = req.headers || {};
    for (var k in headers) {
      parts.push("-H '" + k + ": " + headers[k] + "'");
    }
    if (req.body) {
      parts.push("--data '" + req.body + "'");
    }
    parts.push("'" + req.url + "'");
    return parts.join(" ");
  },
});

// --- An Intruder payload generator: common admin path suffixes. -------------
// Reference it in a payload set as "@gen:ext:toolbox:admin-paths".
hetty.registerPayloadGenerator({
  id: "admin-paths",
  generate: function () {
    return ["admin", "administrator", "admin.php", "wp-admin", "manage", "console"];
  },
});

// --- An Intruder payload processor: double-URL-encode. ----------------------
// Reference it in an attack's processors as "ext:toolbox:double-url".
hetty.registerPayloadProcessor({
  id: "double-url",
  process: function (payload) {
    return encodeURIComponent(encodeURIComponent(payload));
  },
});

hetty.log("toolbox extension loaded");
