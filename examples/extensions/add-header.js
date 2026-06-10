// add-header.js — demonstrates request hooks.
// Adds a custom header to every proxied request and logs the request line.
hetty.meta({
  name: "add-header",
  version: "1.0.0",
  description: "Adds an X-Hetty-Scan header to outgoing requests and logs them.",
});

hetty.on("request", function (req) {
  req.headers["X-Hetty-Scan"] = "1";
  hetty.log(req.method + " " + req.url);
});

hetty.on("response", function (res, req) {
  res.headers["X-Scanned-By"] = "hetty";
});
