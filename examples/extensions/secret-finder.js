// secret-finder.js — demonstrates a custom passive scan check.
// Flags common leaked credentials in HTTP responses.
hetty.meta({
  name: "secret-finder",
  version: "1.0.0",
  description: "Flags leaked tokens and keys in responses.",
});

var patterns = [
  { name: "AWS access key", re: /AKIA[0-9A-Z]{16}/ },
  { name: "Bearer token", re: /Bearer\s+[A-Za-z0-9\-_.=]{20,}/ },
  { name: "Private key block", re: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/ },
  { name: "Google API key", re: /AIza[0-9A-Za-z\-_]{35}/ },
];

hetty.registerPassiveCheck({
  id: "leaked-secrets",
  name: "Leaked secret in response",
  run: function (req, res) {
    var found = [];
    for (var i = 0; i < patterns.length; i++) {
      var m = res.body.match(patterns[i].re);
      if (m) {
        found.push({
          name: "Leaked secret: " + patterns[i].name,
          severity: "high",
          confidence: "firm",
          evidence: String(m[0]).slice(0, 40),
        });
      }
    }
    return found;
  },
});
