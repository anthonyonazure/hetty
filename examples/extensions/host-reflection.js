// host-reflection.js — demonstrates a custom active scan check.
// Injects a marker host value and detects if it is reflected in the response.
hetty.meta({
  name: "host-reflection",
  version: "1.0.0",
  description: "Detects reflection of injected host/parameter values.",
});

hetty.registerActiveCheck({
  id: "reflected-host",
  name: "Reflected value",
  severity: "medium",
  payloads: ["hettymarker12345"],
  detect: function (payload, res, baseline) {
    if (res.body && res.body.indexOf(payload) !== -1) {
      return {
        name: "Injected value reflected",
        severity: "medium",
        confidence: "firm",
        evidence: payload,
      };
    }
    return null;
  },
});
