import { Alert, Box, Button, Chip, CircularProgress, Divider, Paper, TextField, Typography } from "@mui/material";
import { useEffect, useState } from "react";

import { apiGet, apiPost } from "lib/restApi";

interface Status {
  enabled: boolean;
  model: string;
}

interface PayloadSuggestion {
  payloads: string[] | null;
  notes: string;
}

export default function AIAnalyst(): JSX.Element {
  const [status, setStatus] = useState<Status | null>(null);

  const [vulnClass, setVulnClass] = useState("xss");
  const [url, setUrl] = useState("");
  const [param, setParam] = useState("");
  const [context, setContext] = useState("");
  const [payloadLoading, setPayloadLoading] = useState(false);
  const [payloadError, setPayloadError] = useState("");
  const [suggestion, setSuggestion] = useState<PayloadSuggestion | null>(null);

  const [reportLoading, setReportLoading] = useState(false);
  const [reportError, setReportError] = useState("");
  const [report, setReport] = useState("");

  useEffect(() => {
    apiGet<Status>("/api/ai/status")
      .then(setStatus)
      .catch(() => setStatus({ enabled: false, model: "" }));
  }, []);

  const handleSuggest = () => {
    setPayloadLoading(true);
    setPayloadError("");
    apiPost<PayloadSuggestion>("/api/ai/payloads", { vulnClass, url, param, context })
      .then(setSuggestion)
      .catch((err) => setPayloadError(err.message))
      .finally(() => setPayloadLoading(false));
  };

  const handleReport = () => {
    setReportLoading(true);
    setReportError("");
    setReport("");
    apiPost<{ markdown: string }>("/api/ai/report", {})
      .then((r) => setReport(r.markdown))
      .catch((err) => setReportError(err.message))
      .finally(() => setReportLoading(false));
  };

  const downloadReport = () => {
    const blob = new Blob([report], { type: "text/markdown" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "hetty-ai-report.md";
    a.click();
    URL.revokeObjectURL(a.href);
  };

  return (
    <Box>
      <Typography variant="h4" sx={{ mb: 1 }}>
        AI analyst
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        An LLM-backed assistant that triages findings, suggests payloads, and drafts proof-of-concept reports. Triage is
        available on each scanner issue.
      </Typography>

      {status && !status.enabled && (
        <Alert severity="warning" sx={{ mb: 2 }}>
          The AI analyst is not configured. Start Hetty with <code>--ai-key &lt;key&gt;</code> or set the{" "}
          <code>ANTHROPIC_API_KEY</code> environment variable.
        </Alert>
      )}
      {status && status.enabled && (
        <Alert severity="success" sx={{ mb: 2 }}>
          AI analyst enabled <Chip size="small" label={status.model} sx={{ ml: 1 }} />
        </Alert>
      )}

      <Paper variant="outlined" sx={{ p: 2, mb: 3 }}>
        <Typography variant="h6" sx={{ mb: 1 }}>
          Payload suggester
        </Typography>
        <Box sx={{ display: "flex", gap: 1, mb: 2, flexWrap: "wrap" }}>
          <TextField
            label="Vulnerability class"
            value={vulnClass}
            onChange={(e) => setVulnClass(e.target.value)}
            sx={{ width: 200 }}
            placeholder="xss, sqli, ssti…"
          />
          <TextField
            label="Target URL"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            sx={{ flexGrow: 1, minWidth: 240 }}
          />
          <TextField label="Parameter" value={param} onChange={(e) => setParam(e.target.value)} sx={{ width: 160 }} />
        </Box>
        <TextField
          label="Context (optional — observed behavior, filters, WAF)"
          fullWidth
          value={context}
          onChange={(e) => setContext(e.target.value)}
          sx={{ mb: 2 }}
        />
        <Button variant="contained" onClick={handleSuggest} disabled={payloadLoading || !status?.enabled || !vulnClass}>
          {payloadLoading ? <CircularProgress size={24} /> : "Suggest payloads"}
        </Button>
        {payloadError && (
          <Alert severity="error" sx={{ mt: 2 }}>
            {payloadError}
          </Alert>
        )}
        {suggestion && (
          <Box sx={{ mt: 2 }}>
            {suggestion.notes && (
              <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                {suggestion.notes}
              </Typography>
            )}
            <Paper variant="outlined" sx={{ p: 1.5 }}>
              <Box
                component="pre"
                sx={{ m: 0, whiteSpace: "pre-wrap", fontFamily: "'JetBrains Mono', monospace", fontSize: 13 }}
              >
                {(suggestion.payloads || []).join("\n")}
              </Box>
            </Paper>
          </Box>
        )}
      </Paper>

      <Paper variant="outlined" sx={{ p: 2 }}>
        <Typography variant="h6" sx={{ mb: 1 }}>
          Proof-of-concept report
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          Generates a Markdown report from the current project&apos;s scanner findings.
        </Typography>
        <Box sx={{ display: "flex", gap: 1 }}>
          <Button variant="contained" onClick={handleReport} disabled={reportLoading || !status?.enabled}>
            {reportLoading ? <CircularProgress size={24} /> : "Generate report"}
          </Button>
          {report && (
            <Button variant="outlined" onClick={downloadReport}>
              Download .md
            </Button>
          )}
        </Box>
        {reportError && (
          <Alert severity="error" sx={{ mt: 2 }}>
            {reportError}
          </Alert>
        )}
        {report && (
          <>
            <Divider sx={{ my: 2 }} />
            <Box
              component="pre"
              sx={{
                m: 0,
                whiteSpace: "pre-wrap",
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: 13,
                maxHeight: 500,
                overflow: "auto",
              }}
            >
              {report}
            </Box>
          </>
        )}
      </Paper>
    </Box>
  );
}
