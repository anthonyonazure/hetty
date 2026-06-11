import { TabContext, TabList, TabPanel } from "@mui/lab";
import {
  Alert,
  Box,
  Button,
  CircularProgress,
  FormControlLabel,
  Paper,
  Switch,
  Tab,
  TextField,
  Typography,
} from "@mui/material";
import { useState } from "react";

import { apiPost } from "lib/restApi";

function parseHeaders(text: string): { name: string; value: string }[] {
  return text
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l !== "" && l.includes(":"))
    .map((l) => {
      const idx = l.indexOf(":");
      return { name: l.slice(0, idx).trim(), value: l.slice(idx + 1).trim() };
    });
}

function Output({ html }: { html: string }): JSX.Element {
  return (
    <Box sx={{ mt: 2 }}>
      <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
        <Typography variant="subtitle2">Generated PoC</Typography>
        <Button size="small" onClick={() => navigator.clipboard.writeText(html)}>
          Copy HTML
        </Button>
      </Box>
      <Paper
        variant="outlined"
        sx={{ p: 2, maxHeight: 400, overflow: "auto", fontFamily: "'JetBrains Mono', monospace", fontSize: 12 }}
      >
        <pre style={{ margin: 0, whiteSpace: "pre-wrap" }}>{html}</pre>
      </Paper>
    </Box>
  );
}

export default function PoC(): JSX.Element {
  const [tab, setTab] = useState("csrf");

  // CSRF state
  const [method, setMethod] = useState("POST");
  const [url, setUrl] = useState("");
  const [contentType, setContentType] = useState("application/x-www-form-urlencoded");
  const [headers, setHeaders] = useState("");
  const [body, setBody] = useState("");
  const [autoSubmit, setAutoSubmit] = useState(true);
  const [csrfLoading, setCsrfLoading] = useState(false);
  const [csrfError, setCsrfError] = useState("");
  const [csrfHtml, setCsrfHtml] = useState("");

  // Clickjacking state
  const [cjUrl, setCjUrl] = useState("");
  const [cjLoading, setCjLoading] = useState(false);
  const [cjError, setCjError] = useState("");
  const [cjHtml, setCjHtml] = useState("");

  const genCsrf = () => {
    setCsrfLoading(true);
    setCsrfError("");
    setCsrfHtml("");
    apiPost<{ html: string }>("/api/poc/csrf", {
      method,
      url,
      contentType,
      headers: parseHeaders(headers),
      body,
      autoSubmit,
    })
      .then((d) => setCsrfHtml(d.html))
      .catch((err) => setCsrfError(err.message))
      .finally(() => setCsrfLoading(false));
  };

  const genCj = () => {
    setCjLoading(true);
    setCjError("");
    setCjHtml("");
    apiPost<{ html: string }>("/api/poc/clickjacking", { url: cjUrl })
      .then((d) => setCjHtml(d.html))
      .catch((err) => setCjError(err.message))
      .finally(() => setCjLoading(false));
  };

  return (
    <Box>
      <Typography variant="h4" sx={{ mb: 1 }}>
        PoC generators
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        Generate proof-of-concept HTML pages: a self-submitting CSRF request, or a clickjacking overlay for a target
        that lacks framing protection.
      </Typography>

      <TabContext value={tab}>
        <TabList onChange={(_, v) => setTab(v)}>
          <Tab label="CSRF" value="csrf" />
          <Tab label="Clickjacking" value="clickjacking" />
        </TabList>

        <TabPanel value="csrf" sx={{ px: 0 }}>
          {csrfError && (
            <Alert severity="error" sx={{ mb: 2 }}>
              {csrfError}
            </Alert>
          )}
          <Box sx={{ display: "flex", gap: 1, mb: 2 }}>
            <TextField label="Method" sx={{ width: 120 }} value={method} onChange={(e) => setMethod(e.target.value)} />
            <TextField
              label="Target URL"
              fullWidth
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://victim.example/account"
            />
          </Box>
          <TextField
            label="Content-Type"
            fullWidth
            value={contentType}
            onChange={(e) => setContentType(e.target.value)}
            sx={{ mb: 2 }}
          />
          <TextField
            label="Headers (Name: Value per line)"
            fullWidth
            multiline
            minRows={2}
            value={headers}
            onChange={(e) => setHeaders(e.target.value)}
            sx={{ mb: 2 }}
            InputProps={{ sx: { fontFamily: "'JetBrains Mono', monospace", fontSize: 13 } }}
          />
          <TextField
            label="Request body"
            fullWidth
            multiline
            minRows={3}
            value={body}
            onChange={(e) => setBody(e.target.value)}
            sx={{ mb: 2 }}
            InputProps={{ sx: { fontFamily: "'JetBrains Mono', monospace", fontSize: 13 } }}
          />
          <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
            <Button variant="contained" onClick={genCsrf} disabled={csrfLoading || !url}>
              {csrfLoading ? <CircularProgress size={24} /> : "Generate CSRF PoC"}
            </Button>
            <FormControlLabel
              control={<Switch checked={autoSubmit} onChange={(e) => setAutoSubmit(e.target.checked)} />}
              label="Auto-submit on load"
            />
          </Box>
          {csrfHtml && <Output html={csrfHtml} />}
        </TabPanel>

        <TabPanel value="clickjacking" sx={{ px: 0 }}>
          {cjError && (
            <Alert severity="error" sx={{ mb: 2 }}>
              {cjError}
            </Alert>
          )}
          <Box sx={{ display: "flex", gap: 1, mb: 2 }}>
            <TextField
              label="Target URL"
              fullWidth
              value={cjUrl}
              onChange={(e) => setCjUrl(e.target.value)}
              placeholder="https://victim.example/admin"
            />
            <Button variant="contained" onClick={genCj} disabled={cjLoading || !cjUrl} sx={{ whiteSpace: "nowrap" }}>
              {cjLoading ? <CircularProgress size={24} /> : "Generate"}
            </Button>
          </Box>
          {cjHtml && <Output html={cjHtml} />}
        </TabPanel>
      </TabContext>
    </Box>
  );
}
