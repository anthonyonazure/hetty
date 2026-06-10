import {
  Alert,
  Box,
  Button,
  Chip,
  CircularProgress,
  Divider,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TextField,
  Typography,
} from "@mui/material";
import { useEffect, useState } from "react";

import { apiGet, apiPost } from "lib/restApi";

interface TemplateInfo {
  id: string;
  name: string;
  severity: string;
  description: string;
}

interface MatchResult {
  templateId: string;
  name: string;
  severity: string;
  matchedUrl: string;
  description?: string;
}

function severityColor(s: string): "error" | "warning" | "info" | "success" | "default" {
  switch (s) {
    case "critical":
    case "high":
      return "error";
    case "medium":
      return "warning";
    case "low":
      return "info";
    default:
      return "default";
  }
}

export default function Templates(): JSX.Element {
  const [templates, setTemplates] = useState<TemplateInfo[]>([]);
  const [target, setTarget] = useState("");
  const [inline, setInline] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [results, setResults] = useState<MatchResult[] | null>(null);

  useEffect(() => {
    apiGet<{ templates: TemplateInfo[] | null }>("/api/template")
      .then((data) => setTemplates(data.templates || []))
      .catch(() => undefined);
  }, []);

  const handleRun = () => {
    setLoading(true);
    setError("");
    setResults(null);
    const body: Record<string, unknown> = { target };
    if (inline.trim()) {
      body.template = inline;
    }
    apiPost<{ results: MatchResult[] | null; templatesRun: number }>("/api/template/run", body)
      .then((data) => setResults(data.results || []))
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  };

  return (
    <Box>
      <Typography variant="h4" sx={{ mb: 1 }}>
        Templated scanner
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        Runs nuclei-style YAML detection templates against a target. Built-in templates are loaded automatically; add
        more under <code>~/.hetty/templates</code>, or paste an inline template below.
      </Typography>
      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      <Box sx={{ display: "flex", gap: 1, mb: 2 }}>
        <TextField
          label="Target URL"
          fullWidth
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          placeholder="https://example.com"
        />
        <Button variant="contained" onClick={handleRun} disabled={loading || !target} sx={{ whiteSpace: "nowrap" }}>
          {loading ? <CircularProgress size={24} /> : "Run templates"}
        </Button>
      </Box>
      <TextField
        label="Inline template (optional YAML — runs only this template)"
        fullWidth
        multiline
        minRows={3}
        value={inline}
        onChange={(e) => setInline(e.target.value)}
        sx={{ mb: 2 }}
        InputProps={{ sx: { fontFamily: "'JetBrains Mono', monospace", fontSize: 13 } }}
      />

      {results && (
        <Box sx={{ mb: 3 }}>
          <Alert severity={results.length > 0 ? "warning" : "success"} sx={{ mb: 2 }}>
            {results.length} template(s) matched.
          </Alert>
          {results.length > 0 && (
            <TableContainer component={Paper} variant="outlined">
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>Severity</TableCell>
                    <TableCell>Template</TableCell>
                    <TableCell>Matched URL</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {results.map((res) => (
                    <TableRow key={res.templateId + res.matchedUrl} hover>
                      <TableCell>
                        <Chip size="small" label={res.severity} color={severityColor(res.severity)} />
                      </TableCell>
                      <TableCell>{res.name}</TableCell>
                      <TableCell sx={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12 }}>
                        {res.matchedUrl}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          )}
        </Box>
      )}

      <Divider sx={{ my: 2 }} />
      <Typography variant="h6" sx={{ mb: 1 }}>
        Loaded templates ({templates.length})
      </Typography>
      <TableContainer component={Paper} variant="outlined">
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>ID</TableCell>
              <TableCell>Name</TableCell>
              <TableCell>Severity</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {templates.map((t) => (
              <TableRow key={t.id} hover>
                <TableCell sx={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12 }}>{t.id}</TableCell>
                <TableCell>{t.name}</TableCell>
                <TableCell>
                  <Chip size="small" label={t.severity} color={severityColor(t.severity)} />
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
    </Box>
  );
}
