import {
  Alert,
  Box,
  Button,
  Chip,
  CircularProgress,
  Divider,
  List,
  ListItemButton,
  ListItemText,
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

import { apiDelete, apiGet, apiPost, apiPut } from "lib/restApi";

interface Macro {
  name: string;
  steps: unknown[];
  extractors: unknown[];
}

interface MacroResult {
  vars: Record<string, string>;
  cookies: { name: string; value: string }[] | null;
  steps: { url: string; status: number; error?: string }[] | null;
}

const EXAMPLE = `{
  "steps": [
    { "method": "GET", "url": "https://target.example/login" },
    { "method": "POST", "url": "https://target.example/login",
      "headers": [{ "name": "Content-Type", "value": "application/x-www-form-urlencoded" }],
      "body": "user=admin&pass=secret&csrf={{csrf}}" }
  ],
  "extractors": [
    { "name": "csrf", "source": "body", "pattern": "name=\\"csrf\\" value=\\"([^\\"]+)\\"" },
    { "name": "session", "source": "cookie", "key": "session" }
  ]
}`;

export default function Macros(): JSX.Element {
  const [macros, setMacros] = useState<Macro[]>([]);
  const [name, setName] = useState("");
  const [definition, setDefinition] = useState(EXAMPLE);
  const [saveAs, setSaveAs] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [info, setInfo] = useState("");
  const [result, setResult] = useState<MacroResult | null>(null);

  const refresh = () => {
    apiGet<{ macros: Macro[] | null }>("/api/macros")
      .then((d) => setMacros(d.macros || []))
      .catch(() => undefined);
  };

  useEffect(refresh, []);

  function buildMacro(): Record<string, unknown> | null {
    try {
      const parsed = JSON.parse(definition);
      return { name, steps: parsed.steps || [], extractors: parsed.extractors || [] };
    } catch (e) {
      setError("Invalid JSON: " + (e as Error).message);
      return null;
    }
  }

  const handleSave = () => {
    setError("");
    setInfo("");
    const macro = buildMacro();
    if (!macro) return;
    apiPut("/api/macros", macro)
      .then(() => {
        setInfo(`Saved macro "${name}".`);
        refresh();
      })
      .catch((err) => setError(err.message));
  };

  const handleRun = () => {
    setError("");
    setInfo("");
    setResult(null);
    const macro = buildMacro();
    if (!macro) return;
    setLoading(true);
    apiPost<MacroResult>("/api/macros/run", { macro, saveAs: saveAs || undefined })
      .then((r) => {
        setResult(r);
        if (saveAs) setInfo(`Saved result as session profile "${saveAs}".`);
      })
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  };

  const handleDelete = (n: string) => {
    apiDelete(`/api/macros?name=${encodeURIComponent(n)}`)
      .then(refresh)
      .catch((err) => setError(err.message));
  };

  const loadMacro = (m: Macro) => {
    setName(m.name);
    setDefinition(JSON.stringify({ steps: m.steps, extractors: m.extractors }, null, 2));
  };

  return (
    <Box>
      <Typography variant="h4" sx={{ mb: 1 }}>
        Session macros
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        Run a login sequence with a shared cookie jar, extracting CSRF tokens, session cookies and bearer tokens. Later
        steps reference earlier extractions with <code>{"{{name}}"}</code>. Save the result as a session profile to keep
        the scanner, intruder and sender authenticated.
      </Typography>
      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}
      {info && (
        <Alert severity="success" sx={{ mb: 2 }}>
          {info}
        </Alert>
      )}

      <Box sx={{ display: "flex", gap: 2 }}>
        <Box sx={{ flex: 1 }}>
          <TextField
            label="Macro name"
            fullWidth
            value={name}
            onChange={(e) => setName(e.target.value)}
            sx={{ mb: 2 }}
          />
          <TextField
            label="Definition (steps + extractors, JSON)"
            fullWidth
            multiline
            minRows={12}
            value={definition}
            onChange={(e) => setDefinition(e.target.value)}
            sx={{ mb: 2 }}
            InputProps={{ sx: { fontFamily: "'JetBrains Mono', monospace", fontSize: 12 } }}
          />
          <Box sx={{ display: "flex", gap: 1, alignItems: "center", flexWrap: "wrap" }}>
            <Button variant="outlined" onClick={handleSave} disabled={!name}>
              Save
            </Button>
            <Button variant="contained" onClick={handleRun} disabled={loading}>
              {loading ? <CircularProgress size={24} /> : "Run"}
            </Button>
            <TextField
              label="Save result as profile"
              value={saveAs}
              onChange={(e) => setSaveAs(e.target.value)}
              sx={{ width: 240 }}
              placeholder="(optional) profile name"
            />
          </Box>
        </Box>

        <Box sx={{ width: 240 }}>
          <Typography variant="subtitle2" sx={{ mb: 1 }}>
            Saved macros
          </Typography>
          <Paper variant="outlined">
            <List dense>
              {macros.map((m) => (
                <ListItemButton key={m.name} onClick={() => loadMacro(m)}>
                  <ListItemText primary={m.name} secondary={`${(m.steps || []).length} step(s)`} />
                  <Button
                    size="small"
                    color="error"
                    onClick={(e) => {
                      e.stopPropagation();
                      handleDelete(m.name);
                    }}
                  >
                    Delete
                  </Button>
                </ListItemButton>
              ))}
              {macros.length === 0 && (
                <Box sx={{ p: 2 }}>
                  <Typography variant="body2" color="text.secondary">
                    No saved macros.
                  </Typography>
                </Box>
              )}
            </List>
          </Paper>
        </Box>
      </Box>

      {result && (
        <Box sx={{ mt: 3 }}>
          <Divider sx={{ mb: 2 }} />
          <Typography variant="h6" sx={{ mb: 1 }}>
            Result
          </Typography>
          <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mb: 2 }}>
            {Object.entries(result.vars || {}).map(([k, v]) => (
              <Chip key={k} label={`${k} = ${v}`} color="primary" variant="outlined" size="small" />
            ))}
            {(result.cookies || []).map((c) => (
              <Chip key={c.name} label={`🍪 ${c.name}`} size="small" />
            ))}
          </Box>
          <TableContainer component={Paper} variant="outlined">
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Step URL</TableCell>
                  <TableCell>Status</TableCell>
                  <TableCell>Error</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {(result.steps || []).map((s, i) => (
                  <TableRow key={i} hover>
                    <TableCell sx={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12 }}>{s.url}</TableCell>
                    <TableCell>{s.status}</TableCell>
                    <TableCell>{s.error}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </Box>
      )}
    </Box>
  );
}
