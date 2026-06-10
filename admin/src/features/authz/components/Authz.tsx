import {
  Alert,
  Box,
  Button,
  Checkbox,
  Chip,
  CircularProgress,
  FormControl,
  FormControlLabel,
  InputLabel,
  MenuItem,
  Paper,
  Select,
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

import { consumeHandoff } from "lib/handoff";
import { apiGet, apiPost } from "lib/restApi";

interface Profile {
  name: string;
}

interface IdentityResult {
  label: string;
  status: number;
  length: number;
  similarity: number;
  verdict: string;
  note: string;
  durationMs: number;
  error?: string;
}

interface AuthzResult {
  baseline: { status: number; length: number };
  identities: IdentityResult[] | null;
}

function verdictColor(v: string): "error" | "success" | "warning" | "default" {
  switch (v) {
    case "bypassed":
      return "error";
    case "enforced":
      return "success";
    case "ambiguous":
      return "warning";
    default:
      return "default";
  }
}

function parseHeaderLines(text: string): { name: string; value: string }[] {
  const out: { name: string; value: string }[] = [];
  for (const line of text.split("\n")) {
    const idx = line.indexOf(":");
    if (idx > 0) {
      out.push({ name: line.slice(0, idx).trim(), value: line.slice(idx + 1).trim() });
    }
  }
  return out;
}

export default function Authz(): JSX.Element {
  const [method, setMethod] = useState("GET");
  const [url, setUrl] = useState("");
  const [headersText, setHeadersText] = useState("");
  const [body, setBody] = useState("");
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [selectedProfiles, setSelectedProfiles] = useState<string[]>([]);
  const [includeUnauth, setIncludeUnauth] = useState(true);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<AuthzResult | null>(null);

  useEffect(() => {
    apiGet<{ profiles: Profile[] | null }>("/api/session/profiles")
      .then((data) => setProfiles(data.profiles || []))
      .catch(() => undefined);

    const h = consumeHandoff("authz");
    if (h) {
      setMethod(h.method || "GET");
      setUrl(h.url || "");
      setHeadersText(h.headers || "");
      setBody(h.body || "");
    }
  }, []);

  const handleRun = () => {
    setLoading(true);
    setError("");
    setResult(null);

    const identities: { label: string; profile: string }[] = selectedProfiles.map((p) => ({
      label: p,
      profile: p,
    }));
    if (includeUnauth) {
      identities.push({ label: "unauthenticated", profile: "" });
    }

    apiPost<AuthzResult>("/api/authz/analyze", {
      base: { method, url, proto: "", headers: parseHeaderLines(headersText), body },
      identities,
    })
      .then(setResult)
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  };

  return (
    <Box>
      <Typography variant="h4" sx={{ mb: 1 }}>
        Authorization tester
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        Replays a privileged request under other identities to find broken access control (IDOR / BOLA). Put the
        privileged session in the headers below, pick the identities to test, and run.
      </Typography>
      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      <Box sx={{ display: "flex", gap: 1, mb: 2 }}>
        <FormControl sx={{ width: 120 }}>
          <InputLabel id="authz-method">Method</InputLabel>
          <Select labelId="authz-method" label="Method" value={method} onChange={(e) => setMethod(e.target.value)}>
            {["GET", "POST", "PUT", "PATCH", "DELETE"].map((m) => (
              <MenuItem key={m} value={m}>
                {m}
              </MenuItem>
            ))}
          </Select>
        </FormControl>
        <TextField
          label="URL"
          fullWidth
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://example.com/api/account/42"
        />
      </Box>
      <TextField
        label="Headers — privileged identity (one per line, Name: value)"
        fullWidth
        multiline
        minRows={3}
        value={headersText}
        onChange={(e) => setHeadersText(e.target.value)}
        sx={{ mb: 2 }}
        InputProps={{ sx: { fontFamily: "'JetBrains Mono', monospace" } }}
      />
      <TextField
        label="Body"
        fullWidth
        multiline
        minRows={2}
        value={body}
        onChange={(e) => setBody(e.target.value)}
        sx={{ mb: 2 }}
        InputProps={{ sx: { fontFamily: "'JetBrains Mono', monospace" } }}
      />

      <Paper variant="outlined" sx={{ p: 2, mb: 2 }}>
        <Typography variant="subtitle2" sx={{ mb: 1 }}>
          Identities to test
        </Typography>
        <FormControl sx={{ minWidth: 280, mr: 2 }}>
          <InputLabel id="authz-profiles">Auth profiles</InputLabel>
          <Select
            labelId="authz-profiles"
            label="Auth profiles"
            multiple
            value={selectedProfiles}
            onChange={(e) =>
              setSelectedProfiles(typeof e.target.value === "string" ? [e.target.value] : e.target.value)
            }
            renderValue={(selected) => selected.join(", ")}
          >
            {profiles.map((p) => (
              <MenuItem key={p.name} value={p.name}>
                {p.name}
              </MenuItem>
            ))}
            {profiles.length === 0 && (
              <MenuItem disabled value="">
                No profiles — create some under Auth Profiles
              </MenuItem>
            )}
          </Select>
        </FormControl>
        <FormControlLabel
          control={<Checkbox checked={includeUnauth} onChange={(e) => setIncludeUnauth(e.target.checked)} />}
          label="Unauthenticated"
        />
      </Paper>

      <Button
        variant="contained"
        onClick={handleRun}
        disabled={loading || !url || (selectedProfiles.length === 0 && !includeUnauth)}
      >
        {loading ? <CircularProgress size={24} /> : "Run analysis"}
      </Button>

      {result && (
        <Box sx={{ mt: 2 }}>
          <Alert severity="info" sx={{ mb: 2 }}>
            Privileged baseline: status {result.baseline.status}, {result.baseline.length} bytes.
          </Alert>
          <TableContainer component={Paper} variant="outlined">
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Identity</TableCell>
                  <TableCell>Verdict</TableCell>
                  <TableCell>Status</TableCell>
                  <TableCell>Length</TableCell>
                  <TableCell>Similarity</TableCell>
                  <TableCell>Note</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {(result.identities || []).map((id) => (
                  <TableRow key={id.label} hover>
                    <TableCell>{id.label}</TableCell>
                    <TableCell>
                      <Chip size="small" label={id.verdict} color={verdictColor(id.verdict)} />
                    </TableCell>
                    <TableCell>{id.status}</TableCell>
                    <TableCell>{id.length}</TableCell>
                    <TableCell>{(id.similarity * 100).toFixed(0)}%</TableCell>
                    <TableCell>{id.error ? `error: ${id.error}` : id.note}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
          <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: "block" }}>
            <strong>bypassed</strong> = access control NOT enforced (likely a finding). <strong>enforced</strong> =
            properly denied. <strong>ambiguous</strong> = review manually.
          </Typography>
        </Box>
      )}
    </Box>
  );
}
