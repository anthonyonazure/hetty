import {
  Alert,
  Box,
  Button,
  Chip,
  CircularProgress,
  MenuItem,
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

interface WordlistInfo {
  name: string;
  category: string;
  description: string;
  size: number;
}

interface Hit {
  url: string;
  status: number;
  length: number;
  depth: number;
  contentType: string;
  redirect?: string;
}

interface DiscoveryResult {
  seed: string;
  hits: Hit[] | null;
  requests: number;
}

function statusColor(status: number): "success" | "warning" | "error" | "info" | "default" {
  if (status >= 200 && status < 300) return "success";
  if (status >= 300 && status < 400) return "info";
  if (status === 401 || status === 403) return "warning";
  if (status >= 400) return "error";
  return "default";
}

export default function Discovery(): JSX.Element {
  const [seed, setSeed] = useState("");
  const [wordlistText, setWordlistText] = useState("");
  const [preset, setPreset] = useState("");
  const [presets, setPresets] = useState<WordlistInfo[]>([]);
  const [extensions, setExtensions] = useState("");
  const [maxDepth, setMaxDepth] = useState("0");
  const [concurrency, setConcurrency] = useState("10");
  const [rps, setRps] = useState("0");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<DiscoveryResult | null>(null);

  useEffect(() => {
    apiGet<{ lists: WordlistInfo[] | null }>("/api/wordlists")
      .then((data) => setPresets((data.lists || []).filter((l) => l.category === "paths")))
      .catch(() => undefined);
  }, []);

  const handleRun = () => {
    setLoading(true);
    setError("");
    const wordlist = wordlistText
      .split("\n")
      .map((w) => w.trim())
      .filter((w) => w !== "");
    const exts = extensions
      .split(",")
      .map((e) => e.trim())
      .filter((e) => e !== "");

    apiPost<DiscoveryResult>("/api/discovery", {
      seed,
      wordlistName: wordlist.length === 0 ? preset : "",
      options: {
        wordlist,
        extensions: exts,
        maxDepth: parseInt(maxDepth, 10) || 0,
        concurrency: parseInt(concurrency, 10) || 10,
        requestsPerSecond: parseFloat(rps) || 0,
      },
    })
      .then(setResult)
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  };

  return (
    <Box>
      <Typography variant="h4" sx={{ mb: 1 }}>
        Content discovery
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        Forced browsing against a seed URL. Leave the wordlist empty to use the built-in common list. Soft-404
        calibration suppresses catch-all pages. Hits feed the site map.
      </Typography>
      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      <TextField
        label="Seed URL"
        fullWidth
        value={seed}
        onChange={(e) => setSeed(e.target.value)}
        placeholder="https://example.com/"
        sx={{ mb: 2 }}
      />
      <Box sx={{ display: "flex", gap: 1, mb: 2, flexWrap: "wrap" }}>
        <TextField
          label="Extensions (comma sep)"
          value={extensions}
          onChange={(e) => setExtensions(e.target.value)}
          placeholder="php,bak,old"
        />
        <TextField
          label="Max depth"
          sx={{ width: 110 }}
          value={maxDepth}
          onChange={(e) => setMaxDepth(e.target.value)}
        />
        <TextField
          label="Concurrency"
          sx={{ width: 120 }}
          value={concurrency}
          onChange={(e) => setConcurrency(e.target.value)}
        />
        <TextField label="Req/sec (0=∞)" sx={{ width: 130 }} value={rps} onChange={(e) => setRps(e.target.value)} />
        <TextField
          select
          label="Preset wordlist"
          sx={{ width: 220 }}
          value={preset}
          onChange={(e) => setPreset(e.target.value)}
          helperText="Used when the box below is empty"
        >
          <MenuItem value="">
            <em>Built-in common</em>
          </MenuItem>
          {presets.map((p) => (
            <MenuItem key={p.name} value={p.name}>
              {p.name} ({p.size})
            </MenuItem>
          ))}
        </TextField>
      </Box>
      <TextField
        label="Wordlist (one per line — overrides preset)"
        fullWidth
        multiline
        minRows={3}
        value={wordlistText}
        onChange={(e) => setWordlistText(e.target.value)}
        sx={{ mb: 2 }}
        InputProps={{ sx: { fontFamily: "'JetBrains Mono', monospace" } }}
      />
      <Button variant="contained" onClick={handleRun} disabled={loading || !seed}>
        {loading ? <CircularProgress size={24} /> : "Discover"}
      </Button>

      {result && (
        <Box sx={{ mt: 2 }}>
          <Alert severity="success" sx={{ mb: 2 }}>
            {(result.hits || []).length} path(s) found in {result.requests} request(s).
          </Alert>
          <TableContainer component={Paper} variant="outlined" sx={{ maxHeight: 500 }}>
            <Table size="small" stickyHeader>
              <TableHead>
                <TableRow>
                  <TableCell>Status</TableCell>
                  <TableCell>URL</TableCell>
                  <TableCell>Length</TableCell>
                  <TableCell>Depth</TableCell>
                  <TableCell>Content type</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {(result.hits || []).map((h) => (
                  <TableRow key={h.url} hover>
                    <TableCell>
                      <Chip size="small" label={h.status} color={statusColor(h.status)} />
                    </TableCell>
                    <TableCell sx={{ fontFamily: "'JetBrains Mono', monospace" }}>
                      {h.url}
                      {h.redirect && ` → ${h.redirect}`}
                    </TableCell>
                    <TableCell>{h.length}</TableCell>
                    <TableCell>{h.depth}</TableCell>
                    <TableCell>{h.contentType}</TableCell>
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
