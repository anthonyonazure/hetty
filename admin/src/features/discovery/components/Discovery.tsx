import {
  Alert,
  Box,
  Button,
  Chip,
  CircularProgress,
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
import { useState } from "react";

import { apiPost } from "lib/restApi";

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
  const [extensions, setExtensions] = useState("");
  const [maxDepth, setMaxDepth] = useState("0");
  const [concurrency, setConcurrency] = useState("10");
  const [rps, setRps] = useState("0");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<DiscoveryResult | null>(null);

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
      </Box>
      <TextField
        label="Wordlist (one per line, optional)"
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
