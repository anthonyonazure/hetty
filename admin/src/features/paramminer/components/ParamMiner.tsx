import {
  Alert,
  Box,
  Button,
  Chip,
  CircularProgress,
  FormControl,
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
import { useState } from "react";

import { apiPost } from "lib/restApi";

interface Finding {
  param: string;
  location: string;
  reason: string;
  status: number;
  length: number;
}

interface Result {
  target: string;
  location: string;
  baselineStatus: number;
  baselineLength: number;
  findings: Finding[] | null;
  requests: number;
}

export default function ParamMiner(): JSX.Element {
  const [target, setTarget] = useState("");
  const [location, setLocation] = useState("query");
  const [wordlistText, setWordlistText] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<Result | null>(null);

  const handleRun = () => {
    setLoading(true);
    setError("");
    const wordlist = wordlistText
      .split("\n")
      .map((w) => w.trim())
      .filter((w) => w !== "");

    apiPost<Result>("/api/paramminer", {
      target,
      options: { location, wordlist, concurrency: 10 },
    })
      .then(setResult)
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  };

  return (
    <Box>
      <Typography variant="h4" sx={{ mb: 1 }}>
        Parameter discovery
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        Brute-forces hidden/unlinked parameters by sending a canary value and watching for reflection or a measurable
        response change versus a calibrated baseline. Leave the wordlist empty to use the built-in list.
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
          placeholder="https://example.com/api/item"
        />
        <FormControl sx={{ width: 140 }}>
          <InputLabel id="pm-location">Location</InputLabel>
          <Select labelId="pm-location" label="Location" value={location} onChange={(e) => setLocation(e.target.value)}>
            <MenuItem value="query">Query</MenuItem>
            <MenuItem value="body">Body</MenuItem>
            <MenuItem value="header">Header</MenuItem>
          </Select>
        </FormControl>
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
      <Button variant="contained" onClick={handleRun} disabled={loading || !target}>
        {loading ? <CircularProgress size={24} /> : "Mine parameters"}
      </Button>

      {result && (
        <Box sx={{ mt: 2 }}>
          <Alert severity={result.findings && result.findings.length > 0 ? "warning" : "info"} sx={{ mb: 2 }}>
            {(result.findings || []).length} hidden parameter(s) found in {result.requests} request(s). Baseline:{" "}
            {result.baselineStatus} ({result.baselineLength} bytes).
          </Alert>
          {(result.findings || []).length > 0 && (
            <TableContainer component={Paper} variant="outlined">
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>Parameter</TableCell>
                    <TableCell>Location</TableCell>
                    <TableCell>Reason</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell>Length</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {(result.findings || []).map((f) => (
                    <TableRow key={f.param} hover>
                      <TableCell sx={{ fontFamily: "'JetBrains Mono', monospace" }}>{f.param}</TableCell>
                      <TableCell>
                        <Chip size="small" label={f.location} variant="outlined" />
                      </TableCell>
                      <TableCell>{f.reason}</TableCell>
                      <TableCell>{f.status}</TableCell>
                      <TableCell>{f.length}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          )}
        </Box>
      )}
    </Box>
  );
}
