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

interface Finding {
  technique: string;
  baselineMs: number;
  probeMs: number;
  timedOut: boolean;
  detail: string;
}

interface Result {
  target: string;
  vulnerable: boolean;
  baselineMs: number;
  findings: Finding[] | null;
  note: string;
}

export default function Smuggle(): JSX.Element {
  const [target, setTarget] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<Result | null>(null);

  const handleProbe = () => {
    setLoading(true);
    setError("");
    apiPost<Result>("/api/smuggle", { target, options: {} })
      .then(setResult)
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  };

  return (
    <Box>
      <Typography variant="h4" sx={{ mb: 1 }}>
        Request smuggling probe
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        Timing-based CL.TE / TE.CL desync detection. Sends raw requests with conflicting Content-Length and
        Transfer-Encoding headers and watches for a hang. Only run against authorized targets; confirm any hit manually.
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
          placeholder="https://example.com/"
        />
        <Button variant="contained" onClick={handleProbe} disabled={loading || !target} sx={{ whiteSpace: "nowrap" }}>
          {loading ? <CircularProgress size={24} /> : "Probe"}
        </Button>
      </Box>

      {result && (
        <Box sx={{ mt: 1 }}>
          <Alert severity={result.vulnerable ? "error" : "success"} sx={{ mb: 2 }}>
            {result.note} (baseline {result.baselineMs}ms)
          </Alert>
          <TableContainer component={Paper} variant="outlined">
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Technique</TableCell>
                  <TableCell>Baseline</TableCell>
                  <TableCell>Probe</TableCell>
                  <TableCell>Timed out</TableCell>
                  <TableCell>Detail</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {(result.findings || []).map((f) => (
                  <TableRow key={f.technique} hover>
                    <TableCell>
                      <Chip
                        size="small"
                        label={f.technique}
                        color={f.detail.includes("desync") ? "error" : "default"}
                      />
                    </TableCell>
                    <TableCell>{f.baselineMs}ms</TableCell>
                    <TableCell>{f.probeMs}ms</TableCell>
                    <TableCell>{f.timedOut ? "yes" : "no"}</TableCell>
                    <TableCell>{f.detail}</TableCell>
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
