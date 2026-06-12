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

import { apiDelete, apiGet, apiPost, apiPut } from "lib/restApi";

interface Worker {
  name: string;
  url: string;
  token?: string;
}
interface Task {
  target: string;
  worker: string;
  kind: string;
  status: string;
  error?: string;
}
interface RunResult {
  kind: string;
  targets: number;
  workers: number;
  ok: number;
  failed: number;
  tasks: Task[] | null;
}

const KINDS = ["portscan", "subdomains", "fingerprint", "tlsscan", "wafdetect"];

export default function Distributed(): JSX.Element {
  const [workers, setWorkers] = useState<Worker[]>([]);
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [token, setToken] = useState("");
  const [targets, setTargets] = useState("");
  const [kind, setKind] = useState("portscan");
  const [running, setRunning] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<RunResult | null>(null);

  const refresh = () => {
    apiGet<{ workers: Worker[] | null }>("/api/cluster/workers")
      .then((d) => setWorkers(d.workers || []))
      .catch(() => undefined);
  };
  useEffect(refresh, []);

  const addWorker = () => {
    setError("");
    apiPut("/api/cluster/workers", { name, url, token })
      .then(() => {
        setName("");
        setUrl("");
        setToken("");
        refresh();
      })
      .catch((e) => setError(e.message));
  };

  const del = (n: string) => apiDelete(`/api/cluster/workers?name=${encodeURIComponent(n)}`).then(refresh);

  const run = () => {
    setRunning(true);
    setError("");
    setResult(null);
    const list = targets
      .split(/[\n,]/)
      .map((t) => t.trim())
      .filter((t) => t !== "");
    apiPost<RunResult>("/api/cluster/run", { targets: list, kind })
      .then(setResult)
      .catch((e) => setError(e.message))
      .finally(() => setRunning(false));
  };

  return (
    <Box>
      <Typography variant="h4" sx={{ mb: 1 }}>
        Distributed scanning
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        Fan a target list out across worker nodes — each just another Hetty instance reachable over the network (spin
        them up however you like: cloud, Axiom, manual). The controller round-robins targets across the workers and
        aggregates the results. Set each worker&apos;s <code>--auth-token</code> here if it has one.
      </Typography>
      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      <Paper variant="outlined" sx={{ p: 2, mb: 2 }}>
        <Typography variant="subtitle2" sx={{ mb: 1 }}>
          Workers
        </Typography>
        <Box sx={{ display: "flex", gap: 1, mb: 1, flexWrap: "wrap" }}>
          <TextField size="small" label="Name" value={name} onChange={(e) => setName(e.target.value)} />
          <TextField
            size="small"
            label="URL"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="http://10.0.0.5:8080"
            sx={{ width: 260 }}
          />
          <TextField
            size="small"
            label="Auth token (optional)"
            type="password"
            value={token}
            onChange={(e) => setToken(e.target.value)}
          />
          <Button variant="outlined" onClick={addWorker} disabled={!name || !url}>
            Add worker
          </Button>
        </Box>
        <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
          {workers.map((wk) => (
            <Chip key={wk.name} label={`${wk.name} (${wk.url})`} onDelete={() => del(wk.name)} />
          ))}
          {workers.length === 0 && (
            <Typography variant="body2" color="text.secondary">
              No workers yet.
            </Typography>
          )}
        </Box>
      </Paper>

      <Paper variant="outlined" sx={{ p: 2, mb: 2 }}>
        <Box sx={{ display: "flex", gap: 1, mb: 1, alignItems: "flex-start" }}>
          <TextField
            label="Targets (one per line)"
            multiline
            minRows={3}
            value={targets}
            onChange={(e) => setTargets(e.target.value)}
            sx={{ flex: 1 }}
            InputProps={{ sx: { fontFamily: "'JetBrains Mono', monospace", fontSize: 13 } }}
          />
          <Box>
            <TextField
              select
              label="Scan"
              value={kind}
              onChange={(e) => setKind(e.target.value)}
              sx={{ width: 150, mb: 1 }}
            >
              {KINDS.map((k) => (
                <MenuItem key={k} value={k}>
                  {k}
                </MenuItem>
              ))}
            </TextField>
            <Button fullWidth variant="contained" onClick={run} disabled={running || workers.length === 0}>
              {running ? <CircularProgress size={24} /> : "Fan out"}
            </Button>
          </Box>
        </Box>
      </Paper>

      {result && (
        <>
          <Alert severity={result.failed > 0 ? "warning" : "success"} sx={{ mb: 2 }}>
            {result.kind}: {result.ok} ok / {result.failed} failed across {result.workers} worker(s), {result.targets}{" "}
            target(s).
          </Alert>
          <TableContainer component={Paper} variant="outlined" sx={{ maxHeight: 480 }}>
            <Table size="small" stickyHeader>
              <TableHead>
                <TableRow>
                  <TableCell>Target</TableCell>
                  <TableCell>Worker</TableCell>
                  <TableCell>Status</TableCell>
                  <TableCell>Error</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {(result.tasks || []).map((t, i) => (
                  <TableRow key={i} hover>
                    <TableCell sx={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12 }}>{t.target}</TableCell>
                    <TableCell>{t.worker}</TableCell>
                    <TableCell>
                      <Chip size="small" label={t.status} color={t.status === "ok" ? "success" : "error"} />
                    </TableCell>
                    <TableCell sx={{ fontSize: 11 }}>{t.error}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </>
      )}
    </Box>
  );
}
