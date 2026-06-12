import {
  Alert,
  Box,
  Button,
  Chip,
  FormControlLabel,
  MenuItem,
  Paper,
  Switch,
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

interface Schedule {
  id: string;
  name: string;
  target: string;
  kind: string;
  extra?: string;
  intervalSec: number;
  enabled: boolean;
  alertUrl?: string;
  lastRun?: string;
  nextRun?: string;
}
interface Diff {
  time: string;
  added: string[] | null;
  removed: string[] | null;
}

const NATIVE_KINDS = ["subdomains", "portscan", "fingerprint", "tlsscan", "wafdetect"];

export default function Monitoring(): JSX.Element {
  const [schedules, setSchedules] = useState<Schedule[]>([]);
  const [name, setName] = useState("");
  const [target, setTarget] = useState("");
  const [kindSel, setKindSel] = useState("subdomains");
  const [toolName, setToolName] = useState("");
  const [extra, setExtra] = useState("");
  const [interval, setInterval] = useState("3600");
  const [alertUrl, setAlertUrl] = useState("");
  const [saveTo, setSaveTo] = useState("");
  const [destinations, setDestinations] = useState<string[]>([]);
  const [enabled, setEnabled] = useState(true);
  const [error, setError] = useState("");
  const [diffs, setDiffs] = useState<{ id: string; rows: Diff[] } | null>(null);

  const refresh = () => {
    apiGet<{ schedules: Schedule[] | null }>("/api/monitor/schedules")
      .then((d) => setSchedules(d.schedules || []))
      .catch(() => undefined);
  };
  useEffect(() => {
    refresh();
    apiGet<{ destinations: { name: string }[] | null }>("/api/vault/destinations")
      .then((d) => setDestinations((d.destinations || []).map((x) => x.name)))
      .catch(() => undefined);
  }, []);

  const create = () => {
    setError("");
    const kind = kindSel === "tool" ? `tool:${toolName}` : kindSel;
    apiPut<Schedule>("/api/monitor/schedules", {
      name,
      target,
      kind,
      extra,
      intervalSec: parseInt(interval, 10) || 3600,
      alertUrl,
      saveTo,
      enabled,
    })
      .then(() => {
        setName("");
        setTarget("");
        refresh();
      })
      .catch((e) => setError(e.message));
  };

  const runNow = (id: string) => {
    apiPost<Diff>("/api/monitor/run", { id })
      .then(() => {
        refresh();
        viewDiffs(id);
      })
      .catch((e) => setError(e.message));
  };

  const toggle = (s: Schedule) => {
    apiPut("/api/monitor/schedules", { ...s, enabled: !s.enabled })
      .then(refresh)
      .catch((e) => setError(e.message));
  };

  const del = (id: string) => {
    apiDelete(`/api/monitor/schedules?id=${encodeURIComponent(id)}`)
      .then(refresh)
      .catch((e) => setError(e.message));
  };

  const viewDiffs = (id: string) => {
    apiGet<{ diffs: Diff[] | null }>(`/api/monitor/diffs?id=${encodeURIComponent(id)}`)
      .then((d) => setDiffs({ id, rows: d.diffs || [] }))
      .catch((e) => setError(e.message));
  };

  return (
    <Box>
      <Typography variant="h4" sx={{ mb: 1 }}>
        Monitoring
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        Schedule a check to re-run on a timer. Each run is diffed against the previous one, so you get alerted the
        moment something <strong>new</strong> appears (a subdomain, an open port, a finding) — that delta is where the
        bounties are. Set an alert URL (a Slack/Discord/webhook) to be notified on change.
      </Typography>
      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      <Paper variant="outlined" sx={{ p: 2, mb: 3 }}>
        <Typography variant="subtitle2" sx={{ mb: 1 }}>
          New monitor
        </Typography>
        <Box sx={{ display: "flex", gap: 1, mb: 1, flexWrap: "wrap" }}>
          <TextField size="small" label="Name" value={name} onChange={(e) => setName(e.target.value)} />
          <TextField
            size="small"
            label="Target"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="example.com"
          />
          <TextField
            select
            size="small"
            label="Check"
            value={kindSel}
            onChange={(e) => setKindSel(e.target.value)}
            sx={{ width: 150 }}
          >
            {NATIVE_KINDS.map((k) => (
              <MenuItem key={k} value={k}>
                {k}
              </MenuItem>
            ))}
            <MenuItem value="tool">external tool…</MenuItem>
          </TextField>
          {kindSel === "tool" && (
            <TextField
              size="small"
              label="Tool name"
              value={toolName}
              onChange={(e) => setToolName(e.target.value)}
              placeholder="subfinder"
            />
          )}
          <TextField
            size="small"
            label="Every (sec)"
            value={interval}
            onChange={(e) => setInterval(e.target.value)}
            sx={{ width: 110 }}
          />
        </Box>
        <Box sx={{ display: "flex", gap: 1, alignItems: "center", flexWrap: "wrap" }}>
          <TextField
            size="small"
            label="Alert webhook (Slack/Discord/HTTP)"
            value={alertUrl}
            onChange={(e) => setAlertUrl(e.target.value)}
            sx={{ width: 360 }}
          />
          <TextField size="small" label="Extra args (tools)" value={extra} onChange={(e) => setExtra(e.target.value)} />
          <TextField
            select
            size="small"
            label="Save runs to"
            value={saveTo}
            onChange={(e) => setSaveTo(e.target.value)}
            sx={{ width: 160 }}
          >
            <MenuItem value="">
              <em>don&apos;t save</em>
            </MenuItem>
            {destinations.map((d) => (
              <MenuItem key={d} value={d}>
                {d}
              </MenuItem>
            ))}
          </TextField>
          <FormControlLabel
            control={<Switch checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />}
            label="Enabled"
          />
          <Button variant="contained" onClick={create} disabled={!target}>
            Add monitor
          </Button>
        </Box>
      </Paper>

      <TableContainer component={Paper} variant="outlined" sx={{ mb: 3 }}>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Name</TableCell>
              <TableCell>Target</TableCell>
              <TableCell>Check</TableCell>
              <TableCell>Every</TableCell>
              <TableCell>Next run</TableCell>
              <TableCell>On</TableCell>
              <TableCell>Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {schedules.map((s) => (
              <TableRow key={s.id} hover>
                <TableCell>{s.name}</TableCell>
                <TableCell sx={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12 }}>{s.target}</TableCell>
                <TableCell>{s.kind}</TableCell>
                <TableCell>{s.intervalSec}s</TableCell>
                <TableCell sx={{ fontSize: 11 }}>{s.nextRun}</TableCell>
                <TableCell>
                  <Switch size="small" checked={s.enabled} onChange={() => toggle(s)} />
                </TableCell>
                <TableCell>
                  <Button size="small" onClick={() => runNow(s.id)}>
                    Run
                  </Button>
                  <Button size="small" onClick={() => viewDiffs(s.id)}>
                    Changes
                  </Button>
                  <Button size="small" color="error" onClick={() => del(s.id)}>
                    ✕
                  </Button>
                </TableCell>
              </TableRow>
            ))}
            {schedules.length === 0 && (
              <TableRow>
                <TableCell colSpan={7}>
                  <Typography variant="body2" color="text.secondary">
                    No monitors yet.
                  </Typography>
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </TableContainer>

      {diffs && (
        <Paper variant="outlined" sx={{ p: 2 }}>
          <Typography variant="subtitle2" sx={{ mb: 1 }}>
            Change history
          </Typography>
          {diffs.rows.length === 0 && (
            <Typography variant="body2" color="text.secondary">
              No changes recorded yet (the first run is the baseline).
            </Typography>
          )}
          {diffs.rows.map((d, i) => (
            <Box key={i} sx={{ mb: 1 }}>
              <Typography variant="caption" color="text.secondary">
                {d.time}
              </Typography>
              <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                {(d.added || []).map((a) => (
                  <Chip key={`a${a}`} size="small" color="success" label={`+ ${a}`} />
                ))}
                {(d.removed || []).map((r) => (
                  <Chip key={`r${r}`} size="small" color="error" label={`- ${r}`} />
                ))}
              </Box>
            </Box>
          ))}
        </Paper>
      )}
    </Box>
  );
}
