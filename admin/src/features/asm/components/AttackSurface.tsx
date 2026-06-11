import {
  Alert,
  Box,
  Button,
  Chip,
  CircularProgress,
  Divider,
  FormControlLabel,
  List,
  ListItemButton,
  ListItemText,
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

interface WorkspaceSummary {
  name: string;
  targets: number;
  hosts: number;
  lastMode?: string;
  updatedAt?: string;
}

interface Vuln {
  cve: string;
  title: string;
  severity: string;
  exploitAvailable: boolean;
  msfModule?: string;
}
interface Port {
  port: number;
  service: string;
  banner?: string;
  vulns?: Vuln[];
}
interface Tech {
  server?: string;
  powered?: string;
  title?: string;
  technologies?: string[];
}
interface TLSSummary {
  protocols: string[];
  certSubject: string;
  daysUntilExpiry: number;
  issues?: string[];
}
interface Finding {
  source: string;
  title: string;
  severity: string;
  detail?: string;
}
interface ExploitResult {
  module: string;
  target: string;
  status: string;
  detail?: string;
}
interface Host {
  host: string;
  ports?: Port[];
  tech?: Tech;
  waf?: string[];
  tls?: TLSSummary;
  screenshot?: string;
  findings?: Finding[];
  exploits?: ExploitResult[];
}
interface Workspace {
  name: string;
  targets: string[];
  subdomains?: string[];
  hosts: Host[] | null;
  lastMode?: string;
}
interface RunSummary {
  mode: string;
  hostsScanned: number;
  openPorts: number;
  findings: number;
  exploited: number;
  errors?: string[];
}

function sevColor(s: string): "error" | "warning" | "info" | "default" {
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

function HostCard({ host }: { host: Host }): JSX.Element {
  return (
    <Paper variant="outlined" sx={{ p: 2, mb: 2 }}>
      <Box sx={{ display: "flex", gap: 2 }}>
        <Box sx={{ flex: 1 }}>
          <Typography variant="h6" sx={{ fontFamily: "'JetBrains Mono', monospace" }}>
            {host.host}
          </Typography>
          <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, my: 1 }}>
            {(host.tech?.technologies || []).map((t) => (
              <Chip key={t} label={t} size="small" color="primary" variant="outlined" />
            ))}
            {(host.waf || []).map((w) => (
              <Chip key={w} label={`WAF: ${w}`} size="small" color="secondary" />
            ))}
          </Box>
          {host.tls && host.tls.issues && host.tls.issues.length > 0 && (
            <Alert severity="warning" sx={{ mb: 1, py: 0 }}>
              TLS: {host.tls.issues.join("; ")}
            </Alert>
          )}
        </Box>
        {host.screenshot && (
          <Box sx={{ width: 220 }}>
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img
              src={`data:image/png;base64,${host.screenshot}`}
              alt={`${host.host} screenshot`}
              style={{ width: "100%", border: "1px solid #ccc", borderRadius: 4 }}
            />
          </Box>
        )}
      </Box>

      {(host.ports || []).length > 0 && (
        <TableContainer sx={{ mb: 1 }}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Port</TableCell>
                <TableCell>Service</TableCell>
                <TableCell>Banner</TableCell>
                <TableCell>Known vulns</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {(host.ports || []).map((p) => (
                <TableRow key={p.port} hover>
                  <TableCell>{p.port}</TableCell>
                  <TableCell>{p.service}</TableCell>
                  <TableCell sx={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12 }}>{p.banner}</TableCell>
                  <TableCell>
                    {(p.vulns || []).map((v) => (
                      <Chip
                        key={v.cve}
                        size="small"
                        sx={{ mr: 0.5, mb: 0.5 }}
                        color={sevColor(v.severity)}
                        label={`${v.cve}${v.exploitAvailable ? " ⚡" : ""}`}
                        title={v.title}
                      />
                    ))}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}

      {(host.findings || []).length > 0 && (
        <Box sx={{ mb: 1 }}>
          {(host.findings || []).map((f, i) => (
            <Box key={i} sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <Chip size="small" label={f.severity} color={sevColor(f.severity)} />
              <Typography variant="body2">
                {f.title} <span style={{ color: "#888" }}>({f.source})</span>
              </Typography>
            </Box>
          ))}
        </Box>
      )}

      {(host.exploits || []).map((e, i) => (
        <Alert key={i} severity={e.status === "failed" ? "error" : "success"} sx={{ mt: 1 }}>
          <strong>{e.module}</strong> → {e.status}: {e.detail}
        </Alert>
      ))}
    </Paper>
  );
}

export default function AttackSurface(): JSX.Element {
  const [workspaces, setWorkspaces] = useState<WorkspaceSummary[]>([]);
  const [selected, setSelected] = useState("");
  const [detail, setDetail] = useState<Workspace | null>(null);
  const [newName, setNewName] = useState("");
  const [newTargets, setNewTargets] = useState("");
  const [mode, setMode] = useState("recon");
  const [fullPorts, setFullPorts] = useState(false);
  const [screenshot, setScreenshot] = useState(false);
  const [allowExploit, setAllowExploit] = useState(false);
  const [msfEnabled, setMsfEnabled] = useState(false);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState("");
  const [summary, setSummary] = useState<RunSummary | null>(null);

  const refresh = () => {
    apiGet<{ workspaces: WorkspaceSummary[] | null }>("/api/asm/workspaces")
      .then((d) => setWorkspaces(d.workspaces || []))
      .catch(() => undefined);
  };

  useEffect(() => {
    refresh();
    apiGet<{ enabled: boolean }>("/api/msf/status")
      .then((d) => setMsfEnabled(d.enabled))
      .catch(() => undefined);
  }, []);

  const select = (name: string) => {
    setSelected(name);
    setSummary(null);
    apiGet<Workspace>(`/api/asm/workspace?name=${encodeURIComponent(name)}`)
      .then(setDetail)
      .catch((err) => setError(err.message));
  };

  const createWs = () => {
    setError("");
    const targets = newTargets
      .split(/[\n,]/)
      .map((t) => t.trim())
      .filter((t) => t !== "");
    apiPut<Workspace>("/api/asm/workspaces", { name: newName, targets })
      .then(() => {
        setNewName("");
        setNewTargets("");
        refresh();
        select(newName);
      })
      .catch((err) => setError(err.message));
  };

  const deleteWs = (name: string) => {
    apiDelete(`/api/asm/workspaces?name=${encodeURIComponent(name)}`)
      .then(() => {
        if (selected === name) {
          setSelected("");
          setDetail(null);
        }
        refresh();
      })
      .catch((err) => setError(err.message));
  };

  const run = () => {
    setRunning(true);
    setError("");
    setSummary(null);
    apiPost<{ summary: RunSummary; workspace: Workspace }>("/api/asm/run", {
      workspace: selected,
      mode,
      options: { fullPortScan: fullPorts, screenshot, allowExploit: allowExploit && mode === "nuke" },
    })
      .then((d) => {
        setSummary(d.summary);
        setDetail(d.workspace);
        refresh();
      })
      .catch((err) => setError(err.message))
      .finally(() => setRunning(false));
  };

  return (
    <Box>
      <Typography variant="h4" sx={{ mb: 1 }}>
        Attack surface
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        Sn1per-style sweeps. Create a workspace of targets, then run a scan mode that chains subdomain enum, port
        scanning, TLS/WAF analysis, fingerprinting, web vuln scanning, screenshots and known-vuln matching. NUKE mode
        auto-exploits matched vulns through Metasploit (when configured).
      </Typography>
      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      <Box sx={{ display: "flex", gap: 2, alignItems: "flex-start" }}>
        {/* Sidebar: workspaces + create */}
        <Box sx={{ width: 280, flexShrink: 0 }}>
          <Paper variant="outlined" sx={{ mb: 2 }}>
            <List dense>
              {workspaces.map((w) => (
                <ListItemButton key={w.name} selected={w.name === selected} onClick={() => select(w.name)}>
                  <ListItemText primary={w.name} secondary={`${w.targets} target(s), ${w.hosts} host(s)`} />
                  <Button
                    size="small"
                    color="error"
                    onClick={(e) => {
                      e.stopPropagation();
                      deleteWs(w.name);
                    }}
                  >
                    ✕
                  </Button>
                </ListItemButton>
              ))}
              {workspaces.length === 0 && (
                <Box sx={{ p: 2 }}>
                  <Typography variant="body2" color="text.secondary">
                    No workspaces yet.
                  </Typography>
                </Box>
              )}
            </List>
          </Paper>
          <Paper variant="outlined" sx={{ p: 2 }}>
            <Typography variant="subtitle2" sx={{ mb: 1 }}>
              New workspace
            </Typography>
            <TextField
              label="Name"
              size="small"
              fullWidth
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              sx={{ mb: 1 }}
            />
            <TextField
              label="Targets (one per line)"
              size="small"
              fullWidth
              multiline
              minRows={3}
              value={newTargets}
              onChange={(e) => setNewTargets(e.target.value)}
              sx={{ mb: 1 }}
              placeholder={"example.com\n10.0.0.5\nhttps://app.example.com"}
            />
            <Button variant="contained" fullWidth onClick={createWs} disabled={!newName}>
              Create
            </Button>
          </Paper>
        </Box>

        {/* Main: run bar + hosts */}
        <Box sx={{ flex: 1 }}>
          {selected ? (
            <>
              <Paper variant="outlined" sx={{ p: 2, mb: 2 }}>
                <Box sx={{ display: "flex", gap: 1, alignItems: "center", flexWrap: "wrap" }}>
                  <TextField
                    select
                    label="Mode"
                    size="small"
                    value={mode}
                    onChange={(e) => setMode(e.target.value)}
                    sx={{ width: 140 }}
                  >
                    <MenuItem value="recon">recon</MenuItem>
                    <MenuItem value="web">web</MenuItem>
                    <MenuItem value="full">full</MenuItem>
                    <MenuItem value="nuke">nuke</MenuItem>
                  </TextField>
                  <FormControlLabel
                    control={<Switch checked={fullPorts} onChange={(e) => setFullPorts(e.target.checked)} />}
                    label="Full ports (1-1024)"
                  />
                  <FormControlLabel
                    control={<Switch checked={screenshot} onChange={(e) => setScreenshot(e.target.checked)} />}
                    label="Screenshots"
                  />
                  <FormControlLabel
                    control={
                      <Switch
                        checked={allowExploit}
                        onChange={(e) => setAllowExploit(e.target.checked)}
                        disabled={mode !== "nuke" || !msfEnabled}
                        color="error"
                      />
                    }
                    label={msfEnabled ? "Allow exploit (NUKE)" : "Allow exploit (MSF off)"}
                  />
                  <Button
                    variant="contained"
                    color={mode === "nuke" ? "error" : "primary"}
                    onClick={run}
                    disabled={running}
                  >
                    {running ? <CircularProgress size={24} /> : `Run ${mode}`}
                  </Button>
                </Box>
                {summary && (
                  <Alert severity={summary.exploited > 0 ? "error" : "success"} sx={{ mt: 2 }}>
                    {summary.mode}: scanned {summary.hostsScanned} host(s), {summary.openPorts} open port(s),{" "}
                    {summary.findings} finding(s), {summary.exploited} exploited.
                    {summary.errors && summary.errors.length > 0 && ` (${summary.errors.length} error(s))`}
                  </Alert>
                )}
              </Paper>

              {detail && detail.subdomains && detail.subdomains.length > 0 && (
                <Paper variant="outlined" sx={{ p: 2, mb: 2 }}>
                  <Typography variant="subtitle2">Subdomains ({detail.subdomains.length})</Typography>
                  <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mt: 1 }}>
                    {detail.subdomains.map((s) => (
                      <Chip key={s} label={s} size="small" sx={{ fontFamily: "'JetBrains Mono', monospace" }} />
                    ))}
                  </Box>
                </Paper>
              )}

              <Divider sx={{ mb: 2 }}>Hosts</Divider>
              {(detail?.hosts || []).map((h) => (
                <HostCard key={h.host} host={h} />
              ))}
              {(detail?.hosts || []).length === 0 && (
                <Typography variant="body2" color="text.secondary">
                  No results yet — run a scan mode above.
                </Typography>
              )}
            </>
          ) : (
            <Typography variant="body2" color="text.secondary">
              Select or create a workspace to begin.
            </Typography>
          )}
        </Box>
      </Box>
    </Box>
  );
}
