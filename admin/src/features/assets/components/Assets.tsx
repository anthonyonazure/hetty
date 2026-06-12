import {
  Alert,
  Box,
  Button,
  Chip,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Tab,
  Tabs,
  Typography,
} from "@mui/material";
import { useEffect, useState } from "react";

import { apiDelete, apiGet } from "lib/restApi";

interface Asset {
  key: string;
  kind: string;
  value: string;
  firstSeen: string;
  lastSeen: string;
  sources: string[] | null;
  attrs?: Record<string, string>;
}

const KINDS = ["", "domain", "host", "service", "url", "finding"];

function sevColor(s?: string): "error" | "warning" | "info" | "default" {
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

export default function Assets(): JSX.Element {
  const [kind, setKind] = useState("");
  const [assets, setAssets] = useState<Asset[]>([]);
  const [stats, setStats] = useState<Record<string, number>>({});
  const [error, setError] = useState("");

  const load = (k: string) => {
    apiGet<{ assets: Asset[] | null }>(`/api/assets${k ? `?kind=${k}` : ""}`)
      .then((d) => setAssets(d.assets || []))
      .catch((e) => setError(e.message));
    apiGet<Record<string, number>>("/api/assets/stats")
      .then(setStats)
      .catch(() => undefined);
  };

  useEffect(() => load(kind), [kind]);

  const clear = () => {
    if (!confirm("Clear the entire asset graph?")) return;
    apiDelete("/api/assets").then(() => load(kind));
  };

  return (
    <Box>
      <Typography variant="h4" sx={{ mb: 1 }}>
        Assets
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        The unified graph. Every tool — recon, port scans, fingerprinting, the Attack Surface sweeps, and the scheduled
        monitors — feeds its results into one normalized store: domains → hosts → services / URLs → findings, each
        tagged with where it came from and when it was first and last seen. This is your single source of truth that
        grows over time.
      </Typography>
      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1, mb: 2, alignItems: "center" }}>
        {["domain", "host", "service", "url", "finding"].map((k) => (
          <Chip key={k} label={`${k}: ${stats[k] || 0}`} />
        ))}
        <Chip color="primary" label={`total: ${stats["total"] || 0}`} />
        <Box sx={{ flex: 1 }} />
        <Button size="small" color="error" onClick={clear}>
          Clear graph
        </Button>
      </Box>

      <Tabs value={kind} onChange={(_, v) => setKind(v)} sx={{ mb: 1 }}>
        {KINDS.map((k) => (
          <Tab key={k} value={k} label={k === "" ? "All" : k} />
        ))}
      </Tabs>

      <TableContainer component={Paper} variant="outlined" sx={{ maxHeight: 600 }}>
        <Table size="small" stickyHeader>
          <TableHead>
            <TableRow>
              <TableCell>Kind</TableCell>
              <TableCell>Value</TableCell>
              <TableCell>Details</TableCell>
              <TableCell>Sources</TableCell>
              <TableCell>First seen</TableCell>
              <TableCell>Last seen</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {assets.map((a) => (
              <TableRow key={a.key} hover>
                <TableCell>
                  {a.kind === "finding" ? (
                    <Chip size="small" label={a.attrs?.severity || "finding"} color={sevColor(a.attrs?.severity)} />
                  ) : (
                    <Chip size="small" variant="outlined" label={a.kind} />
                  )}
                </TableCell>
                <TableCell sx={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12 }}>{a.value}</TableCell>
                <TableCell sx={{ fontSize: 12 }}>
                  {a.attrs?.service}
                  {a.attrs?.technologies}
                  {a.attrs?.banner ? ` — ${a.attrs.banner}` : ""}
                </TableCell>
                <TableCell>
                  {(a.sources || []).map((s) => (
                    <Chip key={s} size="small" label={s} sx={{ mr: 0.5 }} />
                  ))}
                </TableCell>
                <TableCell sx={{ fontSize: 11 }}>{a.firstSeen}</TableCell>
                <TableCell sx={{ fontSize: 11 }}>{a.lastSeen}</TableCell>
              </TableRow>
            ))}
            {assets.length === 0 && (
              <TableRow>
                <TableCell colSpan={6}>
                  <Typography variant="body2" color="text.secondary">
                    No assets yet — run a recon scan, an Attack Surface sweep, or a monitor.
                  </Typography>
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </TableContainer>
    </Box>
  );
}
