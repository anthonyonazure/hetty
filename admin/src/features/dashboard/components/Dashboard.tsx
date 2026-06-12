import { Alert, Box, Chip, Link as MuiLink, Paper, Typography } from "@mui/material";
import { useEffect, useState } from "react";

import { apiGet } from "lib/restApi";

interface Interesting {
  key: string;
  kind: string;
  value: string;
  reasons: string[];
  sources?: string[] | null;
}

function Stat({ label, value, color }: { label: string; value: number; color?: string }): JSX.Element {
  return (
    <Paper variant="outlined" sx={{ p: 2, minWidth: 120, textAlign: "center" }}>
      <Typography variant="h4" sx={{ color: color || "text.primary" }}>
        {value}
      </Typography>
      <Typography variant="caption" color="text.secondary">
        {label}
      </Typography>
    </Paper>
  );
}

function Bar({ label, value, max, color }: { label: string; value: number; max: number; color: string }): JSX.Element {
  const pct = max > 0 ? (value / max) * 100 : 0;
  return (
    <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.5 }}>
      <Box sx={{ width: 90, fontSize: 12, textTransform: "capitalize" }}>{label}</Box>
      <Box sx={{ flex: 1, bgcolor: "#eee", borderRadius: 1, overflow: "hidden", height: 18 }}>
        <Box sx={{ width: `${pct}%`, bgcolor: color, height: "100%" }} />
      </Box>
      <Box sx={{ width: 30, fontSize: 12, textAlign: "right" }}>{value}</Box>
    </Box>
  );
}

export default function Dashboard(): JSX.Element {
  const [stats, setStats] = useState<Record<string, number>>({});
  const [findings, setFindings] = useState<Record<string, number>>({});
  const [interesting, setInteresting] = useState<Interesting[]>([]);
  const [error, setError] = useState("");

  useEffect(() => {
    apiGet<Record<string, number>>("/api/assets/stats")
      .then(setStats)
      .catch((e) => setError(e.message));
    apiGet<{ interesting: Interesting[] | null }>("/api/assets/interesting")
      .then((d) => setInteresting(d.interesting || []))
      .catch(() => undefined);
    apiGet<{ assets: { attrs?: Record<string, string> }[] | null }>("/api/assets?kind=finding")
      .then((d) => {
        const counts: Record<string, number> = {};
        (d.assets || []).forEach((a) => {
          const sev = a.attrs?.severity || "info";
          counts[sev] = (counts[sev] || 0) + 1;
        });
        setFindings(counts);
      })
      .catch(() => undefined);
  }, []);

  const sevOrder = ["critical", "high", "medium", "low", "info"];
  const sevColors: Record<string, string> = {
    critical: "#b71c1c",
    high: "#e53935",
    medium: "#fb8c00",
    low: "#1e88e5",
    info: "#9e9e9e",
  };
  const maxFinding = Math.max(1, ...Object.values(findings));

  return (
    <Box>
      <Typography variant="h4" sx={{ mb: 1 }}>
        Dashboard
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        A bird&apos;s-eye view of everything Hetty has found, drawn from the unified{" "}
        <MuiLink href="/assets">asset graph</MuiLink>. The “Interesting” list surfaces the assets worth looking at
        first.
      </Typography>
      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      <Box sx={{ display: "flex", flexWrap: "wrap", gap: 2, mb: 3 }}>
        <Stat label="domains" value={stats.domain || 0} />
        <Stat label="hosts" value={stats.host || 0} />
        <Stat label="services" value={stats.service || 0} />
        <Stat label="URLs" value={stats.url || 0} />
        <Stat label="findings" value={stats.finding || 0} color="#e53935" />
        <Stat label="interesting" value={interesting.length} color="#fb8c00" />
      </Box>

      <Box sx={{ display: "flex", gap: 2, flexWrap: "wrap" }}>
        <Paper variant="outlined" sx={{ p: 2, flex: 1, minWidth: 320 }}>
          <Typography variant="subtitle1" sx={{ mb: 1 }}>
            Findings by severity
          </Typography>
          {sevOrder.map((s) => (
            <Bar key={s} label={s} value={findings[s] || 0} max={maxFinding} color={sevColors[s]} />
          ))}
          {Object.keys(findings).length === 0 && (
            <Typography variant="body2" color="text.secondary">
              No findings yet.
            </Typography>
          )}
        </Paper>

        <Paper variant="outlined" sx={{ p: 2, flex: 1, minWidth: 320, maxHeight: 420, overflow: "auto" }}>
          <Typography variant="subtitle1" sx={{ mb: 1 }}>
            Interesting ({interesting.length})
          </Typography>
          {interesting.map((it) => (
            <Box key={it.key} sx={{ mb: 1 }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <Chip size="small" label={it.kind} />
                <Typography variant="body2" sx={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12 }}>
                  {it.value}
                </Typography>
              </Box>
              <Typography variant="caption" color="warning.main">
                {(it.reasons || []).join("; ")}
              </Typography>
            </Box>
          ))}
          {interesting.length === 0 && (
            <Typography variant="body2" color="text.secondary">
              Nothing flagged yet — run some scans.
            </Typography>
          )}
        </Paper>
      </Box>
    </Box>
  );
}
