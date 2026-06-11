import { Alert, Box, Button, Chip, CircularProgress, MenuItem, Paper, TextField, Typography } from "@mui/material";
import { useEffect, useRef, useState } from "react";

import { apiGet, apiPost } from "lib/restApi";

interface ToolInfo {
  name: string;
  binary: string;
  category: string;
  description: string;
  needsTarget: boolean;
  available: boolean;
  path?: string;
}

interface Job {
  id: string;
  tool: string;
  target: string;
  cmdline: string;
  status: string;
  exitCode: number;
  startedAt: string;
  finishedAt?: string;
  output: string;
}

export default function ExternalTools(): JSX.Element {
  const [tools, setTools] = useState<ToolInfo[]>([]);
  const [tool, setTool] = useState("");
  const [target, setTarget] = useState("");
  const [extra, setExtra] = useState("");
  const [job, setJob] = useState<Job | null>(null);
  const [error, setError] = useState("");
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    apiGet<{ tools: ToolInfo[] | null }>("/api/exttools")
      .then((d) => setTools(d.tools || []))
      .catch((err) => setError(err.message));
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, []);

  const selected = tools.find((t) => t.name === tool);

  const poll = (id: string) => {
    if (pollRef.current) clearInterval(pollRef.current);
    pollRef.current = setInterval(() => {
      apiGet<Job>(`/api/exttools/job?id=${encodeURIComponent(id)}`)
        .then((j) => {
          setJob(j);
          if (j.status !== "running" && pollRef.current) {
            clearInterval(pollRef.current);
            pollRef.current = null;
          }
        })
        .catch(() => undefined);
    }, 1500);
  };

  const run = () => {
    setError("");
    setJob(null);
    apiPost<Job>("/api/exttools/run", { tool, target, extra })
      .then((j) => {
        setJob(j);
        poll(j.id);
      })
      .catch((err) => setError(err.message));
  };

  const stop = () => {
    if (!job) return;
    apiPost("/api/exttools/stop", { id: job.id }).catch(() => undefined);
  };

  // Group tools by category for the dropdown.
  const categories = Array.from(new Set(tools.map((t) => t.category)));

  const availableCount = tools.filter((t) => t.available).length;

  return (
    <Box>
      <Typography variant="h4" sx={{ mb: 1 }}>
        External tools
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        Run installed command-line tools (nmap, nikto, nuclei, wpscan, subfinder, sslscan, hydra, sqlmap, ...) against a
        target and stream the output here. Tools are detected on the host PATH — {availableCount} of {tools.length}{" "}
        available. Arguments are passed without a shell (no injection); add tool-specific flags in “Extra args”.
      </Typography>
      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      <Paper variant="outlined" sx={{ p: 2, mb: 2 }}>
        <Box sx={{ display: "flex", gap: 1, mb: 2, flexWrap: "wrap" }}>
          <TextField select label="Tool" value={tool} onChange={(e) => setTool(e.target.value)} sx={{ minWidth: 260 }}>
            {categories.map((cat) => [
              <MenuItem key={`h-${cat}`} disabled sx={{ opacity: 0.7, fontWeight: 600 }}>
                {cat.toUpperCase()}
              </MenuItem>,
              ...tools
                .filter((t) => t.category === cat)
                .map((t) => (
                  <MenuItem key={t.name} value={t.name} disabled={!t.available}>
                    {t.name} {t.available ? "" : "(not installed)"}
                  </MenuItem>
                )),
            ])}
          </TextField>
          <TextField
            label="Target"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="example.com / https://app.example.com / 10.0.0.5"
            sx={{ flex: 1, minWidth: 240 }}
          />
        </Box>
        <TextField
          label="Extra args (optional)"
          fullWidth
          value={extra}
          onChange={(e) => setExtra(e.target.value)}
          placeholder="e.g. -w /usr/share/wordlists/dirb/common.txt"
          sx={{ mb: 2 }}
          InputProps={{ sx: { fontFamily: "'JetBrains Mono', monospace", fontSize: 13 } }}
        />
        {selected && (
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            {selected.description}{" "}
            <Chip
              size="small"
              label={selected.available ? `found: ${selected.path}` : `${selected.binary} not on PATH`}
              color={selected.available ? "success" : "default"}
              sx={{ ml: 1 }}
            />
          </Typography>
        )}
        <Box sx={{ display: "flex", gap: 1 }}>
          <Button variant="contained" onClick={run} disabled={!tool || (selected?.needsTarget && !target)}>
            Run
          </Button>
          {job && job.status === "running" && (
            <Button variant="outlined" color="error" onClick={stop}>
              Stop
            </Button>
          )}
        </Box>
      </Paper>

      {job && (
        <Paper variant="outlined" sx={{ p: 2 }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
            {job.status === "running" && <CircularProgress size={18} />}
            <Chip
              size="small"
              label={job.status === "running" ? "running" : `${job.status} (exit ${job.exitCode})`}
              color={job.status === "failed" ? "error" : job.status === "done" ? "success" : "info"}
            />
            <Typography variant="body2" sx={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12 }}>
              $ {job.cmdline}
            </Typography>
          </Box>
          <Box
            component="pre"
            sx={{
              m: 0,
              p: 1.5,
              maxHeight: 480,
              overflow: "auto",
              bgcolor: "#0b0b0b",
              color: "#d6d6d6",
              borderRadius: 1,
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: 12,
              whiteSpace: "pre-wrap",
            }}
          >
            {job.output || "(waiting for output...)"}
          </Box>
        </Paper>
      )}
    </Box>
  );
}
