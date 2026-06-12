import {
  Alert,
  Box,
  Button,
  Chip,
  CircularProgress,
  Divider,
  IconButton,
  MenuItem,
  Paper,
  TextField,
  Typography,
} from "@mui/material";
import { useEffect, useState } from "react";

import { apiDelete, apiGet, apiPost, apiPut } from "lib/restApi";

interface Step {
  type: string;
  name: string;
  extra?: string;
}
interface Workflow {
  name: string;
  description?: string;
  steps: Step[];
  builtin?: boolean;
}
interface StepResult {
  step: Step;
  output: string;
  status: string;
  detail?: string;
}
interface RunResult {
  workflow: string;
  target: string;
  steps: StepResult[];
}

const NATIVE_STEPS = ["subdomains", "fingerprint", "portscan", "tlsscan", "wafdetect", "webscan", "screenshot"];

export default function Workflows(): JSX.Element {
  const [workflows, setWorkflows] = useState<Workflow[]>([]);
  const [target, setTarget] = useState("");
  const [running, setRunning] = useState("");
  const [error, setError] = useState("");
  const [result, setResult] = useState<RunResult | null>(null);

  // builder
  const [name, setName] = useState("");
  const [steps, setSteps] = useState<Step[]>([{ type: "native", name: "fingerprint", extra: "" }]);

  const refresh = () => {
    apiGet<{ workflows: Workflow[] | null }>("/api/workflows")
      .then((d) => setWorkflows(d.workflows || []))
      .catch(() => undefined);
  };
  useEffect(refresh, []);

  const run = (wf: string) => {
    if (!target) {
      setError("Enter a target first.");
      return;
    }
    setRunning(wf);
    setError("");
    setResult(null);
    apiPost<RunResult>("/api/workflows/run", { workflow: wf, target })
      .then(setResult)
      .catch((e) => setError(e.message))
      .finally(() => setRunning(""));
  };

  const save = () => {
    setError("");
    apiPut("/api/workflows", { name, steps })
      .then(refresh)
      .catch((e) => setError(e.message));
  };

  const del = (n: string) => apiDelete(`/api/workflows?name=${encodeURIComponent(n)}`).then(refresh);

  const updateStep = (i: number, patch: Partial<Step>) => {
    setSteps(steps.map((s, idx) => (idx === i ? { ...s, ...patch } : s)));
  };

  return (
    <Box>
      <Typography variant="h4" sx={{ mb: 1 }}>
        Workflows
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        Chain tools the way you actually run an engagement. Pick a target, then run a built-in chain or your own. Each
        step runs in order and its output is collected into one report. <code>native</code> steps use Hetty&apos;s own
        engines (always available); <code>tool</code> steps use external tools when installed.
      </Typography>
      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      <TextField
        label="Target"
        fullWidth
        value={target}
        onChange={(e) => setTarget(e.target.value)}
        placeholder="example.com / https://app.example.com"
        sx={{ mb: 2 }}
      />

      <Box sx={{ display: "flex", flexWrap: "wrap", gap: 2, mb: 3 }}>
        {workflows.map((wf) => (
          <Paper key={wf.name} variant="outlined" sx={{ p: 2, width: 320 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <Typography variant="subtitle1">{wf.name}</Typography>
              {wf.builtin ? (
                <Chip size="small" label="built-in" />
              ) : (
                <Chip size="small" color="primary" label="custom" />
              )}
            </Box>
            <Typography variant="body2" color="text.secondary" sx={{ my: 1, minHeight: 40 }}>
              {wf.description}
            </Typography>
            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mb: 1 }}>
              {wf.steps.map((s, i) => (
                <Chip key={i} size="small" variant="outlined" label={`${s.name}`} />
              ))}
            </Box>
            <Box sx={{ display: "flex", gap: 1 }}>
              <Button size="small" variant="contained" onClick={() => run(wf.name)} disabled={running !== ""}>
                {running === wf.name ? <CircularProgress size={18} /> : "Run"}
              </Button>
              {!wf.builtin && (
                <Button size="small" color="error" onClick={() => del(wf.name)}>
                  Delete
                </Button>
              )}
            </Box>
          </Paper>
        ))}
      </Box>

      {result && (
        <Paper variant="outlined" sx={{ p: 2, mb: 3 }}>
          <Typography variant="h6" sx={{ mb: 1 }}>
            {result.workflow} → {result.target}
          </Typography>
          {result.steps.map((sr, i) => (
            <Box key={i} sx={{ mb: 1 }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <Chip size="small" label={sr.status} color={sr.status === "error" ? "error" : "success"} />
                <Typography variant="subtitle2">
                  {sr.step.type}:{sr.step.name}
                </Typography>
              </Box>
              <Box
                component="pre"
                sx={{
                  m: 0,
                  mt: 0.5,
                  p: 1,
                  bgcolor: "#0b0b0b",
                  color: "#d6d6d6",
                  borderRadius: 1,
                  fontSize: 11,
                  maxHeight: 200,
                  overflow: "auto",
                  whiteSpace: "pre-wrap",
                }}
              >
                {sr.detail ? `${sr.detail}\n${sr.output}` : sr.output || "(no output)"}
              </Box>
            </Box>
          ))}
        </Paper>
      )}

      <Divider sx={{ mb: 2 }}>Build your own</Divider>
      <Paper variant="outlined" sx={{ p: 2 }}>
        <TextField
          size="small"
          label="Workflow name"
          value={name}
          onChange={(e) => setName(e.target.value)}
          sx={{ mb: 2 }}
        />
        {steps.map((s, i) => (
          <Box key={i} sx={{ display: "flex", gap: 1, mb: 1, alignItems: "center" }}>
            <TextField
              select
              size="small"
              label="Type"
              value={s.type}
              onChange={(e) => updateStep(i, { type: e.target.value })}
              sx={{ width: 110 }}
            >
              <MenuItem value="native">native</MenuItem>
              <MenuItem value="tool">tool</MenuItem>
            </TextField>
            {s.type === "native" ? (
              <TextField
                select
                size="small"
                label="Step"
                value={s.name}
                onChange={(e) => updateStep(i, { name: e.target.value })}
                sx={{ width: 160 }}
              >
                {NATIVE_STEPS.map((n) => (
                  <MenuItem key={n} value={n}>
                    {n}
                  </MenuItem>
                ))}
              </TextField>
            ) : (
              <TextField
                size="small"
                label="Tool name"
                value={s.name}
                onChange={(e) => updateStep(i, { name: e.target.value })}
                sx={{ width: 160 }}
              />
            )}
            <TextField
              size="small"
              label="Extra args"
              value={s.extra}
              onChange={(e) => updateStep(i, { extra: e.target.value })}
              sx={{ flex: 1 }}
            />
            <IconButton size="small" color="error" onClick={() => setSteps(steps.filter((_, idx) => idx !== i))}>
              ✕
            </IconButton>
          </Box>
        ))}
        <Box sx={{ display: "flex", gap: 1, mt: 1 }}>
          <Button size="small" onClick={() => setSteps([...steps, { type: "native", name: "fingerprint", extra: "" }])}>
            + Add step
          </Button>
          <Button size="small" variant="contained" onClick={save} disabled={!name || steps.length === 0}>
            Save workflow
          </Button>
        </Box>
      </Paper>
    </Box>
  );
}
