import { Alert, Box, Button, Paper, TextField, ToggleButton, ToggleButtonGroup, Typography } from "@mui/material";
import { CSSProperties, useState } from "react";

import { apiPost } from "lib/restApi";

interface Segment {
  op: string;
  text: string;
}

interface CompareResult {
  segments: Segment[] | null;
  summary: {
    equal: number;
    inserted: number;
    deleted: number;
  };
}

function segmentStyle(op: string): CSSProperties {
  switch (op) {
    case "insert":
      return { backgroundColor: "rgba(46, 160, 67, 0.4)" };
    case "delete":
      return { backgroundColor: "rgba(248, 81, 73, 0.4)", textDecoration: "line-through" };
    default:
      return {};
  }
}

export default function Comparer(): JSX.Element {
  const [a, setA] = useState("");
  const [b, setB] = useState("");
  const [mode, setMode] = useState("words");
  const [result, setResult] = useState<CompareResult | null>(null);
  const [error, setError] = useState("");

  const handleCompare = () => {
    setError("");
    apiPost<CompareResult>("/api/comparer", { a, b, mode })
      .then(setResult)
      .catch((err) => setError(err.message));
  };

  return (
    <Box>
      <Typography variant="h4" sx={{ mb: 2 }}>
        Comparer
      </Typography>
      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}
      <Box sx={{ display: "flex", gap: 2, mb: 2 }}>
        <TextField
          label="Item A"
          fullWidth
          multiline
          minRows={8}
          value={a}
          onChange={(e) => setA(e.target.value)}
          InputProps={{ sx: { fontFamily: "'JetBrains Mono', monospace" } }}
        />
        <TextField
          label="Item B"
          fullWidth
          multiline
          minRows={8}
          value={b}
          onChange={(e) => setB(e.target.value)}
          InputProps={{ sx: { fontFamily: "'JetBrains Mono', monospace" } }}
        />
      </Box>
      <Box sx={{ display: "flex", gap: 2, mb: 2, alignItems: "center" }}>
        <ToggleButtonGroup
          exclusive
          value={mode}
          onChange={(_, value) => value && setMode(value)}
          size="small"
          color="primary"
        >
          <ToggleButton value="words">Words</ToggleButton>
          <ToggleButton value="bytes">Bytes</ToggleButton>
        </ToggleButtonGroup>
        <Button variant="contained" onClick={handleCompare} disabled={a === "" && b === ""}>
          Compare
        </Button>
      </Box>
      {result && (
        <Box>
          <Alert severity="info" sx={{ mb: 2 }}>
            {result.summary.equal} equal, {result.summary.inserted} inserted, {result.summary.deleted} deleted
            segment(s). Deletions (A only) are struck through; insertions (B only) are highlighted green.
          </Alert>
          <Paper variant="outlined" sx={{ p: 2 }}>
            <Box
              component="pre"
              sx={{ m: 0, whiteSpace: "pre-wrap", wordBreak: "break-all", fontFamily: "'JetBrains Mono', monospace" }}
            >
              {(result.segments || []).map((seg, i) => (
                <span key={i} style={segmentStyle(seg.op)}>
                  {seg.text}
                </span>
              ))}
            </Box>
          </Paper>
        </Box>
      )}
    </Box>
  );
}
