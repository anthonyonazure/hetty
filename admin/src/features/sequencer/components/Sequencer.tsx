import { Alert, Box, Button, Chip, Grid, Paper, TextField, Typography } from "@mui/material";
import { useState } from "react";

import { apiPost } from "lib/restApi";

interface Analysis {
  sampleCount: number;
  uniqueTokens: number;
  duplicateCount: number;
  minLength: number;
  maxLength: number;
  charsetSize: number;
  overallEntropyBits: number;
  meanCharEntropyBits: number;
  estimatedBitsPerToken: number;
  positionEntropyBits: number[] | null;
  quality: string;
  notes?: string[];
}

function qualityColor(quality: string): "error" | "warning" | "success" | "default" {
  switch (quality) {
    case "poor":
      return "error";
    case "moderate":
      return "warning";
    case "good":
    case "excellent":
      return "success";
    default:
      return "default";
  }
}

function Stat({ label, value }: { label: string; value: string | number }): JSX.Element {
  return (
    <Grid item xs={6} sm={3}>
      <Paper variant="outlined" sx={{ p: 2, textAlign: "center" }}>
        <Typography variant="h6">{value}</Typography>
        <Typography variant="body2" color="text.secondary">
          {label}
        </Typography>
      </Paper>
    </Grid>
  );
}

export default function Sequencer(): JSX.Element {
  const [tokensText, setTokensText] = useState("");
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [error, setError] = useState("");

  const tokens = tokensText.split("\n").filter((line) => line !== "");

  const handleAnalyze = () => {
    setError("");
    apiPost<Analysis>("/api/sequencer", { tokens })
      .then(setAnalysis)
      .catch((err) => setError(err.message));
  };

  return (
    <Box>
      <Typography variant="h4" sx={{ mb: 2 }}>
        Sequencer
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        Paste captured session tokens (one per line) to estimate their randomness.
      </Typography>
      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}
      <TextField
        label={`Tokens (${tokens.length})`}
        fullWidth
        multiline
        minRows={8}
        value={tokensText}
        onChange={(e) => setTokensText(e.target.value)}
        sx={{ mb: 2 }}
        InputProps={{ sx: { fontFamily: "'JetBrains Mono', monospace" } }}
      />
      <Button variant="contained" onClick={handleAnalyze} disabled={tokens.length === 0}>
        Analyze
      </Button>
      {analysis && (
        <Box sx={{ mt: 2 }}>
          <Box sx={{ mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <Typography variant="h6">Quality:</Typography>
            <Chip label={analysis.quality} color={qualityColor(analysis.quality)} />
          </Box>
          <Grid container spacing={2} sx={{ mb: 2 }}>
            <Stat label="Samples" value={analysis.sampleCount} />
            <Stat label="Unique tokens" value={analysis.uniqueTokens} />
            <Stat label="Duplicates" value={analysis.duplicateCount} />
            <Stat label="Charset size" value={analysis.charsetSize} />
            <Stat label="Min length" value={analysis.minLength} />
            <Stat label="Max length" value={analysis.maxLength} />
            <Stat label="Est. bits/token" value={analysis.estimatedBitsPerToken.toFixed(1)} />
            <Stat label="Mean char bits" value={analysis.meanCharEntropyBits.toFixed(2)} />
          </Grid>
          {(analysis.notes || []).map((note, i) => (
            <Alert key={i} severity="warning" sx={{ mb: 1 }}>
              {note}
            </Alert>
          ))}
          {(analysis.positionEntropyBits || []).length > 0 && (
            <Paper variant="outlined" sx={{ p: 2 }}>
              <Typography variant="subtitle2" sx={{ mb: 1 }}>
                Per-position entropy (bits)
              </Typography>
              <Box sx={{ display: "flex", alignItems: "flex-end", gap: "2px", height: 80 }}>
                {(analysis.positionEntropyBits || []).map((bits, i) => (
                  <Box
                    key={i}
                    title={`Position ${i}: ${bits.toFixed(2)} bits`}
                    sx={{
                      flex: 1,
                      maxWidth: 20,
                      height: `${Math.min(100, (bits / 8) * 100)}%`,
                      backgroundColor: "primary.main",
                    }}
                  />
                ))}
              </Box>
            </Paper>
          )}
        </Box>
      )}
    </Box>
  );
}
