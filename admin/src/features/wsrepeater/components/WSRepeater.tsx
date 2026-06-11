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
import { useState } from "react";

import { apiPost } from "lib/restApi";

interface Frame {
  opcode: string;
  text?: string;
  binary: boolean;
  length: number;
}

interface RepeaterResult {
  sent: Frame;
  received: Frame[] | null;
}

function parseHeaders(text: string): { name: string; value: string }[] {
  return text
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l !== "" && l.includes(":"))
    .map((l) => {
      const idx = l.indexOf(":");
      return { name: l.slice(0, idx).trim(), value: l.slice(idx + 1).trim() };
    });
}

export default function WSRepeater(): JSX.Element {
  const [url, setUrl] = useState("");
  const [headers, setHeaders] = useState("");
  const [opcode, setOpcode] = useState("text");
  const [payload, setPayload] = useState("");
  const [timeout, setTimeoutMs] = useState("2000");
  const [maxFrames, setMaxFrames] = useState("16");
  const [insecure, setInsecure] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<RepeaterResult | null>(null);

  const handleSend = () => {
    setLoading(true);
    setError("");
    setResult(null);
    apiPost<RepeaterResult>("/api/wsrepeater", {
      url,
      headers: parseHeaders(headers),
      opcode,
      payload,
      readTimeoutMs: parseInt(timeout, 10) || 2000,
      maxFrames: parseInt(maxFrames, 10) || 16,
      insecure,
    })
      .then(setResult)
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  };

  return (
    <Box>
      <Typography variant="h4" sx={{ mb: 1 }}>
        WebSocket repeater
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        Open a WebSocket connection to a target, send a single crafted frame, and capture the frames the server sends
        back — useful for replaying and tampering with WebSocket messages.
      </Typography>
      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      <TextField
        label="WebSocket URL"
        fullWidth
        value={url}
        onChange={(e) => setUrl(e.target.value)}
        placeholder="wss://example.com/socket"
        sx={{ mb: 2 }}
      />
      <Box sx={{ display: "flex", gap: 1, mb: 2, flexWrap: "wrap" }}>
        <TextField select label="Opcode" value={opcode} onChange={(e) => setOpcode(e.target.value)} sx={{ width: 140 }}>
          <MenuItem value="text">text</MenuItem>
          <MenuItem value="binary">binary</MenuItem>
        </TextField>
        <TextField
          label="Read timeout (ms)"
          sx={{ width: 160 }}
          value={timeout}
          onChange={(e) => setTimeoutMs(e.target.value)}
        />
        <TextField
          label="Max reply frames"
          sx={{ width: 160 }}
          value={maxFrames}
          onChange={(e) => setMaxFrames(e.target.value)}
        />
        <TextField
          select
          label="TLS verify"
          value={insecure ? "skip" : "verify"}
          onChange={(e) => setInsecure(e.target.value === "skip")}
          sx={{ width: 150 }}
        >
          <MenuItem value="verify">verify</MenuItem>
          <MenuItem value="skip">skip (insecure)</MenuItem>
        </TextField>
      </Box>
      <TextField
        label="Handshake headers (Name: Value per line)"
        fullWidth
        multiline
        minRows={2}
        value={headers}
        onChange={(e) => setHeaders(e.target.value)}
        sx={{ mb: 2 }}
        InputProps={{ sx: { fontFamily: "'JetBrains Mono', monospace", fontSize: 13 } }}
      />
      <TextField
        label="Frame payload"
        fullWidth
        multiline
        minRows={3}
        value={payload}
        onChange={(e) => setPayload(e.target.value)}
        sx={{ mb: 2 }}
        InputProps={{ sx: { fontFamily: "'JetBrains Mono', monospace", fontSize: 13 } }}
      />
      <Button variant="contained" onClick={handleSend} disabled={loading || !url}>
        {loading ? <CircularProgress size={24} /> : "Send frame"}
      </Button>

      {result && (
        <Box sx={{ mt: 3 }}>
          <Alert severity="success" sx={{ mb: 2 }}>
            Sent a {result.sent.opcode} frame ({result.sent.length} bytes); received {(result.received || []).length}{" "}
            frame(s).
          </Alert>
          <TableContainer component={Paper} variant="outlined">
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Dir</TableCell>
                  <TableCell>Opcode</TableCell>
                  <TableCell>Length</TableCell>
                  <TableCell>Payload</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                <TableRow hover>
                  <TableCell>
                    <Chip size="small" color="primary" label="sent" />
                  </TableCell>
                  <TableCell>{result.sent.opcode}</TableCell>
                  <TableCell>{result.sent.length}</TableCell>
                  <TableCell sx={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, whiteSpace: "pre-wrap" }}>
                    {result.sent.text}
                  </TableCell>
                </TableRow>
                {(result.received || []).map((f, i) => (
                  <TableRow key={i} hover>
                    <TableCell>
                      <Chip size="small" label="recv" />
                    </TableCell>
                    <TableCell>{f.opcode}</TableCell>
                    <TableCell>{f.length}</TableCell>
                    <TableCell sx={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, whiteSpace: "pre-wrap" }}>
                      {f.binary ? "<binary>" : f.text}
                    </TableCell>
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
