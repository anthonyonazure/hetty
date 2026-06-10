import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import {
  Alert,
  Box,
  Button,
  FormControlLabel,
  IconButton,
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

import { apiGet, apiPost } from "lib/restApi";

interface Interaction {
  id: string;
  token: string;
  protocol: string;
  remoteAddr: string;
  method: string;
  host: string;
  path: string;
  query: string;
  userAgent: string;
  time: string;
}

export default function Collab(): JSX.Element {
  const [token, setToken] = useState("");
  const [payloadUrl, setPayloadUrl] = useState("");
  const [interactions, setInteractions] = useState<Interaction[]>([]);
  const [polling, setPolling] = useState(true);
  const [error, setError] = useState("");

  const handleGenerate = () => {
    setError("");
    apiPost<{ token: string; url: string }>("/api/collab/token")
      .then((data) => {
        setToken(data.token);
        setPayloadUrl(data.url);
        setInteractions([]);
      })
      .catch((err) => setError(err.message));
  };

  useEffect(() => {
    if (!token || !polling) {
      return;
    }
    const poll = () => {
      apiGet<{ interactions: Interaction[] | null }>(`/api/collab/interactions?token=${encodeURIComponent(token)}`)
        .then((data) => setInteractions(data.interactions || []))
        .catch((err) => setError(err.message));
    };
    poll();
    const id = setInterval(poll, 5000);
    return () => clearInterval(id);
  }, [token, polling]);

  return (
    <Box>
      <Typography variant="h4" sx={{ mb: 2 }}>
        Collaborator
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        Generate a unique callback URL, place it in payloads, and watch for out-of-band interactions from vulnerable
        targets.
      </Typography>
      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}
      <Box sx={{ display: "flex", gap: 1, mb: 2, alignItems: "center" }}>
        <Button variant="contained" onClick={handleGenerate}>
          Generate payload URL
        </Button>
        {payloadUrl && (
          <>
            <TextField
              value={payloadUrl}
              fullWidth
              InputProps={{ readOnly: true, sx: { fontFamily: "'JetBrains Mono', monospace" } }}
              size="small"
            />
            <IconButton onClick={() => navigator.clipboard.writeText(payloadUrl)} title="Copy to clipboard">
              <ContentCopyIcon />
            </IconButton>
          </>
        )}
      </Box>
      {token && (
        <Box sx={{ mb: 2 }}>
          <FormControlLabel
            control={<Switch checked={polling} onChange={(e) => setPolling(e.target.checked)} />}
            label="Poll for interactions every 5s"
          />
        </Box>
      )}
      {token && (
        <TableContainer component={Paper} variant="outlined">
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Time</TableCell>
                <TableCell>Protocol</TableCell>
                <TableCell>Method</TableCell>
                <TableCell>Path</TableCell>
                <TableCell>Remote address</TableCell>
                <TableCell>User agent</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {interactions.map((interaction) => (
                <TableRow key={interaction.id} hover>
                  <TableCell>{new Date(interaction.time).toLocaleString()}</TableCell>
                  <TableCell>{interaction.protocol}</TableCell>
                  <TableCell>{interaction.method}</TableCell>
                  <TableCell sx={{ fontFamily: "'JetBrains Mono', monospace" }}>
                    {interaction.path}
                    {interaction.query && `?${interaction.query}`}
                  </TableCell>
                  <TableCell>{interaction.remoteAddr}</TableCell>
                  <TableCell sx={{ maxWidth: 300, overflow: "hidden", textOverflow: "ellipsis" }}>
                    {interaction.userAgent}
                  </TableCell>
                </TableRow>
              ))}
              {interactions.length === 0 && (
                <TableRow>
                  <TableCell colSpan={6}>
                    <Typography variant="body2" color="text.secondary">
                      No interactions recorded yet.
                    </Typography>
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </TableContainer>
      )}
    </Box>
  );
}
