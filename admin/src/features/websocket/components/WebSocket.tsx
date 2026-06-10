import RefreshIcon from "@mui/icons-material/Refresh";
import {
  Alert,
  Box,
  Button,
  Chip,
  Divider,
  List,
  ListItemButton,
  ListItemText,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Typography,
} from "@mui/material";
import { useCallback, useEffect, useState } from "react";

import { apiDelete, apiGet } from "lib/restApi";

interface Connection {
  id: string;
  url: string;
  openedAt: string;
  closed: boolean;
  messages: number;
}

interface Message {
  id: string;
  connId: string;
  url: string;
  direction: string;
  opcode: string;
  text?: string;
  binary: boolean;
  length: number;
  time: string;
}

export default function WebSocketHistory(): JSX.Element {
  const [connections, setConnections] = useState<Connection[]>([]);
  const [messages, setMessages] = useState<Message[]>([]);
  const [selected, setSelected] = useState<string>("");
  const [error, setError] = useState("");

  const refresh = useCallback(() => {
    apiGet<{ connections: Connection[] | null }>("/api/websocket/connections")
      .then((data) => setConnections(data.connections || []))
      .catch((err) => setError(err.message));
    const q = selected ? `?connId=${encodeURIComponent(selected)}` : "";
    apiGet<{ messages: Message[] | null }>(`/api/websocket/messages${q}`)
      .then((data) => setMessages(data.messages || []))
      .catch(() => undefined);
  }, [selected]);

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, 3000);
    return () => clearInterval(id);
  }, [refresh]);

  const handleClear = () => {
    apiDelete("/api/websocket")
      .then(() => {
        setConnections([]);
        setMessages([]);
        setSelected("");
      })
      .catch((err) => setError(err.message));
  };

  return (
    <Box>
      <Typography variant="h4" sx={{ mb: 1 }}>
        WebSocket history
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        WebSocket connections and messages intercepted by the proxy, refreshed live. Browse a WebSocket app through
        Hetty to populate this view.
      </Typography>
      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}
      <Box sx={{ display: "flex", gap: 1, mb: 2 }}>
        <Button variant="outlined" startIcon={<RefreshIcon />} onClick={refresh}>
          Refresh
        </Button>
        <Button variant="outlined" color="error" onClick={handleClear}>
          Clear
        </Button>
      </Box>

      <Box sx={{ display: "flex", gap: 2 }}>
        <Paper variant="outlined" sx={{ width: 280, flexShrink: 0 }}>
          <Typography variant="subtitle2" sx={{ p: 1.5 }}>
            Connections ({connections.length})
          </Typography>
          <Divider />
          <List dense>
            <ListItemButton selected={selected === ""} onClick={() => setSelected("")}>
              <ListItemText primary="All messages" />
            </ListItemButton>
            {connections.map((c) => (
              <ListItemButton key={c.id} selected={selected === c.id} onClick={() => setSelected(c.id)}>
                <ListItemText
                  primary={c.url}
                  secondary={`${c.messages} msg${c.closed ? " · closed" : ""}`}
                  primaryTypographyProps={{ noWrap: true, fontSize: 13 }}
                />
              </ListItemButton>
            ))}
            {connections.length === 0 && (
              <Typography variant="body2" color="text.secondary" sx={{ p: 1.5 }}>
                No WebSocket connections yet.
              </Typography>
            )}
          </List>
        </Paper>

        <TableContainer component={Paper} variant="outlined" sx={{ flexGrow: 1, maxHeight: 600 }}>
          <Table size="small" stickyHeader>
            <TableHead>
              <TableRow>
                <TableCell>Dir</TableCell>
                <TableCell>Opcode</TableCell>
                <TableCell>Length</TableCell>
                <TableCell>Message</TableCell>
                <TableCell>Time</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {messages.map((m) => (
                <TableRow key={m.id} hover>
                  <TableCell>
                    <Chip
                      size="small"
                      label={m.direction === "outgoing" ? "→" : "←"}
                      color={m.direction === "outgoing" ? "primary" : "default"}
                    />
                  </TableCell>
                  <TableCell>{m.opcode}</TableCell>
                  <TableCell>{m.length}</TableCell>
                  <TableCell
                    sx={{
                      fontFamily: "'JetBrains Mono', monospace",
                      fontSize: 12,
                      maxWidth: 500,
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}
                  >
                    {m.binary ? "(binary)" : m.text}
                  </TableCell>
                  <TableCell>{m.time ? new Date(m.time).toLocaleTimeString() : ""}</TableCell>
                </TableRow>
              ))}
              {messages.length === 0 && (
                <TableRow>
                  <TableCell colSpan={5}>
                    <Typography variant="body2" color="text.secondary">
                      No messages.
                    </Typography>
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </TableContainer>
      </Box>
    </Box>
  );
}
