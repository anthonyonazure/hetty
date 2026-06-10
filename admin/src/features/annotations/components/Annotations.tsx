import DeleteIcon from "@mui/icons-material/Delete";
import {
  Alert,
  Box,
  Button,
  Chip,
  FormControl,
  IconButton,
  InputLabel,
  MenuItem,
  Paper,
  Select,
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

import { apiDelete, apiGet, apiPut } from "lib/restApi";

interface Annotation {
  targetId: string;
  color: string;
  note: string;
  updatedAt: string;
}

const colors = ["", "red", "orange", "yellow", "green", "cyan", "blue", "purple", "pink", "gray"];

function colorHex(c: string): string {
  const map: Record<string, string> = {
    red: "#f44336",
    orange: "#ff9800",
    yellow: "#ffeb3b",
    green: "#4caf50",
    cyan: "#00bcd4",
    blue: "#2196f3",
    purple: "#9c27b0",
    pink: "#e91e63",
    gray: "#9e9e9e",
  };
  return map[c] || "transparent";
}

export default function Annotations(): JSX.Element {
  const [annotations, setAnnotations] = useState<Annotation[]>([]);
  const [error, setError] = useState("");

  const [targetId, setTargetId] = useState("");
  const [color, setColor] = useState("");
  const [note, setNote] = useState("");

  const refresh = () => {
    apiGet<{ annotations: Annotation[] | null }>("/api/annotations")
      .then((data) => setAnnotations(data.annotations || []))
      .catch((err) => setError(err.message));
  };

  useEffect(refresh, []);

  const handleSave = () => {
    setError("");
    apiPut<Annotation>("/api/annotations", { targetId, color, note })
      .then(() => {
        setTargetId("");
        setColor("");
        setNote("");
        refresh();
      })
      .catch((err) => setError(err.message));
  };

  const handleDelete = (id: string) => {
    apiDelete(`/api/annotations?id=${encodeURIComponent(id)}`)
      .then(refresh)
      .catch((err) => setError(err.message));
  };

  return (
    <Box>
      <Typography variant="h4" sx={{ mb: 1 }}>
        Annotations
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        Triage tags and notes attached to requests by ID. Use the &quot;Annotate&quot; action on a proxy log row, or add
        one here directly.
      </Typography>
      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      <Paper variant="outlined" sx={{ p: 2, mb: 2 }}>
        <Box sx={{ display: "flex", gap: 1, alignItems: "center", flexWrap: "wrap" }}>
          <TextField
            label="Target ID (request ID)"
            value={targetId}
            onChange={(e) => setTargetId(e.target.value)}
            sx={{ width: 300 }}
            InputProps={{ sx: { fontFamily: "'JetBrains Mono', monospace" } }}
          />
          <FormControl sx={{ width: 140 }}>
            <InputLabel id="ann-color">Color</InputLabel>
            <Select labelId="ann-color" label="Color" value={color} onChange={(e) => setColor(e.target.value)}>
              {colors.map((c) => (
                <MenuItem key={c || "none"} value={c}>
                  {c || "(none)"}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
          <TextField
            label="Note"
            value={note}
            onChange={(e) => setNote(e.target.value)}
            sx={{ flexGrow: 1, minWidth: 200 }}
          />
          <Button variant="contained" onClick={handleSave} disabled={!targetId}>
            Save
          </Button>
        </Box>
      </Paper>

      <TableContainer component={Paper} variant="outlined">
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Color</TableCell>
              <TableCell>Target ID</TableCell>
              <TableCell>Note</TableCell>
              <TableCell>Updated</TableCell>
              <TableCell />
            </TableRow>
          </TableHead>
          <TableBody>
            {annotations.map((a) => (
              <TableRow key={a.targetId} hover>
                <TableCell>
                  {a.color ? (
                    <Box sx={{ width: 16, height: 16, borderRadius: "50%", backgroundColor: colorHex(a.color) }} />
                  ) : (
                    <Chip size="small" label="—" variant="outlined" />
                  )}
                </TableCell>
                <TableCell sx={{ fontFamily: "'JetBrains Mono', monospace" }}>{a.targetId}</TableCell>
                <TableCell>{a.note}</TableCell>
                <TableCell>{a.updatedAt ? new Date(a.updatedAt).toLocaleString() : ""}</TableCell>
                <TableCell>
                  <IconButton size="small" onClick={() => handleDelete(a.targetId)}>
                    <DeleteIcon fontSize="small" />
                  </IconButton>
                </TableCell>
              </TableRow>
            ))}
            {annotations.length === 0 && (
              <TableRow>
                <TableCell colSpan={5}>
                  <Typography variant="body2" color="text.secondary">
                    No annotations yet.
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
