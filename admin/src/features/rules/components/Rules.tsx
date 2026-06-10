import AddIcon from "@mui/icons-material/Add";
import DeleteIcon from "@mui/icons-material/Delete";
import {
  Alert,
  Box,
  Button,
  IconButton,
  MenuItem,
  Paper,
  Select,
  Snackbar,
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

import { apiGet, apiPut } from "lib/restApi";

interface Rule {
  id: string;
  name: string;
  enabled: boolean;
  part: string;
  match: string;
  replace: string;
  isRegex: boolean;
}

const parts = [
  { id: "request_url", name: "Request URL" },
  { id: "request_header", name: "Request header" },
  { id: "request_body", name: "Request body" },
  { id: "response_header", name: "Response header" },
  { id: "response_body", name: "Response body" },
];

export default function Rules(): JSX.Element {
  const [rules, setRules] = useState<Rule[]>([]);
  const [error, setError] = useState("");
  const [savedOpen, setSavedOpen] = useState(false);

  useEffect(() => {
    apiGet<{ rules: Rule[] | null }>("/api/rules")
      .then((data) => setRules(data.rules || []))
      .catch((err) => setError(err.message));
  }, []);

  const updateRule = (index: number, patch: Partial<Rule>) => {
    setRules((prev) => prev.map((rule, i) => (i === index ? { ...rule, ...patch } : rule)));
  };

  const handleAdd = () => {
    setRules((prev) => [
      ...prev,
      {
        id: `rule-${prev.length + 1}-${Math.random().toString(36).slice(2, 8)}`,
        name: "",
        enabled: true,
        part: "request_header",
        match: "",
        replace: "",
        isRegex: false,
      },
    ]);
  };

  const handleDelete = (index: number) => {
    setRules((prev) => prev.filter((_, i) => i !== index));
  };

  const handleSave = () => {
    setError("");
    apiPut<{ rules: Rule[] | null }>("/api/rules", { rules })
      .then((data) => {
        setRules(data.rules || []);
        setSavedOpen(true);
      })
      .catch((err) => setError(err.message));
  };

  return (
    <Box>
      <Typography variant="h4" sx={{ mb: 2 }}>
        Match &amp; Replace
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        Rules rewrite proxied requests and responses on the fly. Changes only take effect after saving.
      </Typography>
      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}
      <TableContainer component={Paper} variant="outlined" sx={{ mb: 2 }}>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Enabled</TableCell>
              <TableCell>Name</TableCell>
              <TableCell>Part</TableCell>
              <TableCell>Match</TableCell>
              <TableCell>Replace</TableCell>
              <TableCell>Regex</TableCell>
              <TableCell />
            </TableRow>
          </TableHead>
          <TableBody>
            {rules.map((rule, i) => (
              <TableRow key={rule.id}>
                <TableCell>
                  <Switch
                    size="small"
                    checked={rule.enabled}
                    onChange={(e) => updateRule(i, { enabled: e.target.checked })}
                  />
                </TableCell>
                <TableCell>
                  <TextField
                    variant="standard"
                    value={rule.name}
                    onChange={(e) => updateRule(i, { name: e.target.value })}
                    placeholder="Rule name"
                  />
                </TableCell>
                <TableCell>
                  <Select
                    variant="standard"
                    value={rule.part}
                    onChange={(e) => updateRule(i, { part: e.target.value })}
                  >
                    {parts.map((part) => (
                      <MenuItem key={part.id} value={part.id}>
                        {part.name}
                      </MenuItem>
                    ))}
                  </Select>
                </TableCell>
                <TableCell>
                  <TextField
                    variant="standard"
                    fullWidth
                    value={rule.match}
                    onChange={(e) => updateRule(i, { match: e.target.value })}
                    InputProps={{ sx: { fontFamily: "'JetBrains Mono', monospace" } }}
                  />
                </TableCell>
                <TableCell>
                  <TextField
                    variant="standard"
                    fullWidth
                    value={rule.replace}
                    onChange={(e) => updateRule(i, { replace: e.target.value })}
                    InputProps={{ sx: { fontFamily: "'JetBrains Mono', monospace" } }}
                  />
                </TableCell>
                <TableCell>
                  <Switch
                    size="small"
                    checked={rule.isRegex}
                    onChange={(e) => updateRule(i, { isRegex: e.target.checked })}
                  />
                </TableCell>
                <TableCell>
                  <IconButton size="small" onClick={() => handleDelete(i)}>
                    <DeleteIcon fontSize="small" />
                  </IconButton>
                </TableCell>
              </TableRow>
            ))}
            {rules.length === 0 && (
              <TableRow>
                <TableCell colSpan={7}>
                  <Typography variant="body2" color="text.secondary">
                    No rules defined.
                  </Typography>
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </TableContainer>
      <Box sx={{ display: "flex", gap: 1 }}>
        <Button variant="outlined" startIcon={<AddIcon />} onClick={handleAdd}>
          Add rule
        </Button>
        <Button variant="contained" onClick={handleSave}>
          Save rules
        </Button>
      </Box>
      <Snackbar open={savedOpen} autoHideDuration={3000} onClose={() => setSavedOpen(false)} message="Rules saved." />
    </Box>
  );
}
