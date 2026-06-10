import RefreshIcon from "@mui/icons-material/Refresh";
import {
  Alert,
  Box,
  Button,
  CircularProgress,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Typography,
} from "@mui/material";
import { useEffect, useState } from "react";

import { apiGet, apiPost } from "lib/restApi";

interface ExtensionInfo {
  name: string;
  version: string;
  description: string;
  path: string;
  requestHooks: number;
  responseHooks: number;
  activeChecks: number;
  passiveChecks: number;
  error?: string;
}

export default function Extensions(): JSX.Element {
  const [extensions, setExtensions] = useState<ExtensionInfo[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    apiGet<{ extensions: ExtensionInfo[] | null }>("/api/extensions")
      .then((data) => setExtensions(data.extensions || []))
      .catch((err) => setError(err.message));
  }, []);

  const handleReload = () => {
    setLoading(true);
    setError("");
    apiPost<{ extensions: ExtensionInfo[] | null }>("/api/extensions/reload")
      .then((data) => setExtensions(data.extensions || []))
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  };

  return (
    <Box>
      <Typography variant="h4" sx={{ mb: 2 }}>
        Extensions
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        JavaScript extensions are loaded from <code>~/.hetty/extensions</code>. They can hook proxied traffic and
        register custom scan checks.
      </Typography>
      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}
      <Button variant="outlined" startIcon={<RefreshIcon />} onClick={handleReload} disabled={loading} sx={{ mb: 2 }}>
        {loading ? <CircularProgress size={24} /> : "Reload extensions"}
      </Button>
      <TableContainer component={Paper} variant="outlined">
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Name</TableCell>
              <TableCell>Version</TableCell>
              <TableCell>Description</TableCell>
              <TableCell>Request hooks</TableCell>
              <TableCell>Response hooks</TableCell>
              <TableCell>Active checks</TableCell>
              <TableCell>Passive checks</TableCell>
              <TableCell>Error</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {extensions.map((extension) => (
              <TableRow key={extension.path} hover>
                <TableCell>{extension.name}</TableCell>
                <TableCell>{extension.version}</TableCell>
                <TableCell>{extension.description}</TableCell>
                <TableCell>{extension.requestHooks}</TableCell>
                <TableCell>{extension.responseHooks}</TableCell>
                <TableCell>{extension.activeChecks}</TableCell>
                <TableCell>{extension.passiveChecks}</TableCell>
                <TableCell>{extension.error}</TableCell>
              </TableRow>
            ))}
            {extensions.length === 0 && (
              <TableRow>
                <TableCell colSpan={8}>
                  <Typography variant="body2" color="text.secondary">
                    No extensions loaded.
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
