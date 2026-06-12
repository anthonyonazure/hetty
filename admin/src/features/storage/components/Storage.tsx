import {
  Alert,
  Box,
  Button,
  Chip,
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
import { useEffect, useState } from "react";

import { apiDelete, apiGet, apiPost, apiPut } from "lib/restApi";

interface Config {
  kind: string;
  dir?: string;
  endpoint?: string;
  region?: string;
  bucket?: string;
  accessKey?: string;
  secretKey?: string;
  account?: string;
  container?: string;
  accountKey?: string;
  token?: string;
  folderId?: string;
}
interface Destination {
  name: string;
  config: Config;
}

const KINDS = [
  { value: "local", label: "Local folder" },
  { value: "network", label: "Network share (UNC)" },
  { value: "s3", label: "S3-compatible" },
  { value: "azure", label: "Azure Blob" },
  { value: "gdrive", label: "Google Drive" },
  { value: "box", label: "Box" },
];

export default function Storage(): JSX.Element {
  const [dests, setDests] = useState<Destination[]>([]);
  const [name, setName] = useState("");
  const [cfg, setCfg] = useState<Config>({ kind: "local" });
  const [error, setError] = useState("");
  const [info, setInfo] = useState("");

  const refresh = () => {
    apiGet<{ destinations: Destination[] | null }>("/api/vault/destinations")
      .then((d) => setDests(d.destinations || []))
      .catch(() => undefined);
  };
  useEffect(refresh, []);

  const set = (patch: Partial<Config>) => setCfg({ ...cfg, ...patch });

  const save = () => {
    setError("");
    setInfo("");
    apiPut("/api/vault/destinations", { name, config: cfg })
      .then(() => {
        setInfo(`Saved destination "${name}".`);
        setName("");
        refresh();
      })
      .catch((e) => setError(e.message));
  };

  const del = (n: string) => apiDelete(`/api/vault/destinations?name=${encodeURIComponent(n)}`).then(refresh);

  const test = (n: string) => {
    setError("");
    setInfo("");
    apiPost<{ location: string }>("/api/vault/save", {
      destination: n,
      key: "hetty-test/hello.txt",
      data: "hetty storage test",
      contentType: "text/plain",
    })
      .then((r) => setInfo(`Test write OK → ${r.location}`))
      .catch((e) => setError(`Test write failed: ${e.message}`));
  };

  const field = (label: string, key: keyof Config, placeholder = "", pw = false) => (
    <TextField
      size="small"
      label={label}
      type={pw ? "password" : "text"}
      value={(cfg[key] as string) || ""}
      onChange={(e) => set({ [key]: e.target.value } as Partial<Config>)}
      placeholder={placeholder}
      sx={{ mb: 1, mr: 1, width: 320 }}
    />
  );

  return (
    <Box>
      <Typography variant="h4" sx={{ mb: 1 }}>
        Save / Storage
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        Define destinations where reports, exports and monitoring snapshots get saved — a local folder, a network share,
        or the cloud (S3-compatible, Azure Blob, Google Drive, Box). Other pages and the scheduler can then save to a
        destination by name. Secrets are stored locally and shown redacted here.
      </Typography>
      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}
      {info && (
        <Alert severity="success" sx={{ mb: 2 }}>
          {info}
        </Alert>
      )}

      <Paper variant="outlined" sx={{ p: 2, mb: 3 }}>
        <Typography variant="subtitle2" sx={{ mb: 1 }}>
          New destination
        </Typography>
        <Box sx={{ display: "flex", gap: 1, mb: 1, flexWrap: "wrap" }}>
          <TextField size="small" label="Name" value={name} onChange={(e) => setName(e.target.value)} />
          <TextField
            select
            size="small"
            label="Kind"
            value={cfg.kind}
            onChange={(e) => setCfg({ kind: e.target.value })}
            sx={{ width: 200 }}
          >
            {KINDS.map((k) => (
              <MenuItem key={k.value} value={k.value}>
                {k.label}
              </MenuItem>
            ))}
          </TextField>
        </Box>
        <Box sx={{ display: "flex", flexWrap: "wrap" }}>
          {(cfg.kind === "local" || cfg.kind === "network") &&
            field("Folder / UNC path", "dir", "C:\\loot or \\\\server\\share")}
          {cfg.kind === "s3" && (
            <>
              {field("Endpoint", "endpoint", "https://s3.amazonaws.com")}
              {field("Region", "region", "us-east-1")}
              {field("Bucket", "bucket")}
              {field("Access key", "accessKey")}
              {field("Secret key", "secretKey", "", true)}
            </>
          )}
          {cfg.kind === "azure" && (
            <>
              {field("Account", "account")}
              {field("Container", "container")}
              {field("Account key", "accountKey", "", true)}
            </>
          )}
          {(cfg.kind === "gdrive" || cfg.kind === "box") && (
            <>
              {field("OAuth token", "token", "", true)}
              {field("Folder ID (optional)", "folderId")}
            </>
          )}
        </Box>
        <Button variant="contained" onClick={save} disabled={!name}>
          Save destination
        </Button>
      </Paper>

      <TableContainer component={Paper} variant="outlined">
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Name</TableCell>
              <TableCell>Kind</TableCell>
              <TableCell>Where</TableCell>
              <TableCell>Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {dests.map((d) => (
              <TableRow key={d.name} hover>
                <TableCell>{d.name}</TableCell>
                <TableCell>
                  <Chip size="small" label={d.config.kind} />
                </TableCell>
                <TableCell sx={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12 }}>
                  {d.config.dir || d.config.bucket || d.config.container || d.config.folderId || "—"}
                </TableCell>
                <TableCell>
                  <Button size="small" onClick={() => test(d.name)}>
                    Test
                  </Button>
                  <Button size="small" color="error" onClick={() => del(d.name)}>
                    ✕
                  </Button>
                </TableCell>
              </TableRow>
            ))}
            {dests.length === 0 && (
              <TableRow>
                <TableCell colSpan={4}>
                  <Typography variant="body2" color="text.secondary">
                    No destinations yet.
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
