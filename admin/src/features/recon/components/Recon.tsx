import { TabContext, TabList, TabPanel } from "@mui/lab";
import {
  Alert,
  Box,
  Button,
  Chip,
  CircularProgress,
  FormControlLabel,
  Paper,
  Switch,
  Tab,
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

interface Subdomain {
  host: string;
  resolved: boolean;
  addresses?: string[];
}

interface SubResult {
  domain: string;
  subdomains: Subdomain[] | null;
  sources: string[];
  total: number;
  resolved: number;
}

interface Tech {
  url: string;
  status: number;
  server?: string;
  poweredBy?: string;
  title?: string;
  technologies: string[] | null;
}

export default function Recon(): JSX.Element {
  const [tab, setTab] = useState("subdomains");

  const [domain, setDomain] = useState("");
  const [resolve, setResolve] = useState(true);
  const [subLoading, setSubLoading] = useState(false);
  const [subError, setSubError] = useState("");
  const [subResult, setSubResult] = useState<SubResult | null>(null);

  const [fpUrl, setFpUrl] = useState("");
  const [fpLoading, setFpLoading] = useState(false);
  const [fpError, setFpError] = useState("");
  const [tech, setTech] = useState<Tech | null>(null);

  const handleEnumerate = () => {
    setSubLoading(true);
    setSubError("");
    apiPost<SubResult>("/api/recon/subdomains", { domain, options: { resolve, concurrency: 20 } })
      .then(setSubResult)
      .catch((err) => setSubError(err.message))
      .finally(() => setSubLoading(false));
  };

  const handleFingerprint = () => {
    setFpLoading(true);
    setFpError("");
    apiPost<Tech>("/api/recon/fingerprint", { url: fpUrl })
      .then(setTech)
      .catch((err) => setFpError(err.message))
      .finally(() => setFpLoading(false));
  };

  return (
    <Box>
      <Typography variant="h4" sx={{ mb: 1 }}>
        Recon
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        Passive attack-surface discovery: enumerate a domain&apos;s subdomains from Certificate Transparency logs, and
        fingerprint a host&apos;s technology stack. Resolved hosts are added to the site map.
      </Typography>

      <TabContext value={tab}>
        <TabList onChange={(_, v) => setTab(v)}>
          <Tab label="Subdomains" value="subdomains" />
          <Tab label="Fingerprint" value="fingerprint" />
        </TabList>

        <TabPanel value="subdomains" sx={{ px: 0 }}>
          {subError && (
            <Alert severity="error" sx={{ mb: 2 }}>
              {subError}
            </Alert>
          )}
          <Box sx={{ display: "flex", gap: 1, mb: 2, alignItems: "center" }}>
            <TextField
              label="Domain"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              placeholder="example.com"
              sx={{ width: 320 }}
            />
            <FormControlLabel
              control={<Switch checked={resolve} onChange={(e) => setResolve(e.target.checked)} />}
              label="Resolve (DNS)"
            />
            <Button variant="contained" onClick={handleEnumerate} disabled={subLoading || !domain}>
              {subLoading ? <CircularProgress size={24} /> : "Enumerate"}
            </Button>
          </Box>
          {subResult && (
            <Box>
              <Alert severity="success" sx={{ mb: 2 }}>
                {subResult.total} subdomain(s) found via {(subResult.sources || []).join(", ")}
                {resolve && `, ${subResult.resolved} resolved`}.
              </Alert>
              <TableContainer component={Paper} variant="outlined" sx={{ maxHeight: 500 }}>
                <Table size="small" stickyHeader>
                  <TableHead>
                    <TableRow>
                      <TableCell>Host</TableCell>
                      <TableCell>Resolved</TableCell>
                      <TableCell>Addresses</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {(subResult.subdomains || []).map((s) => (
                      <TableRow key={s.host} hover>
                        <TableCell sx={{ fontFamily: "'JetBrains Mono', monospace" }}>{s.host}</TableCell>
                        <TableCell>
                          <Chip
                            size="small"
                            label={s.resolved ? "live" : "—"}
                            color={s.resolved ? "success" : "default"}
                          />
                        </TableCell>
                        <TableCell sx={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12 }}>
                          {(s.addresses || []).join(", ")}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Box>
          )}
        </TabPanel>

        <TabPanel value="fingerprint" sx={{ px: 0 }}>
          {fpError && (
            <Alert severity="error" sx={{ mb: 2 }}>
              {fpError}
            </Alert>
          )}
          <Box sx={{ display: "flex", gap: 1, mb: 2 }}>
            <TextField
              label="URL"
              fullWidth
              value={fpUrl}
              onChange={(e) => setFpUrl(e.target.value)}
              placeholder="https://example.com/"
            />
            <Button
              variant="contained"
              onClick={handleFingerprint}
              disabled={fpLoading || !fpUrl}
              sx={{ whiteSpace: "nowrap" }}
            >
              {fpLoading ? <CircularProgress size={24} /> : "Fingerprint"}
            </Button>
          </Box>
          {tech && (
            <Paper variant="outlined" sx={{ p: 2 }}>
              <Typography variant="subtitle1">{tech.title || tech.url}</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                Status {tech.status}
                {tech.server && ` · Server: ${tech.server}`}
                {tech.poweredBy && ` · X-Powered-By: ${tech.poweredBy}`}
              </Typography>
              <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                {(tech.technologies || []).map((t) => (
                  <Chip key={t} label={t} size="small" color="primary" variant="outlined" />
                ))}
                {(tech.technologies || []).length === 0 && (
                  <Typography variant="body2" color="text.secondary">
                    No technologies detected.
                  </Typography>
                )}
              </Box>
            </Paper>
          )}
        </TabPanel>
      </TabContext>
    </Box>
  );
}
