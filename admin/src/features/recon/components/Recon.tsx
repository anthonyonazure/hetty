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
interface PortRow {
  port: number;
  service: string;
  banner?: string;
}
interface PortResult {
  host: string;
  open: PortRow[] | null;
  scanned: number;
}
interface TLSResult {
  host: string;
  protocols: string[] | null;
  negotiatedCipher: string;
  cert: {
    subject: string;
    issuer: string;
    sans?: string[];
    notAfter: string;
    daysUntilExpiry: number;
    keyType: string;
    keyBits: number;
    signatureAlgorithm: string;
    selfSigned: boolean;
  };
  issues: string[] | null;
}
interface WAFResult {
  url: string;
  detected: { name: string; confidence: string; evidence: string }[] | null;
  blocked: boolean;
  baselineStatus: number;
  probeStatus: number;
}
interface ShodanResult {
  ip: string;
  org: string;
  os: string;
  hostnames: string[] | null;
  ports: number[] | null;
  vulns: string[] | null;
  services: { port: number; transport: string; product: string; version: string }[] | null;
}

function useRunner<T>() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<T | null>(null);
  const run = (p: Promise<T>) => {
    setLoading(true);
    setError("");
    setResult(null);
    p.then(setResult)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  };
  return { loading, error, result, run };
}

function Errs({ error }: { error: string }): JSX.Element | null {
  if (!error) return null;
  return (
    <Alert severity="error" sx={{ mb: 2 }}>
      {error}
    </Alert>
  );
}

export default function Recon(): JSX.Element {
  const [tab, setTab] = useState("subdomains");

  const [domain, setDomain] = useState("");
  const [resolve, setResolve] = useState(true);
  const sub = useRunner<SubResult>();

  const [fpUrl, setFpUrl] = useState("");
  const fp = useRunner<Tech>();

  const [psHost, setPsHost] = useState("");
  const [psFull, setPsFull] = useState(false);
  const ps = useRunner<PortResult>();

  const [tlsHost, setTlsHost] = useState("");
  const tls = useRunner<TLSResult>();

  const [wafUrl, setWafUrl] = useState("");
  const waf = useRunner<WAFResult>();

  const [shotUrl, setShotUrl] = useState("");
  const shot = useRunner<{ pngBase64: string; bytes: number }>();

  const [shodanIP, setShodanIP] = useState("");
  const shodan = useRunner<ShodanResult>();

  return (
    <Box>
      <Typography variant="h4" sx={{ mb: 1 }}>
        Recon
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        Native recon toolbox: subdomains, fingerprinting, port scanning, TLS analysis, WAF detection, screenshots and
        Shodan OSINT. Results from the resolving tabs feed the site map.
      </Typography>

      <TabContext value={tab}>
        <TabList onChange={(_, v) => setTab(v)} variant="scrollable" scrollButtons="auto">
          <Tab label="Subdomains" value="subdomains" />
          <Tab label="Fingerprint" value="fingerprint" />
          <Tab label="Port Scan" value="portscan" />
          <Tab label="TLS/SSL" value="tls" />
          <Tab label="WAF" value="waf" />
          <Tab label="Screenshot" value="screenshot" />
          <Tab label="Shodan" value="shodan" />
        </TabList>

        {/* --- Subdomains --- */}
        <TabPanel value="subdomains" sx={{ px: 0 }}>
          <Errs error={sub.error} />
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
            <Button
              variant="contained"
              disabled={sub.loading || !domain}
              onClick={() =>
                sub.run(apiPost<SubResult>("/api/recon/subdomains", { domain, options: { resolve, concurrency: 20 } }))
              }
            >
              {sub.loading ? <CircularProgress size={24} /> : "Enumerate"}
            </Button>
          </Box>
          {sub.result && (
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
                  {(sub.result.subdomains || []).map((s) => (
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
          )}
        </TabPanel>

        {/* --- Fingerprint --- */}
        <TabPanel value="fingerprint" sx={{ px: 0 }}>
          <Errs error={fp.error} />
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
              disabled={fp.loading || !fpUrl}
              onClick={() => fp.run(apiPost<Tech>("/api/recon/fingerprint", { url: fpUrl }))}
              sx={{ whiteSpace: "nowrap" }}
            >
              {fp.loading ? <CircularProgress size={24} /> : "Fingerprint"}
            </Button>
          </Box>
          {fp.result && (
            <Paper variant="outlined" sx={{ p: 2 }}>
              <Typography variant="subtitle1">{fp.result.title || fp.result.url}</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                Status {fp.result.status}
                {fp.result.server && ` · Server: ${fp.result.server}`}
                {fp.result.poweredBy && ` · X-Powered-By: ${fp.result.poweredBy}`}
              </Typography>
              <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                {(fp.result.technologies || []).map((t) => (
                  <Chip key={t} label={t} size="small" color="primary" variant="outlined" />
                ))}
              </Box>
            </Paper>
          )}
        </TabPanel>

        {/* --- Port Scan --- */}
        <TabPanel value="portscan" sx={{ px: 0 }}>
          <Errs error={ps.error} />
          <Box sx={{ display: "flex", gap: 1, mb: 2, alignItems: "center" }}>
            <TextField
              label="Host"
              value={psHost}
              onChange={(e) => setPsHost(e.target.value)}
              placeholder="example.com / 10.0.0.5"
              sx={{ width: 320 }}
            />
            <FormControlLabel
              control={<Switch checked={psFull} onChange={(e) => setPsFull(e.target.checked)} />}
              label="Full (1-1024)"
            />
            <Button
              variant="contained"
              disabled={ps.loading || !psHost}
              onClick={() => {
                const options = psFull
                  ? { ports: Array.from({ length: 1024 }, (_, i) => i + 1), banner: true }
                  : { topPorts: 100, banner: true };
                ps.run(apiPost<PortResult>("/api/portscan", { host: psHost, options }));
              }}
            >
              {ps.loading ? <CircularProgress size={24} /> : "Scan"}
            </Button>
          </Box>
          {ps.result && (
            <>
              <Alert severity="success" sx={{ mb: 2 }}>
                {(ps.result.open || []).length} open / {ps.result.scanned} scanned on {ps.result.host}.
              </Alert>
              <TableContainer component={Paper} variant="outlined">
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Port</TableCell>
                      <TableCell>Service</TableCell>
                      <TableCell>Banner</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {(ps.result.open || []).map((p) => (
                      <TableRow key={p.port} hover>
                        <TableCell>{p.port}</TableCell>
                        <TableCell>{p.service}</TableCell>
                        <TableCell sx={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12 }}>
                          {p.banner}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </>
          )}
        </TabPanel>

        {/* --- TLS --- */}
        <TabPanel value="tls" sx={{ px: 0 }}>
          <Errs error={tls.error} />
          <Box sx={{ display: "flex", gap: 1, mb: 2 }}>
            <TextField
              label="Host"
              fullWidth
              value={tlsHost}
              onChange={(e) => setTlsHost(e.target.value)}
              placeholder="example.com (port 443 default)"
            />
            <Button
              variant="contained"
              disabled={tls.loading || !tlsHost}
              onClick={() => tls.run(apiPost<TLSResult>("/api/tlsscan", { host: tlsHost }))}
              sx={{ whiteSpace: "nowrap" }}
            >
              {tls.loading ? <CircularProgress size={24} /> : "Analyze"}
            </Button>
          </Box>
          {tls.result && (
            <Paper variant="outlined" sx={{ p: 2 }}>
              <Typography variant="subtitle1">{tls.result.cert.subject || tls.result.host}</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                Protocols: {(tls.result.protocols || []).join(", ")} · Cipher: {tls.result.negotiatedCipher}
                <br />
                Issuer: {tls.result.cert.issuer} · {tls.result.cert.keyType} {tls.result.cert.keyBits}-bit ·{" "}
                {tls.result.cert.signatureAlgorithm} · expires in {tls.result.cert.daysUntilExpiry}d
              </Typography>
              {(tls.result.issues || []).length > 0 ? (
                (tls.result.issues || []).map((i) => (
                  <Alert key={i} severity="warning" sx={{ mb: 0.5, py: 0 }}>
                    {i}
                  </Alert>
                ))
              ) : (
                <Alert severity="success">No TLS issues detected.</Alert>
              )}
            </Paper>
          )}
        </TabPanel>

        {/* --- WAF --- */}
        <TabPanel value="waf" sx={{ px: 0 }}>
          <Errs error={waf.error} />
          <Box sx={{ display: "flex", gap: 1, mb: 2 }}>
            <TextField
              label="URL"
              fullWidth
              value={wafUrl}
              onChange={(e) => setWafUrl(e.target.value)}
              placeholder="https://example.com/"
            />
            <Button
              variant="contained"
              disabled={waf.loading || !wafUrl}
              onClick={() => waf.run(apiPost<WAFResult>("/api/wafdetect", { url: wafUrl }))}
              sx={{ whiteSpace: "nowrap" }}
            >
              {waf.loading ? <CircularProgress size={24} /> : "Detect"}
            </Button>
          </Box>
          {waf.result && (
            <Paper variant="outlined" sx={{ p: 2 }}>
              <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mb: 1 }}>
                {(waf.result.detected || []).map((d) => (
                  <Chip key={d.name} label={`${d.name} (${d.confidence})`} color="secondary" title={d.evidence} />
                ))}
                {(waf.result.detected || []).length === 0 && (
                  <Typography variant="body2">No WAF fingerprinted.</Typography>
                )}
              </Box>
              <Alert severity={waf.result.blocked ? "warning" : "info"}>
                Malicious probe {waf.result.blocked ? "was blocked" : "was not blocked"} (baseline{" "}
                {waf.result.baselineStatus} → probe {waf.result.probeStatus}).
              </Alert>
            </Paper>
          )}
        </TabPanel>

        {/* --- Screenshot --- */}
        <TabPanel value="screenshot" sx={{ px: 0 }}>
          <Errs error={shot.error} />
          <Box sx={{ display: "flex", gap: 1, mb: 2 }}>
            <TextField
              label="URL"
              fullWidth
              value={shotUrl}
              onChange={(e) => setShotUrl(e.target.value)}
              placeholder="https://example.com/"
            />
            <Button
              variant="contained"
              disabled={shot.loading || !shotUrl}
              onClick={() =>
                shot.run(apiPost<{ pngBase64: string; bytes: number }>("/api/screenshot", { url: shotUrl }))
              }
              sx={{ whiteSpace: "nowrap" }}
            >
              {shot.loading ? <CircularProgress size={24} /> : "Capture"}
            </Button>
          </Box>
          {shot.result && (
            <Paper variant="outlined" sx={{ p: 1 }}>
              {/* eslint-disable-next-line @next/next/no-img-element */}
              <img
                src={`data:image/png;base64,${shot.result.pngBase64}`}
                alt="screenshot"
                style={{ maxWidth: "100%", border: "1px solid #ccc" }}
              />
            </Paper>
          )}
        </TabPanel>

        {/* --- Shodan --- */}
        <TabPanel value="shodan" sx={{ px: 0 }}>
          <Errs error={shodan.error} />
          <Box sx={{ display: "flex", gap: 1, mb: 2 }}>
            <TextField
              label="IP address"
              value={shodanIP}
              onChange={(e) => setShodanIP(e.target.value)}
              placeholder="8.8.8.8"
              sx={{ width: 320 }}
            />
            <Button
              variant="contained"
              disabled={shodan.loading || !shodanIP}
              onClick={() => shodan.run(apiPost<ShodanResult>("/api/osint/shodan", { ip: shodanIP }))}
            >
              {shodan.loading ? <CircularProgress size={24} /> : "Lookup"}
            </Button>
          </Box>
          {shodan.result && (
            <Paper variant="outlined" sx={{ p: 2 }}>
              <Typography variant="subtitle1">
                {shodan.result.ip} {shodan.result.org && `· ${shodan.result.org}`}{" "}
                {shodan.result.os && `· ${shodan.result.os}`}
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                {(shodan.result.hostnames || []).join(", ")}
              </Typography>
              <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mb: 1 }}>
                {(shodan.result.ports || []).map((p) => (
                  <Chip key={p} label={p} size="small" />
                ))}
                {(shodan.result.vulns || []).map((v) => (
                  <Chip key={v} label={v} size="small" color="error" />
                ))}
              </Box>
              {(shodan.result.services || []).length > 0 && (
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell>Port</TableCell>
                        <TableCell>Product</TableCell>
                        <TableCell>Version</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {(shodan.result.services || []).map((s, i) => (
                        <TableRow key={i}>
                          <TableCell>
                            {s.port}/{s.transport}
                          </TableCell>
                          <TableCell>{s.product}</TableCell>
                          <TableCell>{s.version}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              )}
            </Paper>
          )}
        </TabPanel>
      </TabContext>
    </Box>
  );
}
