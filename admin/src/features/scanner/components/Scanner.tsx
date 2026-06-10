import { TabContext, TabList, TabPanel } from "@mui/lab";
import {
  Alert,
  Box,
  Button,
  Chip,
  CircularProgress,
  FormControl,
  InputLabel,
  MenuItem,
  Paper,
  Select,
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
import { useCallback, useEffect, useState } from "react";

import { consumeHandoff } from "lib/handoff";
import { apiDelete, apiGet, apiPost } from "lib/restApi";

interface CapturedRequest {
  method: string;
  url: string;
  proto: string;
  header: Record<string, string[]>;
  body: string | null;
}

interface CapturedResponse {
  proto: string;
  statusCode: number;
  header: Record<string, string[]>;
  body: string | null;
}

export interface Issue {
  id: string;
  checkId: string;
  name: string;
  severity: string;
  confidence: string;
  description: string;
  remediation: string;
  url: string;
  method: string;
  param: string;
  evidence: string;
  payload: string;
  createdAt: string;
  request?: CapturedRequest;
  response?: CapturedResponse;
}

interface CheckInfo {
  id: string;
  name: string;
  kind: string;
}

interface Profile {
  name: string;
}

interface ScanSummary {
  baseRequests?: number;
  crawledPages?: number;
  scannedURLs?: number;
  tasksRun: number;
  issues: Issue[] | null;
}

const httpMethods = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

function severityColor(severity: string): "error" | "warning" | "info" | "success" | "default" {
  switch (severity) {
    case "critical":
    case "high":
      return "error";
    case "medium":
      return "warning";
    case "low":
      return "info";
    default:
      return "default";
  }
}

function decodeBody(b64: string | null | undefined): string {
  if (!b64) {
    return "";
  }
  try {
    return atob(b64);
  } catch {
    return "(binary)";
  }
}

function parseHeaderLines(text: string): Record<string, string> {
  const headers: Record<string, string> = {};
  for (const line of text.split("\n")) {
    const idx = line.indexOf(":");
    if (idx > 0) {
      headers[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
    }
  }
  return headers;
}

function IssueDetail({ issue }: { issue: Issue }): JSX.Element {
  return (
    <Paper variant="outlined" sx={{ p: 2, mt: 2 }}>
      <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
        <Typography variant="h6">{issue.name}</Typography>
        <Chip size="small" label={issue.severity} color={severityColor(issue.severity)} />
        <Chip size="small" label={issue.confidence} variant="outlined" />
      </Box>
      <Typography variant="body2" sx={{ mt: 1 }}>
        {issue.description}
      </Typography>
      {issue.remediation && (
        <Typography variant="body2" sx={{ mt: 1 }}>
          <strong>Remediation:</strong> {issue.remediation}
        </Typography>
      )}
      <Typography variant="body2" sx={{ mt: 1, fontFamily: "'JetBrains Mono', monospace" }}>
        {issue.method} {issue.url}
        {issue.param && ` (param: ${issue.param})`}
      </Typography>
      {issue.payload && (
        <Typography variant="body2" sx={{ mt: 1, fontFamily: "'JetBrains Mono', monospace" }}>
          <strong>Payload:</strong> {issue.payload}
        </Typography>
      )}
      {issue.evidence && (
        <Typography variant="body2" sx={{ mt: 1, fontFamily: "'JetBrains Mono', monospace", whiteSpace: "pre-wrap" }}>
          <strong>Evidence:</strong> {issue.evidence}
        </Typography>
      )}
      {issue.response && (
        <Box sx={{ mt: 1 }}>
          <Typography variant="subtitle2">Response (status {issue.response.statusCode})</Typography>
          <Box
            component="pre"
            sx={{
              maxHeight: 300,
              overflow: "auto",
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: 12,
              backgroundColor: "background.default",
              p: 1,
            }}
          >
            {decodeBody(issue.response.body).slice(0, 10000)}
          </Box>
        </Box>
      )}
    </Paper>
  );
}

export default function Scanner(): JSX.Element {
  const [tab, setTab] = useState("issues");
  const [issues, setIssues] = useState<Issue[]>([]);
  const [selectedIssue, setSelectedIssue] = useState<Issue | null>(null);
  const [checks, setChecks] = useState<CheckInfo[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [summary, setSummary] = useState<ScanSummary | null>(null);

  const [method, setMethod] = useState("GET");
  const [url, setUrl] = useState("");
  const [headersText, setHeadersText] = useState("");
  const [body, setBody] = useState("");

  const [seed, setSeed] = useState("");
  const [maxPages, setMaxPages] = useState("25");
  const [maxDepth, setMaxDepth] = useState("3");

  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [profile, setProfile] = useState("");

  const refreshIssues = useCallback(() => {
    apiGet<{ issues: Issue[] | null }>("/api/scanner/issues")
      .then((data) => {
        setIssues(data.issues || []);
        setError("");
      })
      .catch((err) => setError(err.message));
  }, []);

  useEffect(() => {
    refreshIssues();
    apiGet<{ checks: CheckInfo[] | null }>("/api/scanner/checks")
      .then((data) => setChecks(data.checks || []))
      .catch(() => undefined);
    apiGet<{ profiles: Profile[] | null }>("/api/session/profiles")
      .then((data) => setProfiles(data.profiles || []))
      .catch(() => undefined);

    const h = consumeHandoff("scanner");
    if (h) {
      setMethod(h.method || "GET");
      setUrl(h.url || "");
      setHeadersText(h.headers || "");
      setBody(h.body || "");
      setTab("scan");
    }
  }, [refreshIssues]);

  const handleScan = () => {
    setLoading(true);
    setError("");
    setSummary(null);
    apiPost<ScanSummary>("/api/scanner/scan", {
      method,
      url,
      headers: parseHeaderLines(headersText),
      body,
      profile,
    })
      .then((data) => {
        setSummary(data);
        refreshIssues();
      })
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  };

  const handleCrawlScan = () => {
    setLoading(true);
    setError("");
    setSummary(null);
    apiPost<ScanSummary>("/api/scanner/crawl-scan", {
      seed,
      options: { maxPages: parseInt(maxPages, 10) || 25, maxDepth: parseInt(maxDepth, 10) || 3 },
      profile,
    })
      .then((data) => {
        setSummary(data);
        refreshIssues();
      })
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  };

  const handleClear = () => {
    apiDelete("/api/scanner/issues")
      .then(() => {
        setIssues([]);
        setSelectedIssue(null);
      })
      .catch((err) => setError(err.message));
  };

  return (
    <Box>
      <Typography variant="h4" sx={{ mb: 2 }}>
        Scanner
      </Typography>
      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}
      <TabContext value={tab}>
        <TabList onChange={(_, value) => setTab(value)}>
          <Tab label={`Issues (${issues.length})`} value="issues" />
          <Tab label="Scan URL" value="scan" />
          <Tab label="Crawl & scan" value="crawl" />
          <Tab label="Checks" value="checks" />
        </TabList>
        <TabPanel value="issues" sx={{ px: 0 }}>
          <Box sx={{ mb: 1, display: "flex", gap: 1 }}>
            <Button variant="outlined" onClick={refreshIssues}>
              Refresh
            </Button>
            <Button variant="outlined" color="error" onClick={handleClear} disabled={issues.length === 0}>
              Clear all
            </Button>
          </Box>
          <TableContainer component={Paper} variant="outlined">
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Severity</TableCell>
                  <TableCell>Name</TableCell>
                  <TableCell>URL</TableCell>
                  <TableCell>Param</TableCell>
                  <TableCell>Confidence</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {issues.map((issue) => (
                  <TableRow
                    key={issue.id}
                    hover
                    selected={selectedIssue?.id === issue.id}
                    sx={{ cursor: "pointer" }}
                    onClick={() => setSelectedIssue(issue)}
                  >
                    <TableCell>
                      <Chip size="small" label={issue.severity} color={severityColor(issue.severity)} />
                    </TableCell>
                    <TableCell>{issue.name}</TableCell>
                    <TableCell sx={{ maxWidth: 400, overflow: "hidden", textOverflow: "ellipsis" }}>
                      {issue.url}
                    </TableCell>
                    <TableCell>{issue.param}</TableCell>
                    <TableCell>{issue.confidence}</TableCell>
                  </TableRow>
                ))}
                {issues.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={5}>
                      <Typography variant="body2" color="text.secondary">
                        No issues found yet. Run a scan, or browse via the proxy to trigger passive checks.
                      </Typography>
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </TableContainer>
          {selectedIssue && <IssueDetail issue={selectedIssue} />}
        </TabPanel>
        <TabPanel value="scan" sx={{ px: 0 }}>
          <Box sx={{ display: "flex", gap: 1, mb: 2 }}>
            <FormControl sx={{ width: 120 }}>
              <InputLabel id="scan-method">Method</InputLabel>
              <Select labelId="scan-method" label="Method" value={method} onChange={(e) => setMethod(e.target.value)}>
                {httpMethods.map((m) => (
                  <MenuItem key={m} value={m}>
                    {m}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
            <TextField
              label="URL"
              fullWidth
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://example.com/search?q=test"
            />
          </Box>
          <TextField
            label="Headers (one per line, Name: value)"
            fullWidth
            multiline
            minRows={3}
            value={headersText}
            onChange={(e) => setHeadersText(e.target.value)}
            sx={{ mb: 2 }}
            InputProps={{ sx: { fontFamily: "'JetBrains Mono', monospace" } }}
          />
          <TextField
            label="Body"
            fullWidth
            multiline
            minRows={3}
            value={body}
            onChange={(e) => setBody(e.target.value)}
            sx={{ mb: 2 }}
            InputProps={{ sx: { fontFamily: "'JetBrains Mono', monospace" } }}
          />
          <FormControl sx={{ width: 240, mb: 2, display: "block" }}>
            <InputLabel id="scan-profile">Auth profile</InputLabel>
            <Select
              labelId="scan-profile"
              label="Auth profile"
              value={profile}
              onChange={(e) => setProfile(e.target.value)}
              sx={{ width: 240 }}
            >
              <MenuItem value="">(none)</MenuItem>
              {profiles.map((p) => (
                <MenuItem key={p.name} value={p.name}>
                  {p.name}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
          <Box>
            <Button variant="contained" onClick={handleScan} disabled={loading || !url}>
              {loading ? <CircularProgress size={24} /> : "Scan"}
            </Button>
          </Box>
          {summary && (
            <Alert severity="success" sx={{ mt: 2 }}>
              Scan finished: {summary.tasksRun} tasks run, {(summary.issues || []).length} new issue(s) found.
            </Alert>
          )}
        </TabPanel>
        <TabPanel value="crawl" sx={{ px: 0 }}>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Crawls from the seed URL, then actively scans every discovered page.
          </Typography>
          <Box sx={{ display: "flex", gap: 1, mb: 2 }}>
            <TextField
              label="Seed URL"
              fullWidth
              value={seed}
              onChange={(e) => setSeed(e.target.value)}
              placeholder="https://example.com/"
            />
            <TextField
              label="Max pages"
              sx={{ width: 120 }}
              value={maxPages}
              onChange={(e) => setMaxPages(e.target.value)}
            />
            <TextField
              label="Max depth"
              sx={{ width: 120 }}
              value={maxDepth}
              onChange={(e) => setMaxDepth(e.target.value)}
            />
          </Box>
          <FormControl sx={{ width: 240, mb: 2, display: "block" }}>
            <InputLabel id="crawlscan-profile">Auth profile</InputLabel>
            <Select
              labelId="crawlscan-profile"
              label="Auth profile"
              value={profile}
              onChange={(e) => setProfile(e.target.value)}
              sx={{ width: 240 }}
            >
              <MenuItem value="">(none)</MenuItem>
              {profiles.map((p) => (
                <MenuItem key={p.name} value={p.name}>
                  {p.name}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
          <Button variant="contained" onClick={handleCrawlScan} disabled={loading || !seed}>
            {loading ? <CircularProgress size={24} /> : "Crawl & scan"}
          </Button>
          {summary && summary.crawledPages !== undefined && (
            <Alert severity="success" sx={{ mt: 2 }}>
              Crawled {summary.crawledPages} page(s), scanned {summary.scannedURLs} URL(s), {summary.tasksRun} tasks
              run, {(summary.issues || []).length} new issue(s) found.
            </Alert>
          )}
        </TabPanel>
        <TabPanel value="checks" sx={{ px: 0 }}>
          <TableContainer component={Paper} variant="outlined">
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>ID</TableCell>
                  <TableCell>Name</TableCell>
                  <TableCell>Kind</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {checks.map((check) => (
                  <TableRow key={check.id}>
                    <TableCell sx={{ fontFamily: "'JetBrains Mono', monospace" }}>{check.id}</TableCell>
                    <TableCell>{check.name}</TableCell>
                    <TableCell>
                      <Chip size="small" label={check.kind} variant="outlined" />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </TabPanel>
      </TabContext>
    </Box>
  );
}
