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

import { consumeHandoff } from "lib/handoff";
import { apiGet, apiPost } from "lib/restApi";

interface AttackResult {
  index: number;
  payloads: string[] | null;
  position: number;
  status: number;
  length: number;
  durationMs: number;
  matches?: Record<string, boolean>;
  extract?: string;
  error?: string;
}

interface AttackSummary {
  attackType: string;
  positions: number;
  requests: number;
}

interface Profile {
  name: string;
}

const attackTypes = [
  { id: "sniper", name: "Sniper" },
  { id: "batteringram", name: "Battering ram" },
  { id: "pitchfork", name: "Pitchfork" },
  { id: "clusterbomb", name: "Cluster bomb" },
];

const MARKER = "§";

function parseHeaderLines(text: string): { name: string; value: string }[] {
  const headers: { name: string; value: string }[] = [];
  for (const line of text.split("\n")) {
    const idx = line.indexOf(":");
    if (idx > 0) {
      headers.push({ name: line.slice(0, idx).trim(), value: line.slice(idx + 1).trim() });
    }
  }
  return headers;
}

export default function Intruder(): JSX.Element {
  const [method, setMethod] = useState("GET");
  const [url, setUrl] = useState("");
  const [headersText, setHeadersText] = useState("");
  const [body, setBody] = useState("");
  const [attackType, setAttackType] = useState("sniper");
  const [payloadSetsText, setPayloadSetsText] = useState<string[]>([""]);
  const [processors, setProcessors] = useState("");
  const [grepMatch, setGrepMatch] = useState("");
  const [grepExtract, setGrepExtract] = useState("");
  const [positions, setPositions] = useState<number | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [summary, setSummary] = useState<AttackSummary | null>(null);
  const [results, setResults] = useState<AttackResult[]>([]);
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [profile, setProfile] = useState("");

  useEffect(() => {
    apiGet<{ profiles: Profile[] | null }>("/api/session/profiles")
      .then((data) => setProfiles(data.profiles || []))
      .catch(() => undefined);

    const h = consumeHandoff("intruder");
    if (h) {
      setMethod(h.method || "GET");
      setUrl(h.url || "");
      setHeadersText(h.headers || "");
      setBody(h.body || "");
    }
  }, []);

  const baseSpec = () => ({
    method,
    url,
    proto: "",
    headers: parseHeaderLines(headersText),
    body,
  });

  const handleCountPositions = () => {
    setError("");
    apiPost<{ positions: number }>("/api/intruder/positions", { base: baseSpec(), marker: MARKER })
      .then((data) => setPositions(data.positions))
      .catch((err) => setError(err.message));
  };

  const handleRun = () => {
    setLoading(true);
    setError("");
    setSummary(null);
    setResults([]);
    apiPost<{ summary: AttackSummary; results: AttackResult[] | null }>("/api/intruder/run", {
      type: attackType,
      base: baseSpec(),
      payloadSets: payloadSetsText.map((text) => text.split("\n").filter((line) => line !== "")),
      processors: processors
        .split(",")
        .map((p) => p.trim())
        .filter((p) => p !== ""),
      grepMatch: grepMatch.split("\n").filter((line) => line !== ""),
      grepExtract,
      marker: MARKER,
      profile,
    })
      .then((data) => {
        setSummary(data.summary);
        setResults(data.results || []);
      })
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  };

  const setCount = attackType === "sniper" || attackType === "batteringram" ? 1 : payloadSetsText.length;

  return (
    <Box>
      <Typography variant="h4" sx={{ mb: 2 }}>
        Intruder
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        Mark payload positions by wrapping them in {MARKER} markers in the URL, headers or body (e.g.{" "}
        <code>
          https://example.com/?id={MARKER}1{MARKER}
        </code>
        ).
      </Typography>
      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}
      <Box sx={{ display: "flex", gap: 1, mb: 2 }}>
        <FormControl sx={{ width: 120 }}>
          <InputLabel id="intruder-method">Method</InputLabel>
          <Select labelId="intruder-method" label="Method" value={method} onChange={(e) => setMethod(e.target.value)}>
            {["GET", "POST", "PUT", "PATCH", "DELETE"].map((m) => (
              <MenuItem key={m} value={m}>
                {m}
              </MenuItem>
            ))}
          </Select>
        </FormControl>
        <TextField
          label="URL (with § markers)"
          fullWidth
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          InputProps={{ sx: { fontFamily: "'JetBrains Mono', monospace" } }}
        />
      </Box>
      <TextField
        label="Headers (one per line, Name: value)"
        fullWidth
        multiline
        minRows={2}
        value={headersText}
        onChange={(e) => setHeadersText(e.target.value)}
        sx={{ mb: 2 }}
        InputProps={{ sx: { fontFamily: "'JetBrains Mono', monospace" } }}
      />
      <TextField
        label="Body"
        fullWidth
        multiline
        minRows={2}
        value={body}
        onChange={(e) => setBody(e.target.value)}
        sx={{ mb: 2 }}
        InputProps={{ sx: { fontFamily: "'JetBrains Mono', monospace" } }}
      />
      <Box sx={{ display: "flex", gap: 1, mb: 2, alignItems: "center" }}>
        <FormControl sx={{ width: 200 }}>
          <InputLabel id="attack-type">Attack type</InputLabel>
          <Select
            labelId="attack-type"
            label="Attack type"
            value={attackType}
            onChange={(e) => setAttackType(e.target.value)}
          >
            {attackTypes.map((t) => (
              <MenuItem key={t.id} value={t.id}>
                {t.name}
              </MenuItem>
            ))}
          </Select>
        </FormControl>
        <Button variant="outlined" onClick={handleCountPositions} disabled={!url}>
          Count positions
        </Button>
        {positions !== null && <Chip label={`${positions} position(s)`} />}
        <FormControl sx={{ width: 200 }}>
          <InputLabel id="intruder-profile">Auth profile</InputLabel>
          <Select
            labelId="intruder-profile"
            label="Auth profile"
            value={profile}
            onChange={(e) => setProfile(e.target.value)}
          >
            <MenuItem value="">(none)</MenuItem>
            {profiles.map((p) => (
              <MenuItem key={p.name} value={p.name}>
                {p.name}
              </MenuItem>
            ))}
          </Select>
        </FormControl>
      </Box>
      {Array.from({ length: setCount }, (_, i) => (
        <TextField
          key={i}
          label={`Payload set ${i + 1} (one payload per line)`}
          fullWidth
          multiline
          minRows={3}
          value={payloadSetsText[i] || ""}
          onChange={(e) => {
            const next = [...payloadSetsText];
            next[i] = e.target.value;
            setPayloadSetsText(next);
          }}
          sx={{ mb: 2 }}
          InputProps={{ sx: { fontFamily: "'JetBrains Mono', monospace" } }}
        />
      ))}
      {setCount > 1 || attackType === "pitchfork" || attackType === "clusterbomb" ? (
        <Box sx={{ mb: 2, display: "flex", gap: 1 }}>
          <Button variant="outlined" size="small" onClick={() => setPayloadSetsText([...payloadSetsText, ""])}>
            Add payload set
          </Button>
          {payloadSetsText.length > 1 && (
            <Button variant="outlined" size="small" onClick={() => setPayloadSetsText(payloadSetsText.slice(0, -1))}>
              Remove last set
            </Button>
          )}
        </Box>
      ) : null}
      <Box sx={{ display: "flex", gap: 1, mb: 2 }}>
        <TextField
          label="Payload processors (comma-separated)"
          fullWidth
          value={processors}
          onChange={(e) => setProcessors(e.target.value)}
          helperText="Available: urlencode, base64, upper, lower, md5, sha1, sha256, prefix:<s>, suffix:<s>"
        />
      </Box>
      <Box sx={{ display: "flex", gap: 1, mb: 2 }}>
        <TextField
          label="Grep match (one string per line)"
          fullWidth
          multiline
          minRows={2}
          value={grepMatch}
          onChange={(e) => setGrepMatch(e.target.value)}
        />
        <TextField
          label="Grep extract (regex)"
          fullWidth
          value={grepExtract}
          onChange={(e) => setGrepExtract(e.target.value)}
        />
      </Box>
      <Button variant="contained" onClick={handleRun} disabled={loading || !url}>
        {loading ? <CircularProgress size={24} /> : "Start attack"}
      </Button>
      {summary && (
        <Alert severity="success" sx={{ mt: 2 }}>
          Attack finished: {summary.requests} request(s) across {summary.positions} position(s).
        </Alert>
      )}
      {results.length > 0 && (
        <TableContainer component={Paper} variant="outlined" sx={{ mt: 2, maxHeight: 500 }}>
          <Table size="small" stickyHeader>
            <TableHead>
              <TableRow>
                <TableCell>#</TableCell>
                <TableCell>Payload(s)</TableCell>
                <TableCell>Position</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Length</TableCell>
                <TableCell>Time (ms)</TableCell>
                <TableCell>Matches</TableCell>
                <TableCell>Extract</TableCell>
                <TableCell>Error</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {results.map((r) => (
                <TableRow key={r.index} hover>
                  <TableCell>{r.index}</TableCell>
                  <TableCell sx={{ fontFamily: "'JetBrains Mono', monospace", maxWidth: 300, overflow: "hidden" }}>
                    {(r.payloads || []).join(", ")}
                  </TableCell>
                  <TableCell>{r.position >= 0 ? r.position : ""}</TableCell>
                  <TableCell>{r.status}</TableCell>
                  <TableCell>{r.length}</TableCell>
                  <TableCell>{r.durationMs}</TableCell>
                  <TableCell>
                    {Object.entries(r.matches || {})
                      .filter(([, matched]) => matched)
                      .map(([needle]) => (
                        <Chip key={needle} size="small" label={needle} color="warning" sx={{ mr: 0.5 }} />
                      ))}
                  </TableCell>
                  <TableCell sx={{ fontFamily: "'JetBrains Mono', monospace" }}>{r.extract}</TableCell>
                  <TableCell>{r.error}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}
    </Box>
  );
}
