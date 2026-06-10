import DeleteIcon from "@mui/icons-material/Delete";
import {
  Alert,
  Box,
  Button,
  Divider,
  IconButton,
  List,
  ListItemButton,
  ListItemText,
  Paper,
  TextField,
  Typography,
} from "@mui/material";
import { useEffect, useState } from "react";

import { apiDelete, apiGet, apiPut } from "lib/restApi";

interface KV {
  name: string;
  value: string;
}

interface CSRFRule {
  fetchUrl: string;
  pattern: string;
  injectHeader: string;
  injectParam: string;
}

interface Profile {
  name: string;
  headers: KV[] | null;
  cookies: KV[] | null;
  bearer: string;
  csrf?: CSRFRule | null;
}

const emptyProfile: Profile = { name: "", headers: [], cookies: [], bearer: "", csrf: null };

function kvText(kvs: KV[] | null | undefined): string {
  return (kvs || []).map((k) => `${k.name}: ${k.value}`).join("\n");
}

function parseKV(text: string): KV[] {
  const out: KV[] = [];
  for (const line of text.split("\n")) {
    const idx = line.indexOf(":");
    if (idx > 0) {
      out.push({ name: line.slice(0, idx).trim(), value: line.slice(idx + 1).trim() });
    }
  }
  return out;
}

export default function Sessions(): JSX.Element {
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [error, setError] = useState("");
  const [saved, setSaved] = useState("");

  const [name, setName] = useState("");
  const [headersText, setHeadersText] = useState("");
  const [cookiesText, setCookiesText] = useState("");
  const [bearer, setBearer] = useState("");
  const [csrfEnabled, setCsrfEnabled] = useState(false);
  const [csrf, setCsrf] = useState<CSRFRule>({ fetchUrl: "", pattern: "", injectHeader: "", injectParam: "" });

  const refresh = () => {
    apiGet<{ profiles: Profile[] | null }>("/api/session/profiles")
      .then((data) => setProfiles(data.profiles || []))
      .catch((err) => setError(err.message));
  };

  useEffect(refresh, []);

  const loadProfile = (p: Profile) => {
    setName(p.name);
    setHeadersText(kvText(p.headers));
    setCookiesText(kvText(p.cookies));
    setBearer(p.bearer || "");
    if (p.csrf) {
      setCsrfEnabled(true);
      setCsrf(p.csrf);
    } else {
      setCsrfEnabled(false);
      setCsrf({ fetchUrl: "", pattern: "", injectHeader: "", injectParam: "" });
    }
  };

  const clearForm = () => loadProfile(emptyProfile);

  const handleSave = () => {
    setError("");
    setSaved("");
    const profile: Profile = {
      name,
      headers: parseKV(headersText),
      cookies: parseKV(cookiesText),
      bearer,
      csrf: csrfEnabled ? csrf : null,
    };
    apiPut<{ profiles: Profile[] | null }>("/api/session/profiles", profile)
      .then((data) => {
        setProfiles(data.profiles || []);
        setSaved(`Saved profile "${name}".`);
      })
      .catch((err) => setError(err.message));
  };

  const handleDelete = (n: string) => {
    apiDelete(`/api/session/profiles?name=${encodeURIComponent(n)}`)
      .then(refresh)
      .catch((err) => setError(err.message));
  };

  return (
    <Box>
      <Typography variant="h4" sx={{ mb: 1 }}>
        Auth profiles
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        Named identities (headers, cookies, bearer token, optional CSRF macro) used by the authorization tester and
        other tools to run requests as a specific user.
      </Typography>
      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}
      {saved && (
        <Alert severity="success" sx={{ mb: 2 }}>
          {saved}
        </Alert>
      )}

      <Box sx={{ display: "flex", gap: 2 }}>
        <Paper variant="outlined" sx={{ width: 240, flexShrink: 0 }}>
          <Typography variant="subtitle2" sx={{ p: 1.5 }}>
            Profiles ({profiles.length})
          </Typography>
          <Divider />
          <List dense>
            {profiles.map((p) => (
              <Box key={p.name} sx={{ display: "flex", alignItems: "center" }}>
                <ListItemButton onClick={() => loadProfile(p)}>
                  <ListItemText primary={p.name} />
                </ListItemButton>
                <IconButton size="small" onClick={() => handleDelete(p.name)}>
                  <DeleteIcon fontSize="small" />
                </IconButton>
              </Box>
            ))}
            {profiles.length === 0 && (
              <Typography variant="body2" color="text.secondary" sx={{ p: 1.5 }}>
                None yet.
              </Typography>
            )}
          </List>
        </Paper>

        <Paper variant="outlined" sx={{ p: 2, flexGrow: 1 }}>
          <Box sx={{ display: "flex", gap: 1, mb: 2, alignItems: "center" }}>
            <TextField
              label="Profile name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              sx={{ width: 240 }}
            />
            <Button variant="outlined" onClick={clearForm}>
              New
            </Button>
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
            label="Cookies (one per line, name: value)"
            fullWidth
            multiline
            minRows={2}
            value={cookiesText}
            onChange={(e) => setCookiesText(e.target.value)}
            sx={{ mb: 2 }}
            InputProps={{ sx: { fontFamily: "'JetBrains Mono', monospace" } }}
          />
          <TextField
            label="Bearer token (optional)"
            fullWidth
            value={bearer}
            onChange={(e) => setBearer(e.target.value)}
            sx={{ mb: 2 }}
            InputProps={{ sx: { fontFamily: "'JetBrains Mono', monospace" } }}
          />

          <Button size="small" onClick={() => setCsrfEnabled(!csrfEnabled)} sx={{ mb: 1 }}>
            {csrfEnabled ? "Remove CSRF macro" : "Add CSRF macro"}
          </Button>
          {csrfEnabled && (
            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1, mb: 2 }}>
              <TextField
                label="Fetch URL"
                value={csrf.fetchUrl}
                onChange={(e) => setCsrf({ ...csrf, fetchUrl: e.target.value })}
                sx={{ flexGrow: 1, minWidth: 240 }}
              />
              <TextField
                label="Pattern (regex, 1 group)"
                value={csrf.pattern}
                onChange={(e) => setCsrf({ ...csrf, pattern: e.target.value })}
                sx={{ flexGrow: 1, minWidth: 240 }}
                InputProps={{ sx: { fontFamily: "'JetBrains Mono', monospace" } }}
              />
              <TextField
                label="Inject header"
                value={csrf.injectHeader}
                onChange={(e) => setCsrf({ ...csrf, injectHeader: e.target.value })}
                sx={{ width: 200 }}
              />
            </Box>
          )}

          <Box>
            <Button variant="contained" onClick={handleSave} disabled={!name}>
              Save profile
            </Button>
          </Box>
        </Paper>
      </Box>
    </Box>
  );
}
