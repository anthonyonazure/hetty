import {
  Alert,
  Box,
  Button,
  Chip,
  FormControl,
  InputLabel,
  MenuItem,
  Paper,
  Select,
  TextField,
  Typography,
} from "@mui/material";
import { useState } from "react";

import { apiPost } from "lib/restApi";

interface ParsedToken {
  headerJson: string;
  payloadJson: string;
  signature: string;
  alg: string;
}

interface BruteResult {
  found: boolean;
  secret: string;
  tried: number;
}

export default function Jwt(): JSX.Element {
  const [token, setToken] = useState("");
  const [header, setHeader] = useState(`{"alg":"HS256","typ":"JWT"}`);
  const [payload, setPayload] = useState(`{"sub":"123","admin":false}`);
  const [secret, setSecret] = useState("secret");
  const [alg, setAlg] = useState("HS256");
  const [noneVariant, setNoneVariant] = useState("none");
  const [output, setOutput] = useState("");
  const [brute, setBrute] = useState<BruteResult | null>(null);
  const [error, setError] = useState("");

  const handleParse = () => {
    setError("");
    setBrute(null);
    apiPost<ParsedToken>("/api/jwt/parse", { token })
      .then((t) => {
        setHeader(t.headerJson);
        setPayload(t.payloadJson);
        setOutput("");
      })
      .catch((err) => setError(err.message));
  };

  const handleSign = () => {
    setError("");
    apiPost<{ token: string }>("/api/jwt/sign", { header, payload, secret, alg })
      .then((r) => setOutput(r.token))
      .catch((err) => setError(err.message));
  };

  const handleAlgNone = () => {
    setError("");
    apiPost<{ token: string }>("/api/jwt/alg-none", { header, payload, variant: noneVariant })
      .then((r) => setOutput(r.token))
      .catch((err) => setError(err.message));
  };

  const handleBrute = () => {
    setError("");
    setBrute(null);
    apiPost<BruteResult>("/api/jwt/brute", { token })
      .then(setBrute)
      .catch((err) => setError(err.message));
  };

  return (
    <Box>
      <Typography variant="h4" sx={{ mb: 1 }}>
        JWT editor
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        Parse a token, edit its claims and re-sign, forge <code>alg:none</code>, perform HS/RS key confusion (paste the
        RSA public key as the HMAC secret), or brute-force a weak HMAC secret.
      </Typography>
      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      <TextField
        label="Token"
        fullWidth
        multiline
        minRows={2}
        value={token}
        onChange={(e) => setToken(e.target.value)}
        sx={{ mb: 1 }}
        InputProps={{ sx: { fontFamily: "'JetBrains Mono', monospace", wordBreak: "break-all" } }}
      />
      <Box sx={{ display: "flex", gap: 1, mb: 2 }}>
        <Button variant="outlined" onClick={handleParse} disabled={!token}>
          Parse
        </Button>
        <Button variant="outlined" onClick={handleBrute} disabled={!token}>
          Brute-force secret
        </Button>
      </Box>
      {brute && (
        <Alert severity={brute.found ? "warning" : "info"} sx={{ mb: 2 }}>
          {brute.found
            ? `Weak secret found after ${brute.tried} tries: "${brute.secret}"`
            : `No weak secret found (${brute.tried} candidates tried).`}
        </Alert>
      )}

      <Paper variant="outlined" sx={{ p: 2, mb: 2 }}>
        <Typography variant="subtitle2" sx={{ mb: 1 }}>
          Header
        </Typography>
        <TextField
          fullWidth
          multiline
          minRows={2}
          value={header}
          onChange={(e) => setHeader(e.target.value)}
          sx={{ mb: 2 }}
          InputProps={{ sx: { fontFamily: "'JetBrains Mono', monospace" } }}
        />
        <Typography variant="subtitle2" sx={{ mb: 1 }}>
          Payload
        </Typography>
        <TextField
          fullWidth
          multiline
          minRows={3}
          value={payload}
          onChange={(e) => setPayload(e.target.value)}
          InputProps={{ sx: { fontFamily: "'JetBrains Mono', monospace" } }}
        />
      </Paper>

      <Box sx={{ display: "flex", gap: 1, mb: 2, alignItems: "center", flexWrap: "wrap" }}>
        <FormControl sx={{ width: 130 }}>
          <InputLabel id="jwt-alg">Algorithm</InputLabel>
          <Select labelId="jwt-alg" label="Algorithm" value={alg} onChange={(e) => setAlg(e.target.value)}>
            {["HS256", "HS384", "HS512"].map((a) => (
              <MenuItem key={a} value={a}>
                {a}
              </MenuItem>
            ))}
          </Select>
        </FormControl>
        <TextField
          label="HMAC secret / public key"
          value={secret}
          onChange={(e) => setSecret(e.target.value)}
          sx={{ flexGrow: 1, minWidth: 200 }}
          InputProps={{ sx: { fontFamily: "'JetBrains Mono', monospace" } }}
        />
        <Button variant="contained" onClick={handleSign}>
          Sign
        </Button>
        <FormControl sx={{ width: 110 }}>
          <InputLabel id="jwt-none">alg:none</InputLabel>
          <Select
            labelId="jwt-none"
            label="alg:none"
            value={noneVariant}
            onChange={(e) => setNoneVariant(e.target.value)}
          >
            {["none", "None", "NONE", "nOnE"].map((v) => (
              <MenuItem key={v} value={v}>
                {v}
              </MenuItem>
            ))}
          </Select>
        </FormControl>
        <Button variant="outlined" onClick={handleAlgNone}>
          Forge alg:none
        </Button>
      </Box>

      {output && (
        <Paper variant="outlined" sx={{ p: 2 }}>
          <Chip size="small" label="forged token" color="warning" sx={{ mb: 1 }} />
          <Box
            component="pre"
            sx={{ m: 0, whiteSpace: "pre-wrap", wordBreak: "break-all", fontFamily: "'JetBrains Mono', monospace" }}
          >
            {output}
          </Box>
        </Paper>
      )}
    </Box>
  );
}
