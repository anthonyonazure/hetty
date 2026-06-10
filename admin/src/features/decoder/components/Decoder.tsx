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
import { useEffect, useState } from "react";

import { apiGet, apiPost } from "lib/restApi";

interface Codec {
  id: string;
  name: string;
  canEncode: boolean;
  canDecode: boolean;
}

interface DecodeResult {
  output?: string;
  outputBase64: string;
  isBinary: boolean;
}

interface SmartStep {
  codec: string;
  output: string;
}

export default function Decoder(): JSX.Element {
  const [codecs, setCodecs] = useState<Codec[]>([]);
  const [codec, setCodec] = useState("base64");
  const [input, setInput] = useState("");
  const [output, setOutput] = useState("");
  const [isBinary, setIsBinary] = useState(false);
  const [steps, setSteps] = useState<SmartStep[]>([]);
  const [error, setError] = useState("");

  useEffect(() => {
    apiGet<{ codecs: Codec[] | null }>("/api/decoder/codecs")
      .then((data) => setCodecs(data.codecs || []))
      .catch((err) => setError(err.message));
  }, []);

  const selected = codecs.find((c) => c.id === codec);

  const handleApply = (op: "encode" | "decode") => {
    setError("");
    setSteps([]);
    apiPost<DecodeResult>("/api/decoder", { codec, op, input })
      .then((data) => {
        setIsBinary(data.isBinary);
        setOutput(data.isBinary ? data.outputBase64 : data.output || "");
      })
      .catch((err) => setError(err.message));
  };

  const handleSmartDecode = () => {
    setError("");
    setOutput("");
    apiPost<{ steps: SmartStep[] | null }>("/api/decoder/smart", { input })
      .then((data) => {
        setSteps(data.steps || []);
        if (!data.steps || data.steps.length === 0) {
          setError("No known encoding detected.");
        }
      })
      .catch((err) => setError(err.message));
  };

  return (
    <Box>
      <Typography variant="h4" sx={{ mb: 2 }}>
        Decoder
      </Typography>
      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}
      <TextField
        label="Input"
        fullWidth
        multiline
        minRows={4}
        value={input}
        onChange={(e) => setInput(e.target.value)}
        sx={{ mb: 2 }}
        InputProps={{ sx: { fontFamily: "'JetBrains Mono', monospace" } }}
      />
      <Box sx={{ display: "flex", gap: 1, mb: 2, alignItems: "center" }}>
        <FormControl sx={{ width: 220 }}>
          <InputLabel id="decoder-codec">Codec</InputLabel>
          <Select labelId="decoder-codec" label="Codec" value={codec} onChange={(e) => setCodec(e.target.value)}>
            {codecs.map((c) => (
              <MenuItem key={c.id} value={c.id}>
                {c.name}
              </MenuItem>
            ))}
          </Select>
        </FormControl>
        <Button variant="contained" onClick={() => handleApply("encode")} disabled={!input || !selected?.canEncode}>
          Encode
        </Button>
        <Button variant="contained" onClick={() => handleApply("decode")} disabled={!input || !selected?.canDecode}>
          Decode
        </Button>
        <Button variant="outlined" onClick={handleSmartDecode} disabled={!input}>
          Smart decode
        </Button>
      </Box>
      {output !== "" && (
        <Paper variant="outlined" sx={{ p: 2, mb: 2 }}>
          {isBinary && <Chip size="small" label="binary output (base64)" color="warning" sx={{ mb: 1 }} />}
          <Box
            component="pre"
            sx={{ m: 0, whiteSpace: "pre-wrap", wordBreak: "break-all", fontFamily: "'JetBrains Mono', monospace" }}
          >
            {output}
          </Box>
        </Paper>
      )}
      {steps.length > 0 && (
        <Box>
          <Typography variant="h6" sx={{ mb: 1 }}>
            Smart decode chain
          </Typography>
          {steps.map((step, i) => (
            <Paper key={i} variant="outlined" sx={{ p: 2, mb: 1 }}>
              <Chip size="small" label={step.codec} sx={{ mb: 1 }} />
              <Box
                component="pre"
                sx={{
                  m: 0,
                  whiteSpace: "pre-wrap",
                  wordBreak: "break-all",
                  fontFamily: "'JetBrains Mono', monospace",
                }}
              >
                {step.output}
              </Box>
            </Paper>
          ))}
        </Box>
      )}
    </Box>
  );
}
