import {
  Alert,
  Box,
  Button,
  Chip,
  CircularProgress,
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
import { useState } from "react";

import { apiPost } from "lib/restApi";

interface Field {
  name: string;
  type: string;
  args?: string[];
}

interface GqlType {
  kind: string;
  name: string;
  fields?: Field[];
}

interface Schema {
  queryType: string;
  mutationType: string;
  subscriptionType: string;
  types: GqlType[];
}

interface Result {
  endpoint: string;
  introspectionEnabled: boolean;
  schema?: Schema;
  queryNames?: string[];
  mutationNames?: string[];
  suggestedQueries?: string[];
  note?: string;
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

export default function GraphQL(): JSX.Element {
  const [endpoint, setEndpoint] = useState("");
  const [headersText, setHeadersText] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<Result | null>(null);

  const handleIntrospect = () => {
    setLoading(true);
    setError("");
    apiPost<Result>("/api/gql/introspect", {
      endpoint,
      options: { headers: parseHeaderLines(headersText) },
    })
      .then(setResult)
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  };

  return (
    <Box>
      <Typography variant="h4" sx={{ mb: 1 }}>
        GraphQL
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        Runs the introspection query against a GraphQL endpoint, reports whether introspection is exposed, and lists the
        schema with ready-to-use query skeletons.
      </Typography>
      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      <TextField
        label="GraphQL endpoint"
        fullWidth
        value={endpoint}
        onChange={(e) => setEndpoint(e.target.value)}
        placeholder="https://example.com/graphql"
        sx={{ mb: 2 }}
      />
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
      <Button variant="contained" onClick={handleIntrospect} disabled={loading || !endpoint}>
        {loading ? <CircularProgress size={24} /> : "Introspect"}
      </Button>

      {result && (
        <Box sx={{ mt: 2 }}>
          <Alert severity={result.introspectionEnabled ? "warning" : "info"} sx={{ mb: 2 }}>
            {result.introspectionEnabled
              ? "Introspection is ENABLED — the full schema is exposed (often a finding in production)."
              : `Introspection not available. ${result.note || ""}`}
          </Alert>

          {result.introspectionEnabled && (
            <>
              {(result.suggestedQueries || []).length > 0 && (
                <Paper variant="outlined" sx={{ p: 2, mb: 2 }}>
                  <Typography variant="subtitle2" sx={{ mb: 1 }}>
                    Suggested operations
                  </Typography>
                  <Box
                    component="pre"
                    sx={{ m: 0, whiteSpace: "pre-wrap", fontFamily: "'JetBrains Mono', monospace", fontSize: 13 }}
                  >
                    {(result.suggestedQueries || []).join("\n")}
                  </Box>
                </Paper>
              )}

              <TableContainer component={Paper} variant="outlined" sx={{ maxHeight: 500 }}>
                <Table size="small" stickyHeader>
                  <TableHead>
                    <TableRow>
                      <TableCell>Type</TableCell>
                      <TableCell>Kind</TableCell>
                      <TableCell>Fields</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {(result.schema?.types || []).map((t) => (
                      <TableRow key={t.name} hover>
                        <TableCell sx={{ fontFamily: "'JetBrains Mono', monospace" }}>
                          {t.name}
                          {t.name === result.schema?.queryType && (
                            <Chip size="small" label="Query" color="primary" sx={{ ml: 0.5 }} />
                          )}
                          {t.name === result.schema?.mutationType && (
                            <Chip size="small" label="Mutation" color="secondary" sx={{ ml: 0.5 }} />
                          )}
                        </TableCell>
                        <TableCell>{t.kind}</TableCell>
                        <TableCell sx={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12 }}>
                          {(t.fields || []).map((f) => f.name + ": " + f.type).join(", ")}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </>
          )}
        </Box>
      )}
    </Box>
  );
}
