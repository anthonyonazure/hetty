import {
  Alert,
  Box,
  Button,
  CircularProgress,
  FormControlLabel,
  Paper,
  Switch,
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

interface CrawledPage {
  url: string;
  status: number;
  depth: number;
  contentType: string;
  links: string[] | null;
  error?: string;
}

interface CrawlResult {
  seed: string;
  pages: CrawledPage[] | null;
  urls: string[] | null;
}

export default function Spider(): JSX.Element {
  const [seed, setSeed] = useState("");
  const [maxPages, setMaxPages] = useState("25");
  const [maxDepth, setMaxDepth] = useState("3");
  const [sameHostOnly, setSameHostOnly] = useState(true);
  const [renderJS, setRenderJS] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<CrawlResult | null>(null);

  const handleCrawl = () => {
    setLoading(true);
    setError("");
    const endpoint = renderJS ? "/api/browser/crawl" : "/api/spider/crawl";
    apiPost<CrawlResult>(endpoint, {
      seed,
      options: {
        maxPages: parseInt(maxPages, 10) || 25,
        maxDepth: parseInt(maxDepth, 10) || 3,
        sameHostOnly,
      },
    })
      .then(setResult)
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  };

  return (
    <Box>
      <Typography variant="h4" sx={{ mb: 2 }}>
        Spider
      </Typography>
      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}
      <Box sx={{ display: "flex", gap: 1, mb: 2, alignItems: "center" }}>
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
        <FormControlLabel
          control={<Switch checked={sameHostOnly} onChange={(e) => setSameHostOnly(e.target.checked)} />}
          label="Same host only"
          sx={{ whiteSpace: "nowrap" }}
        />
        <FormControlLabel
          control={<Switch checked={renderJS} onChange={(e) => setRenderJS(e.target.checked)} />}
          label="Render JS (headless Chrome)"
          sx={{ whiteSpace: "nowrap" }}
        />
      </Box>
      <Button variant="contained" onClick={handleCrawl} disabled={loading || !seed}>
        {loading ? <CircularProgress size={24} /> : renderJS ? "Crawl (browser)" : "Crawl"}
      </Button>
      {result && (
        <Box sx={{ mt: 2 }}>
          <Alert severity="success" sx={{ mb: 2 }}>
            Crawled {(result.pages || []).length} page(s), discovered {(result.urls || []).length} unique URL(s).
          </Alert>
          <TableContainer component={Paper} variant="outlined">
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>URL</TableCell>
                  <TableCell>Status</TableCell>
                  <TableCell>Depth</TableCell>
                  <TableCell>Content type</TableCell>
                  <TableCell>Links</TableCell>
                  <TableCell>Error</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {(result.pages || []).map((page) => (
                  <TableRow key={page.url} hover>
                    <TableCell sx={{ maxWidth: 400, overflow: "hidden", textOverflow: "ellipsis" }}>
                      {page.url}
                    </TableCell>
                    <TableCell>{page.status}</TableCell>
                    <TableCell>{page.depth}</TableCell>
                    <TableCell>{page.contentType}</TableCell>
                    <TableCell>{(page.links || []).length}</TableCell>
                    <TableCell>{page.error}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </Box>
      )}
    </Box>
  );
}
