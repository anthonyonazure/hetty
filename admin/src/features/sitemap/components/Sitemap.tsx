import ChevronRightIcon from "@mui/icons-material/ChevronRight";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import RefreshIcon from "@mui/icons-material/Refresh";
import { Alert, Box, Button, Chip, IconButton, Paper, Typography } from "@mui/material";
import { useEffect, useState } from "react";

import { apiDelete, apiGet } from "lib/restApi";

interface Node {
  name: string;
  path: string;
  url?: string;
  methods?: string[];
  statuses?: number[];
  params?: string[];
  contentTypes?: string[];
  sources?: string[];
  count: number;
  children?: Node[];
}

interface Tech {
  host: string;
  servers?: string[];
  powered?: string[];
}

interface Tree {
  hosts: Node[] | null;
  tech: Tech[] | null;
}

function TreeNode({ node, depth }: { node: Node; depth: number }): JSX.Element {
  const [open, setOpen] = useState(depth < 1);
  const hasChildren = (node.children || []).length > 0;

  return (
    <Box>
      <Box
        sx={{
          display: "flex",
          alignItems: "center",
          pl: depth * 2,
          py: 0.25,
          "&:hover": { backgroundColor: "action.hover" },
        }}
      >
        <IconButton size="small" sx={{ visibility: hasChildren ? "visible" : "hidden" }} onClick={() => setOpen(!open)}>
          {open ? <ExpandMoreIcon fontSize="small" /> : <ChevronRightIcon fontSize="small" />}
        </IconButton>
        <Typography
          component="span"
          sx={{ fontFamily: "'JetBrains Mono', monospace", fontWeight: depth === 0 ? 600 : 400 }}
        >
          {node.name || "/"}
        </Typography>
        {(node.methods || []).map((m) => (
          <Chip key={m} size="small" label={m} variant="outlined" sx={{ ml: 0.5, height: 18, fontSize: 10 }} />
        ))}
        {(node.statuses || []).map((s) => (
          <Chip key={s} size="small" label={s} sx={{ ml: 0.5, height: 18, fontSize: 10 }} />
        ))}
        {(node.params || []).length > 0 && (
          <Typography component="span" variant="caption" color="text.secondary" sx={{ ml: 1 }}>
            ?{(node.params || []).join("&")}
          </Typography>
        )}
      </Box>
      {open && (node.children || []).map((c) => <TreeNode key={c.path} node={c} depth={depth + 1} />)}
    </Box>
  );
}

export default function Sitemap(): JSX.Element {
  const [tree, setTree] = useState<Tree | null>(null);
  const [error, setError] = useState("");

  const refresh = () => {
    apiGet<Tree>("/api/sitemap")
      .then(setTree)
      .catch((err) => setError(err.message));
  };

  useEffect(refresh, []);

  const handleClear = () => {
    apiDelete("/api/sitemap")
      .then(() => setTree({ hosts: [], tech: [] }))
      .catch((err) => setError(err.message));
  };

  return (
    <Box>
      <Typography variant="h4" sx={{ mb: 1 }}>
        Site map
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        Aggregated view of every host and path Hetty has observed via the proxy, spider and content discovery.
      </Typography>
      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}
      <Box sx={{ display: "flex", gap: 1, mb: 2 }}>
        <Button variant="outlined" startIcon={<RefreshIcon />} onClick={refresh}>
          Refresh
        </Button>
        <Button variant="outlined" color="error" onClick={handleClear}>
          Clear
        </Button>
      </Box>

      {(tree?.tech || []).length > 0 && (
        <Paper variant="outlined" sx={{ p: 2, mb: 2 }}>
          <Typography variant="subtitle2" sx={{ mb: 1 }}>
            Detected technology
          </Typography>
          {(tree?.tech || []).map((t) => (
            <Box key={t.host} sx={{ mb: 0.5 }}>
              <strong>{t.host}</strong>
              {(t.servers || []).map((s) => (
                <Chip key={s} size="small" label={s} sx={{ ml: 0.5 }} />
              ))}
              {(t.powered || []).map((p) => (
                <Chip key={p} size="small" color="secondary" label={p} sx={{ ml: 0.5 }} />
              ))}
            </Box>
          ))}
        </Paper>
      )}

      <Paper variant="outlined" sx={{ p: 1 }}>
        {(tree?.hosts || []).map((host) => (
          <TreeNode key={host.name} node={host} depth={0} />
        ))}
        {(tree?.hosts || []).length === 0 && (
          <Typography variant="body2" color="text.secondary" sx={{ p: 2 }}>
            No traffic observed yet. Browse through the proxy, or run the spider / content discovery.
          </Typography>
        )}
      </Paper>
    </Box>
  );
}
