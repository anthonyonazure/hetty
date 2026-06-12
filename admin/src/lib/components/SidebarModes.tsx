import {
  Box,
  Button,
  Checkbox,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  FormControlLabel,
  MenuItem,
  Select,
  TextField,
} from "@mui/material";
import { useEffect, useState } from "react";

// Every sidebar destination (href + label). Modes are sets of hrefs to SHOW;
// everything else is hidden via an injected <style> that targets the drawer
// anchors — so no per-item nav edits are needed.
const DESTS: { href: string; label: string }[] = [
  { href: "/proxy/logs", label: "Proxy Logs" },
  { href: "/proxy/intercept", label: "Intercept" },
  { href: "/sender", label: "Sender" },
  { href: "/scope", label: "Scope" },
  { href: "/scanner", label: "Scanner" },
  { href: "/spider", label: "Spider" },
  { href: "/intruder", label: "Intruder" },
  { href: "/decoder", label: "Decoder" },
  { href: "/comparer", label: "Comparer" },
  { href: "/sequencer", label: "Sequencer" },
  { href: "/rules", label: "Match & Replace" },
  { href: "/extensions", label: "Extensions" },
  { href: "/collab", label: "Collaborator" },
  { href: "/authz", label: "Authz" },
  { href: "/sessions", label: "Sessions" },
  { href: "/discovery", label: "Discovery" },
  { href: "/sitemap", label: "Site map" },
  { href: "/jwt", label: "JWT" },
  { href: "/annotations", label: "Annotations" },
  { href: "/paramminer", label: "Param Miner" },
  { href: "/graphql", label: "GraphQL" },
  { href: "/smuggle", label: "Smuggle" },
  { href: "/websocket", label: "WebSockets" },
  { href: "/dashboard", label: "Dashboard" },
  { href: "/asm", label: "Attack Surface" },
  { href: "/recon", label: "Recon" },
  { href: "/tools", label: "External Tools" },
  { href: "/workflows", label: "Workflows" },
  { href: "/monitor", label: "Monitoring" },
  { href: "/assets", label: "Assets" },
  { href: "/cluster", label: "Distributed" },
  { href: "/storage", label: "Save / Storage" },
  { href: "/templates", label: "Templates" },
  { href: "/macros", label: "Macros" },
  { href: "/wsrepeater", label: "WS Repeater" },
  { href: "/poc", label: "PoC Generators" },
  { href: "/ai", label: "AI Analyst" },
];

// Always visible regardless of mode.
const ALWAYS = ["/", "/projects", "/settings", "/guide"];

// Built-in modes: the hrefs to show ([] for Everything means "show all").
const BUILTIN: Record<string, string[]> = {
  Everything: [],
  Recon: ["/dashboard", "/asm", "/recon", "/tools", "/workflows", "/monitor", "/assets", "/cluster"],
  "Web app": [
    "/proxy/logs",
    "/proxy/intercept",
    "/sender",
    "/scope",
    "/scanner",
    "/spider",
    "/intruder",
    "/discovery",
    "/sitemap",
    "/graphql",
    "/jwt",
    "/macros",
    "/wsrepeater",
    "/poc",
    "/templates",
    "/websocket",
  ],
  Network: ["/dashboard", "/asm", "/recon", "/tools", "/cluster", "/assets"],
  Platform: ["/dashboard", "/asm", "/recon", "/tools", "/workflows", "/monitor", "/assets", "/cluster", "/storage"],
  Minimal: [],
};

type CustomModes = Record<string, string[]>;

export default function SidebarModes(): JSX.Element {
  const [mode, setMode] = useState("Everything");
  const [custom, setCustom] = useState<CustomModes>({});
  const [editing, setEditing] = useState(false);
  const [newName, setNewName] = useState("");
  const [picked, setPicked] = useState<string[]>([]);

  useEffect(() => {
    if (typeof window === "undefined") return;
    setMode(window.localStorage.getItem("hetty.mode") || "Everything");
    try {
      setCustom(JSON.parse(window.localStorage.getItem("hetty.customModes") || "{}"));
    } catch {
      setCustom({});
    }
  }, []);

  const allModes: CustomModes = { ...BUILTIN, ...custom };
  const visible = allModes[mode];

  const setActive = (m: string) => {
    setMode(m);
    if (typeof window !== "undefined") window.localStorage.setItem("hetty.mode", m);
  };

  const saveCustom = () => {
    const next = { ...custom, [newName]: picked };
    setCustom(next);
    if (typeof window !== "undefined") window.localStorage.setItem("hetty.customModes", JSON.stringify(next));
    setEditing(false);
    setActive(newName);
    setNewName("");
    setPicked([]);
  };

  // Build the hide-style: hide every destination not in the active set (unless
  // mode is Everything, which shows all). ALWAYS-items are never hidden.
  let css = "";
  if (mode !== "Everything") {
    const show = new Set([...(visible || []), ...ALWAYS]);
    const hidden = DESTS.filter((d) => !show.has(d.href)).map((d) => `.MuiDrawer-paper a[href="${d.href}"]`);
    if (hidden.length) css = `${hidden.join(",")}{display:none !important}`;
  }

  return (
    <Box sx={{ flex: 1, mr: 1 }}>
      {css && <style dangerouslySetInnerHTML={{ __html: css }} />}
      <Box sx={{ display: "flex", gap: 0.5, alignItems: "center" }}>
        <Select
          size="small"
          value={mode}
          onChange={(e) => setActive(e.target.value)}
          sx={{ fontSize: 12, flex: 1, ".MuiSelect-select": { py: 0.5 } }}
        >
          {Object.keys(allModes).map((m) => (
            <MenuItem key={m} value={m} sx={{ fontSize: 13 }}>
              {m}
            </MenuItem>
          ))}
        </Select>
        <Button
          size="small"
          sx={{ minWidth: 0, px: 0.5, fontSize: 11 }}
          onClick={() => {
            setPicked(visible && visible.length ? visible : []);
            setNewName(custom[mode] ? mode : "");
            setEditing(true);
          }}
        >
          +
        </Button>
      </Box>

      <Dialog open={editing} onClose={() => setEditing(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Custom sidebar mode</DialogTitle>
        <DialogContent>
          <TextField
            label="Mode name"
            size="small"
            fullWidth
            value={newName}
            onChange={(e) => setNewName(e.target.value)}
            sx={{ mb: 2, mt: 1 }}
          />
          <Box sx={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 0 }}>
            {DESTS.map((d) => (
              <FormControlLabel
                key={d.href}
                control={
                  <Checkbox
                    size="small"
                    checked={picked.includes(d.href)}
                    onChange={(e) =>
                      setPicked((p) => (e.target.checked ? [...p, d.href] : p.filter((x) => x !== d.href)))
                    }
                  />
                }
                label={<span style={{ fontSize: 13 }}>{d.label}</span>}
              />
            ))}
          </Box>
        </DialogContent>
        <DialogActions>
          {custom[newName] && (
            <Button
              color="error"
              onClick={() => {
                const next = { ...custom };
                delete next[newName];
                setCustom(next);
                if (typeof window !== "undefined")
                  window.localStorage.setItem("hetty.customModes", JSON.stringify(next));
                setEditing(false);
                setActive("Everything");
              }}
            >
              Delete
            </Button>
          )}
          <Button onClick={() => setEditing(false)}>Cancel</Button>
          <Button variant="contained" disabled={!newName} onClick={saveCustom}>
            Save & use
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
