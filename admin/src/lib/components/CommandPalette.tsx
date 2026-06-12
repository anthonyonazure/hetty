import { Box, Dialog, List, ListItemButton, ListItemText, TextField } from "@mui/material";
import { useRouter } from "next/router";
import { useEffect, useRef, useState } from "react";

// Every navigable destination. Ctrl/⌘+K opens a search box to jump to any of
// them instantly — so the long sidebar never has to be scrolled.
const DESTINATIONS: { label: string; href: string; keywords?: string }[] = [
  { label: "Home", href: "/" },
  { label: "Proxy — Logs", href: "/proxy/logs", keywords: "history traffic" },
  { label: "Proxy — Intercept", href: "/proxy/intercept" },
  { label: "Sender (Repeater)", href: "/sender", keywords: "repeater replay" },
  { label: "Scope", href: "/scope" },
  { label: "Scanner", href: "/scanner", keywords: "vuln audit" },
  { label: "Spider", href: "/spider", keywords: "crawl" },
  { label: "Intruder", href: "/intruder", keywords: "fuzz" },
  { label: "Decoder", href: "/decoder" },
  { label: "Comparer", href: "/comparer", keywords: "diff" },
  { label: "Sequencer", href: "/sequencer", keywords: "token randomness" },
  { label: "Match & Replace (Rules)", href: "/rules" },
  { label: "Extensions", href: "/extensions", keywords: "plugins js" },
  { label: "Collaborator (OOB)", href: "/collab", keywords: "oast dns" },
  { label: "Authz tester", href: "/authz", keywords: "authorization idor" },
  { label: "Session profiles", href: "/sessions", keywords: "auth" },
  { label: "Content discovery", href: "/discovery", keywords: "dirb brute" },
  { label: "Site map", href: "/sitemap" },
  { label: "JWT editor", href: "/jwt", keywords: "token" },
  { label: "Annotations", href: "/annotations", keywords: "notes" },
  { label: "Param Miner", href: "/paramminer", keywords: "parameters" },
  { label: "GraphQL", href: "/graphql", keywords: "introspection" },
  { label: "Request smuggling", href: "/smuggle", keywords: "desync" },
  { label: "WebSockets", href: "/websocket" },
  { label: "Attack Surface", href: "/asm", keywords: "sn1per asm sweep" },
  { label: "Recon", href: "/recon", keywords: "subdomains portscan tls waf shodan" },
  { label: "External Tools", href: "/tools", keywords: "nmap nuclei nikto kali" },
  { label: "Workflows", href: "/workflows", keywords: "chain" },
  { label: "Monitoring", href: "/monitor", keywords: "schedule alerts diff" },
  { label: "Assets", href: "/assets", keywords: "graph inventory" },
  { label: "Save / Storage", href: "/storage", keywords: "s3 azure drive box cloud" },
  { label: "Guide", href: "/guide", keywords: "help docs how" },
  { label: "Templated scanner", href: "/templates", keywords: "nuclei yaml" },
  { label: "Macros", href: "/macros", keywords: "login session" },
  { label: "WS Repeater", href: "/wsrepeater", keywords: "websocket" },
  { label: "PoC Generators", href: "/poc", keywords: "csrf clickjacking" },
  { label: "AI Analyst", href: "/ai", keywords: "triage" },
  { label: "Projects", href: "/projects" },
  { label: "Settings", href: "/settings" },
];

export default function CommandPalette(): JSX.Element {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setOpen((o) => !o);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const q = query.trim().toLowerCase();
  const results = q
    ? DESTINATIONS.filter((d) => (d.label + " " + (d.keywords || "")).toLowerCase().includes(q))
    : DESTINATIONS;

  const go = (href: string) => {
    setOpen(false);
    setQuery("");
    router.push(href);
  };

  return (
    <Dialog
      open={open}
      onClose={() => setOpen(false)}
      fullWidth
      maxWidth="sm"
      TransitionProps={{ onEntered: () => inputRef.current?.focus() }}
    >
      <Box sx={{ p: 1 }}>
        <TextField
          inputRef={inputRef}
          fullWidth
          autoFocus
          placeholder="Jump to… (type a tool name)"
          value={query}
          onChange={(e) => {
            setQuery(e.target.value);
            setActive(0);
          }}
          onKeyDown={(e) => {
            if (e.key === "ArrowDown") setActive((a) => Math.min(a + 1, results.length - 1));
            else if (e.key === "ArrowUp") setActive((a) => Math.max(a - 1, 0));
            else if (e.key === "Enter" && results[active]) go(results[active].href);
            else if (e.key === "Escape") setOpen(false);
          }}
        />
        <List dense sx={{ maxHeight: 360, overflowY: "auto", mt: 1 }}>
          {results.map((d, i) => (
            <ListItemButton key={d.href} selected={i === active} onClick={() => go(d.href)}>
              <ListItemText primary={d.label} secondary={d.href} />
            </ListItemButton>
          ))}
        </List>
      </Box>
    </Dialog>
  );
}
