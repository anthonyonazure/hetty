// handoff carries a request from the proxy log (or any tool) to another tool
// page via sessionStorage, powering the "Send to …" context-menu actions.

export interface HandoffRequest {
  method: string;
  url: string;
  headers: string; // newline-joined "Name: value"
  body: string;
}

const KEY = "hetty:handoff";

export function setHandoff(tool: string, req: HandoffRequest): void {
  if (typeof window === "undefined") {
    return;
  }
  window.sessionStorage.setItem(KEY, JSON.stringify({ tool, req }));
}

export function consumeHandoff(tool: string): HandoffRequest | null {
  if (typeof window === "undefined") {
    return null;
  }
  const raw = window.sessionStorage.getItem(KEY);
  if (!raw) {
    return null;
  }
  try {
    const parsed = JSON.parse(raw) as { tool: string; req: HandoffRequest };
    if (parsed.tool !== tool) {
      return null;
    }
    window.sessionStorage.removeItem(KEY);
    return parsed.req;
  } catch {
    return null;
  }
}
