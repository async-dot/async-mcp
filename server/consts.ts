import type { Config } from "../config.ts";

// Scopes (plan 4.8, T4). There is no scope for "done", "delete" or "hand over": no token can do those.
// progress:write also covers ask_on_task and give_on_task (v1.2), which run as the person.
export const SCOPES = ["tasks:read", "progress:write", "tasks:propose"] as const;
export type Scope = (typeof SCOPES)[number];
export const SCOPE_LABELS: Record<Scope, string> = {
  "tasks:read": "Read your tasks, spaces and teammates' names",
  "progress:write": "Log progress notes, and ask a teammate for something or say you sent it, as you",
  "tasks:propose": "Propose changes and new tasks for you to approve",
};

export const ACCESS_TTL_SEC = 60 * 60;                // 1 hour
export const REFRESH_TTL_SEC = 30 * 24 * 60 * 60;     // 30 days, rotated on every use
export const CODE_TTL_SEC = 60;
export const REQUEST_TTL_SEC = 10 * 60;
export const MAX_OPEN_AGENT_PROPOSALS = 20;

// MCP protocol revisions this server answers, newest first. 2026-07-28 removed the initialize
// handshake and sessions; the older ones still send initialize. Both work here because the server keeps no state.
export const PROTOCOL_VERSIONS = ["2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"] as const;

export function urls(cfg: Pick<Config, "publicUrl">) {
  const base = cfg.publicUrl;
  return {
    issuer: base,
    resource: `${base}/mcp`,            // canonical: https://async.adtivity.xyz/mcp (vercel.json rewrites it to the function)
    resourceAlt: `${base}/api/mcp`,     // the same server under the /api prefix
    authorize: `${base}/api/oauth/authorize`,
    token: `${base}/api/oauth/token`,
    register: `${base}/api/oauth/register`,
    revoke: `${base}/api/oauth/revoke`,
    prmFor: (path: string) => `${base}/.well-known/oauth-protected-resource${path}`,
  };
}
