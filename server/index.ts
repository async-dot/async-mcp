import type { FastifyInstance, FastifyRequest } from "fastify";
import type pg from "pg";
import type { Config } from "../config.ts";
import type { Ctx } from "../db.ts";
import type { Notifier, Poker } from "../domain/sync.ts";
import type { Limiter } from "../lib/ratelimit.ts";
import { type DocFetch, guardedFetch } from "./clientdoc.ts";
import { registerOauth } from "./oauth.ts";
import { registerMcpServer } from "./server.ts";

// Everything MCP hangs off the spine through this one call from buildApp (contract v0.8):
// the OAuth authorization server, the connected-agents API, and the MCP server itself at /mcp.
export interface McpDeps {
  app: FastifyInstance;
  cfg: Config;
  pool: pg.Pool;
  poker: Poker;
  notifier: Notifier | null;
  limiter: (name: string, max: number, windowMs: number) => Limiter;
  L: { oauthPerIp: number; registerPerIp: number; mcpPerHour: number; mcpBadAuthPerIp: number };
  requireAuth: (req: FastifyRequest) => Promise<void>;
  ctxOf: (req: FastifyRequest, teamId: string | null) => Ctx;
  appUrl: string;
  docFetch: DocFetch;
}

export type McpOpts = Omit<McpDeps, "docFetch"> & { docFetch?: DocFetch };

export function registerMcp(o: McpOpts) {
  const d: McpDeps = { ...o, docFetch: o.docFetch || guardedFetch(o.cfg.dev) };
  registerOauth(d);
  registerMcpServer(d);
}
