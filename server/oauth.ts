import crypto from "node:crypto";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import { withTx } from "../db.ts";
import { audit } from "../domain/audit.ts";
import { myTeams } from "../domain/auth.ts";
import { badRequest, notFound, tooMany } from "../lib/errors.ts";
import { secretToken, sha256, uuidv7 } from "../lib/ids.ts";
import { ClientDocError, cleanName, fetchClientDoc, isLoopbackHost, redirectMatches, validRedirectUri } from "./clientdoc.ts";
import { ACCESS_TTL_SEC, CODE_TTL_SEC, REFRESH_TTL_SEC, REQUEST_TTL_SEC, SCOPE_LABELS, SCOPES, type Scope, urls } from "./consts.ts";
import type { McpDeps } from "./index.ts";

// The spine as an OAuth 2.1 authorization server for the MCP server (MCP authorization, 2026-07-28):
// RFC 8414 metadata, authorization code + PKCE (S256 only), RFC 8707 resource, Client ID Metadata
// Documents with Dynamic Client Registration (RFC 7591) as the fallback, RFC 9207 iss, RFC 7009 revoke.
// Public clients only (token_endpoint_auth_method none): an agent has nowhere safe to keep a secret.

interface ClientRow { id: string; client_id: string; registration: "cimd" | "dcr"; name: string; client_uri: string | null; logo_uri: string | null; redirect_uris: string[]; metadata_fetched_at: string | null }

const CIMD_REFRESH_MS = 60 * 60 * 1000;
const CHALLENGE = /^[A-Za-z0-9_-]{43}$/;           // base64url of a SHA-256 digest
const VERIFIER = /^[A-Za-z0-9._~-]{43,128}$/;

const oauthError = (reply: FastifyReply, status: number, error: string, description: string) =>
  reply.status(status).header("cache-control", "no-store").header("pragma", "no-cache").send({ error, error_description: description });

const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
function errorPage(reply: FastifyReply, status: number, message: string) {
  return reply.status(status).header("content-type", "text/html; charset=utf-8").header("cache-control", "no-store")
    .header("content-security-policy", "default-src 'none'; style-src 'unsafe-inline'").header("x-frame-options", "DENY")
    .send(`<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Async</title><body style="font:16px system-ui;max-width:32rem;margin:15vh auto;padding:0 1rem;color:#222"><h1 style="font-size:1.2rem">This agent could not connect</h1><p>${esc(message)}</p><p style="color:#666">Nothing was shared. You can close this tab.</p></body>`);
}

function scopesFrom(raw: unknown): Scope[] {
  const asked = typeof raw === "string" ? raw.split(/\s+/).filter(Boolean) : [];
  const ok = SCOPES.filter((s) => asked.includes(s));
  return ok.length ? ok : [...SCOPES];            // unknown or missing scopes: ask for all of ours, the person trims them
}

export function registerOauth(d: McpDeps) {
  const { app, cfg, pool } = d;
  const U = urls(cfg);
  const allowLocal = cfg.dev;
  const authzIp = d.limiter("oauth_authz_ip", d.L.oauthPerIp, 10 * 60_000);
  const tokenIp = d.limiter("oauth_token_ip", d.L.oauthPerIp * 2, 10 * 60_000);
  const registerIp = d.limiter("oauth_register_ip", d.L.registerPerIp, 10 * 60_000);
  const decideUser = d.limiter("oauth_decide_user", Math.max(30, Math.floor(d.L.oauthPerIp / 2)), 10 * 60_000);   // 30 per person per 10 minutes by default (also covers Change)

  const anon = { userId: null, teamId: null };
  const getClient = (clientId: string) => withTx(pool, anon, async (c) =>
    (await c.query("select * from oauth_client_get($1)", [clientId])).rows[0] as ClientRow | undefined);

  // The client for an authorization request: a cached or freshly fetched metadata document, or a registered client.
  async function resolveClient(clientId: string): Promise<ClientRow> {
    const looksLikeUrl = /^https?:\/\//i.test(clientId);
    const cached = await getClient(clientId);
    if (!looksLikeUrl) {
      if (!cached || cached.registration !== "dcr") throw new ClientDocError("Unknown client.");
      return cached;
    }
    if (cached && cached.metadata_fetched_at && Date.now() - Date.parse(cached.metadata_fetched_at) < CIMD_REFRESH_MS) return cached;
    try {
      const doc = await fetchClientDoc(clientId, d.docFetch, allowLocal);
      await withTx(pool, anon, (c) => c.query("select oauth_client_upsert($1, $2, 'cimd', $3, $4, $5, $6)",
        [uuidv7(), doc.client_id, doc.name, doc.redirect_uris, doc.client_uri, doc.logo_uri]));
      return (await getClient(clientId))!;
    } catch (e) {
      if (cached) { app.log.warn({ client: clientId }, "client metadata refresh failed; using the cached copy"); return cached; }
      throw e;
    }
  }

  // ---------- metadata (public, cacheable) ----------
  const meta = (reply: FastifyReply) => reply.header("cache-control", "public, max-age=300").header("access-control-allow-origin", "*");
  const prm = (resource: string) => ({
    resource,
    authorization_servers: [U.issuer],
    scopes_supported: [...SCOPES],
    bearer_methods_supported: ["header"],
    resource_name: "Async",
  });
  // RFC 9728: the metadata URL is the well-known prefix with the resource's path appended.
  app.get("/.well-known/oauth-protected-resource", async (_r, reply) => meta(reply).send(prm(U.resource)));
  app.get("/.well-known/oauth-protected-resource/mcp", async (_r, reply) => meta(reply).send(prm(U.resource)));
  app.get("/.well-known/oauth-protected-resource/api/mcp", async (_r, reply) => meta(reply).send(prm(U.resourceAlt)));
  app.get("/.well-known/oauth-authorization-server", async (_r, reply) => meta(reply).send({
    issuer: U.issuer,
    authorization_endpoint: U.authorize,
    token_endpoint: U.token,
    registration_endpoint: U.register,
    revocation_endpoint: U.revoke,
    response_types_supported: ["code"],
    response_modes_supported: ["query"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
    revocation_endpoint_auth_methods_supported: ["none"],
    scopes_supported: [...SCOPES],
    client_id_metadata_document_supported: true,
    authorization_response_iss_parameter_supported: true,
  }));

  // ---------- OAuth endpoints (their own plugin, so the form parser stays local) ----------
  app.register(async (o) => {
    o.addContentTypeParser("application/x-www-form-urlencoded", { parseAs: "string", bodyLimit: 16 * 1024 }, (_req, body, done) => {
      try { done(null, Object.fromEntries(new URLSearchParams(body as string))); } catch (e) { done(e as Error); }
    });

    // Dynamic Client Registration (RFC 7591). Deprecated in favour of metadata documents, kept for clients that need it.
    o.post("/oauth/register", async (req, reply) => {
      if (!(await registerIp.take(req.ip))) throw tooMany();
      const b = (req.body && typeof req.body === "object" ? req.body : {}) as Record<string, unknown>;
      const uris = b.redirect_uris;
      if (!Array.isArray(uris) || !uris.length || uris.length > 10) return oauthError(reply, 400, "invalid_redirect_uri", "Send redirect_uris (1 to 10).");
      if (!uris.every((u) => typeof u === "string" && validRedirectUri(u))) return oauthError(reply, 400, "invalid_redirect_uri", "Redirect URIs must be https, http on localhost, or a private-use scheme, with no fragment.");
      const method = b.token_endpoint_auth_method;
      if (method !== undefined && method !== "none") return oauthError(reply, 400, "invalid_client_metadata", "Only public clients are supported (token_endpoint_auth_method none).");
      const grants = Array.isArray(b.grant_types) ? b.grant_types : ["authorization_code", "refresh_token"];
      if (!grants.every((g) => g === "authorization_code" || g === "refresh_token")) return oauthError(reply, 400, "invalid_client_metadata", "Only authorization_code and refresh_token are supported.");
      const name = cleanName(b.client_name) || "An agent";
      const clientId = "dcr_" + secretToken(18);
      await withTx(pool, anon, (c) => c.query("select oauth_client_upsert($1, $2, 'dcr', $3, $4, null, null)", [uuidv7(), clientId, name, uris]));
      return reply.status(201).header("cache-control", "no-store").send({
        client_id: clientId, client_id_issued_at: Math.floor(Date.now() / 1000), client_name: name, redirect_uris: uris,
        grant_types: ["authorization_code", "refresh_token"], response_types: ["code"], token_endpoint_auth_method: "none", scope: SCOPES.join(" "),
      });
    });

    // The browser lands here from the agent. Nothing is granted: this stores the request and sends the person
    // to the consent screen in the web app, where they sign in and decide.
    o.get("/oauth/authorize", async (req, reply) => {
      if (!(await authzIp.take(req.ip))) return errorPage(reply, 429, "Too many attempts. Wait a minute and try again.");
      const q = (req.query || {}) as Record<string, string | undefined>;
      if (!q.client_id || typeof q.client_id !== "string" || q.client_id.length > 512) return errorPage(reply, 400, "The agent did not say who it is (client_id).");
      let client: ClientRow;
      try { client = await resolveClient(q.client_id); } catch (e) {
        return errorPage(reply, 400, e instanceof ClientDocError ? e.message : "I could not look up that agent.");
      }
      const redirect = q.redirect_uri;
      if (!redirect || !redirectMatches(client.redirect_uris, redirect)) return errorPage(reply, 400, "That redirect address is not registered for this agent.");
      // From here the redirect address is trusted, so errors go back to the agent (RFC 6749, 4.1.2.1).
      const back = (error: string, description: string) => {
        const u = new URL(redirect);
        u.searchParams.set("error", error); u.searchParams.set("error_description", description);
        if (q.state) u.searchParams.set("state", q.state);
        u.searchParams.set("iss", U.issuer);
        return reply.redirect(u.toString(), 302);
      };
      if (q.response_type !== "code") return back("unsupported_response_type", "Use response_type=code.");
      if (!q.code_challenge || !CHALLENGE.test(q.code_challenge)) return back("invalid_request", "PKCE is required: send a code_challenge (S256).");
      if (q.code_challenge_method !== "S256") return back("invalid_request", "Only code_challenge_method=S256 is accepted.");
      // RFC 8707: the token will be for this server only. A resource that is not ours is refused.
      const resource = q.resource ? q.resource.replace(/\/$/, "") : U.resource;
      if (resource !== U.resource && resource !== U.resourceAlt) return back("invalid_target", "That resource is not this server.");
      if (q.state && q.state.length > 512) return back("invalid_request", "state is too long.");
      const handle = secretToken(24);
      await withTx(pool, anon, (c) => c.query("select oauth_request_create($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        [uuidv7(), sha256(handle), client.id, redirect, q.code_challenge, resource, scopesFrom(q.scope), q.state || null, REQUEST_TTL_SEC]));
      return reply.header("cache-control", "no-store").header("referrer-policy", "no-referrer").redirect(`${d.appUrl}/connect?req=${handle}`, 302);
    });

    o.post("/oauth/token", async (req, reply) => {
      if (!(await tokenIp.take(req.ip))) return oauthError(reply, 429, "slow_down", "Too many requests.");
      const b = (req.body && typeof req.body === "object" ? req.body : {}) as Record<string, unknown>;
      const str = (k: string) => (typeof b[k] === "string" ? (b[k] as string) : "");
      const grantType = str("grant_type");
      const clientId = str("client_id");
      if (!clientId) return oauthError(reply, 400, "invalid_request", "client_id is required.");
      const client = await getClient(clientId);
      if (!client) return oauthError(reply, 401, "invalid_client", "Unknown client.");
      const resource = str("resource").replace(/\/$/, "");
      if (resource && resource !== U.resource && resource !== U.resourceAlt) return oauthError(reply, 400, "invalid_target", "That resource is not this server.");
      const access = "ast_" + secretToken(32);
      const refresh = "asr_" + secretToken(32);
      const body = (scopes: string[]) => ({ access_token: access, token_type: "Bearer", expires_in: ACCESS_TTL_SEC, refresh_token: refresh, scope: scopes.join(" ") });
      const ok = (scopes: string[]) => reply.header("cache-control", "no-store").header("pragma", "no-cache").send(body(scopes));

      if (grantType === "authorization_code") {
        const code = str("code"), verifier = str("code_verifier"), redirect = str("redirect_uri");
        if (!code || !verifier || !redirect) return oauthError(reply, 400, "invalid_request", "code, code_verifier and redirect_uri are required.");
        if (!VERIFIER.test(verifier)) return oauthError(reply, 400, "invalid_grant", "code_verifier is not valid.");
        const r = await withTx(pool, anon, async (c) => (await c.query("select * from oauth_code_redeem($1)", [sha256(code)])).rows[0]);
        if (r.outcome === "reused") {
          app.log.warn({ client: client.client_id }, "authorization code reused; tokens from it were revoked");
          return oauthError(reply, 400, "invalid_grant", "That code was already used.");
        }
        if (r.outcome !== "ok") return oauthError(reply, 400, "invalid_grant", "That code is invalid or expired.");
        const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
        const same = (a: string, b2: string) => a.length === b2.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b2));
        if (r.client_id !== clientId || r.redirect_uri !== redirect || !same(challenge, r.code_challenge)) return oauthError(reply, 400, "invalid_grant", "That code does not match this request.");
        if (resource && resource !== r.resource) return oauthError(reply, 400, "invalid_target", "That is not the resource the person approved.");
        const issued = await withTx(pool, anon, async (c) => (await c.query("select oauth_token_issue($1, $2, $3, $4, $5, $6, $7) as ok",
          [uuidv7(), r.grant_id, sha256(access), sha256(refresh), ACCESS_TTL_SEC, REFRESH_TTL_SEC, r.resource])).rows[0].ok as boolean);
        if (!issued) return oauthError(reply, 400, "invalid_grant", "That grant was revoked.");
        await withTx(pool, { userId: r.user_id, teamId: null }, (c) => audit(c, { userId: r.user_id, agentClientId: client.id, actorType: "agent", ip: req.ip }, "agent.token_issued", `agent:${client.id}`, { grant: "authorization_code", client: client.name }));
        return ok(r.scopes);
      }

      if (grantType === "refresh_token") {
        const token = str("refresh_token");
        if (!token) return oauthError(reply, 400, "invalid_request", "refresh_token is required.");
        const r = await withTx(pool, anon, async (c) => (await c.query("select * from oauth_token_refresh($1, $2, $3, $4, $5, $6, $7)",
          [sha256(token), clientId, uuidv7(), sha256(access), sha256(refresh), ACCESS_TTL_SEC, REFRESH_TTL_SEC])).rows[0]);
        if (r.outcome === "reused") app.log.warn({ client: client.client_id }, "refresh token reused; the grant's tokens were revoked");
        if (r.outcome !== "ok") return oauthError(reply, 400, "invalid_grant", r.outcome === "expired" ? "That refresh token expired. Connect again." : "That refresh token is not valid. Connect again.");
        if (resource && resource !== r.resource) return oauthError(reply, 400, "invalid_target", "That is not the resource the person approved.");
        return ok(r.scopes);
      }
      return oauthError(reply, 400, "unsupported_grant_type", "Use authorization_code or refresh_token.");
    });

    // RFC 7009. Always 200 so it can't be used to probe for valid tokens.
    o.post("/oauth/revoke", async (req, reply) => {
      if (!(await tokenIp.take(req.ip))) return oauthError(reply, 429, "slow_down", "Too many requests.");
      const b = (req.body && typeof req.body === "object" ? req.body : {}) as Record<string, unknown>;
      if (typeof b.token === "string" && typeof b.client_id === "string" && b.token.length < 200) {
        await withTx(pool, anon, (c) => c.query("select oauth_token_revoke($1, $2)", [sha256(b.token as string), b.client_id]));
      }
      return reply.header("cache-control", "no-store").send({});
    });
  });

  // ---------- consent (the web app, signed in with a device token) ----------
  const handleParam = z.object({ handle: z.string().min(16).max(80).regex(/^[A-Za-z0-9_-]+$/) });
  const decision = z.object({ approve: z.boolean(), scopes: z.array(z.enum(SCOPES)).max(3).optional(), workspace_ids: z.array(z.uuid()).max(100).optional() }).strict();
const NO_WORKSPACES = "Pick at least one workspace for this agent to see.";
const NOT_YOUR_WORKSPACE = "You can only pick workspaces you are in.";

  app.get("/v1/oauth/requests/:handle", { preHandler: d.requireAuth }, async (req) => {
    const p = handleParam.safeParse(req.params);
    if (!p.success) throw notFound("This connection request is not valid.");
    const row = await withTx(pool, { userId: req.auth!.userId, teamId: null }, async (c) =>
      (await c.query("select * from oauth_request_view($1)", [sha256(p.data.handle)])).rows[0]);
    if (!row) throw notFound("This connection request expired or was already answered. Start again from the agent.");
    const host = (() => { try { const u = new URL(row.redirect_uri); return u.protocol.startsWith("http") ? u.host : `${u.protocol}//`; } catch { return ""; } })();
    // The workspaces the person could give this agent, with the ones ticked at first: their Personal space plus the
    // company they are in right now (the web app passes it as ?team=). Never all of them silently.
    const mine = await withTx(pool, { userId: req.auth!.userId, teamId: null }, (c) => myTeams(c));
    const current = typeof (req.query as Record<string, unknown>)?.team === "string" ? (req.query as Record<string, string>).team : "";
    const companies = mine.filter((t) => t.kind === "company");
    const pick = companies.find((t) => t.id === current) ?? (companies.length === 1 ? companies[0] : null);
    return {
      workspaces: mine.map((t) => ({ id: t.id, name: t.name, kind: t.kind, role: t.role, selected: t.kind === "personal" || t.id === pick?.id })),
      client: { name: row.name, uri: row.client_uri, registration: row.registration, id: row.client_id },
      redirect_host: host,
      redirect_is_local: (() => { try { return isLoopbackHost(new URL(row.redirect_uri).hostname); } catch { return false; } })(),
      scopes: (row.scopes as Scope[]).map((s) => ({ id: s, label: SCOPE_LABELS[s], required: s === "tasks:read" })),
      never: ["mark tasks done", "delete tasks", "hand tasks over", "send email or messages outside Async"],
      expires_at: row.expires_at,
    };
  });

  app.post("/v1/oauth/requests/:handle/decision", { preHandler: d.requireAuth }, async (req) => {
    const p = handleParam.safeParse(req.params);
    if (!p.success) throw notFound("This connection request is not valid.");
    const b = decision.safeParse(req.body);
    if (!b.success) throw badRequest("Send {approve: boolean, scopes?: string[], workspace_ids: string[]}.");
    if (b.data.approve && !b.data.workspace_ids?.length) throw badRequest(NO_WORKSPACES);
    if (!(await decideUser.take(req.auth!.userId))) throw tooMany();
    const code = "asc_" + secretToken(32);
    const userId = req.auth!.userId;
    const out = await withTx(pool, { userId, teamId: null }, async (c) => {
      const view = (await c.query("select client_id, name from oauth_request_view($1)", [sha256(p.data.handle)])).rows[0];
      const r = (await c.query("select * from oauth_request_decide($1, $2, $3, $4, $5, $6, $7)",
        [sha256(p.data.handle), b.data.approve, b.data.scopes || [...SCOPES], uuidv7(), sha256(code), CODE_TTL_SEC, b.data.workspace_ids ?? []])).rows[0];
      if (r.outcome === "invalid" || !view) return null;
      if (r.outcome === "no_workspaces") throw badRequest(NO_WORKSPACES);
      if (r.outcome === "not_member") throw badRequest(NOT_YOUR_WORKSPACE);
      const client = (await c.query("select id from oauth_client_get($1)", [view.client_id])).rows[0];
      await audit(c, { userId, agentClientId: client.id, actorType: "user", ip: req.ip, deviceId: req.auth!.deviceId },
        r.outcome === "approved" ? "agent.connect" : "agent.connect_denied", `agent:${client.id}`, { client: view.name, scopes: b.data.scopes || "all requested", workspaces: b.data.workspace_ids ?? [] });
      return r as { outcome: "approved" | "denied"; redirect_uri: string; state: string | null };
    });
    if (!out) throw notFound("This connection request expired or was already answered. Start again from the agent.");
    const u = new URL(out.redirect_uri);
    if (out.outcome === "approved") u.searchParams.set("code", code);
    else { u.searchParams.set("error", "access_denied"); u.searchParams.set("error_description", "The person said no."); }
    if (out.state) u.searchParams.set("state", out.state);
    u.searchParams.set("iss", U.issuer);
    return { redirect_to: u.toString(), approved: out.outcome === "approved" };
  });

  // ---------- connected agents: list and revoke (settings in the web app) ----------
  app.get("/v1/agents", { preHandler: d.requireAuth }, async (req) => {
    const { rows, mine } = await withTx(pool, { userId: req.auth!.userId, teamId: null }, async (c) => ({
      rows: (await c.query(
        `select g.id, g.scopes, g.workspace_ids, g.created_at, g.last_used_at, g.revoked_at, a.name, a.client_uri, a.registration,
                (select count(*)::int from oauth_token t where t.grant_id = g.id and t.revoked_at is null and t.refresh_expires_at > now() and t.rotated_at is null) as live_tokens
           from agent_grant g join agent_client a on a.id = g.agent_client_id
          where g.user_id = $1 order by g.revoked_at nulls first, coalesce(g.last_used_at, g.created_at) desc`, [req.auth!.userId])).rows,
      mine: await myTeams(c),
    }));
    const brief = (t: { id: string; name: string; kind: string; role: string }) => ({ id: t.id, name: t.name, kind: t.kind, role: t.role });
    return {
      // every workspace the person is in: the choices for Change
      workspaces: mine.map(brief),
      agents: rows.map((r) => ({
        id: r.id, name: r.name, uri: r.client_uri, registration: r.registration, scopes: r.scopes,
        // null workspace_ids = a connection made before this existed: it can use all of the person's workspaces, including ones they join later
        all_workspaces: r.workspace_ids === null,
        workspace_ids: r.workspace_ids === null ? mine.map((t) => t.id) : (r.workspace_ids as string[]).filter((id) => mine.some((t) => t.id === id)),
        workspaces: (r.workspace_ids === null ? mine : mine.filter((t) => (r.workspace_ids as string[]).includes(t.id))).map(brief),
        connected_at: r.created_at, last_used_at: r.last_used_at, revoked_at: r.revoked_at, live: !r.revoked_at && r.live_tokens > 0,
      })),
    };
  });

  // Change: set the workspaces a connection may use, without reconnecting. It applies to the very next call, tokens already issued included.
  app.post("/v1/agents/:id/workspaces", { preHandler: d.requireAuth }, async (req) => {
    const p = z.object({ id: z.uuid() }).safeParse(req.params);
    if (!p.success) throw notFound("I can't find that agent.");
    const b = z.object({ workspace_ids: z.array(z.uuid()).max(100) }).strict().safeParse(req.body);
    if (!b.success) throw badRequest("Send {workspace_ids: string[]}.");
    if (!b.data.workspace_ids.length) throw badRequest(NO_WORKSPACES);
    const userId = req.auth!.userId;
    if (!(await decideUser.take(userId))) throw tooMany();
    await withTx(pool, { userId, teamId: null }, async (c) => {
      const out = (await c.query("select agent_grant_set_workspaces($1, $2) as r", [p.data.id, b.data.workspace_ids])).rows[0].r as string;
      if (out === "no_workspaces") throw badRequest(NO_WORKSPACES);
      if (out === "not_member") throw badRequest(NOT_YOUR_WORKSPACE);
      if (out !== "ok") throw notFound("I can't find that agent.");
      const g = (await c.query("select agent_client_id from agent_grant where id = $1", [p.data.id])).rows[0];
      await audit(c, { userId, agentClientId: g.agent_client_id, actorType: "user", ip: req.ip, deviceId: req.auth!.deviceId }, "agent.workspaces", `agent:${g.agent_client_id}`, { workspaces: b.data.workspace_ids });
    });
    return { ok: true };
  });

  app.post("/v1/agents/:id/revoke", { preHandler: d.requireAuth }, async (req) => {
    const p = z.object({ id: z.uuid() }).safeParse(req.params);
    if (!p.success) throw notFound("I can't find that agent.");
    const userId = req.auth!.userId;
    await withTx(pool, { userId, teamId: null }, async (c) => {
      const g = await c.query("update agent_grant set revoked_at = coalesce(revoked_at, now()) where id = $1 and user_id = $2 returning agent_client_id", [p.data.id, userId]);
      if (!g.rowCount) throw notFound("I can't find that agent.");
      await c.query("update oauth_token set revoked_at = coalesce(revoked_at, now()) where grant_id = $1", [p.data.id]);
      await audit(c, { userId, agentClientId: g.rows[0].agent_client_id, actorType: "user", ip: req.ip, deviceId: req.auth!.deviceId }, "agent.revoke", `agent:${g.rows[0].agent_client_id}`, {});
    });
    return { ok: true };
  });
}

export type { FastifyRequest };
