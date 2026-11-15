-- Contract v0.8: the MCP server and the spine as its OAuth 2.1 authorization server.
-- Tables: agent_client (who the agent is), agent_grant (what one user allowed it), oauth_token
-- (hashed access and refresh tokens), oauth_request (a pending authorization and its one-time code).
-- Additive: no column, policy or function that v0.6 relies on changes meaning.
--
-- Access model. Agents are not people: an MCP token maps to (user, agent_client, grant), and every
-- tool runs as that user under the same row-level security as the web app, so an agent sees exactly
-- what its user sees and nothing else. Tokens and codes are stored as SHA-256 hashes only.
-- The anonymous steps of OAuth (register, authorize, token, introspect-by-use) have no user yet,
-- so they go through narrow SECURITY DEFINER functions, each of which does one thing.

-- ---------- tables ----------

create table ink.agent_client (
  id uuid primary key,
  client_id text not null unique check (length(client_id) between 8 and 512),   -- the OAuth client_id: an https URL (client ID metadata document) or an id we issued (dynamic registration)
  registration text not null check (registration in ('cimd', 'dcr')),
  name text not null check (length(name) between 1 and 80),
  client_uri text,
  logo_uri text,
  redirect_uris text[] not null check (cardinality(redirect_uris) between 1 and 10),
  metadata_fetched_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table ink.agent_grant (
  id uuid primary key,
  user_id uuid not null references ink.app_user(id) on delete cascade,
  agent_client_id uuid not null references ink.agent_client(id),
  scopes text[] not null check (scopes <@ array['tasks:read', 'progress:write', 'tasks:propose']::text[] and cardinality(scopes) >= 1),
  resource text not null,
  created_at timestamptz not null default now(),
  last_used_at timestamptz,
  revoked_at timestamptz,
  unique (user_id, agent_client_id)
);
create index agent_grant_user_idx on ink.agent_grant (user_id);

create table ink.oauth_token (
  id uuid primary key,
  grant_id uuid not null references ink.agent_grant(id) on delete cascade,
  user_id uuid not null references ink.app_user(id) on delete cascade,
  agent_client_id uuid not null references ink.agent_client(id),
  access_hash text not null unique,
  refresh_hash text not null unique,
  resource text not null,
  access_expires_at timestamptz not null,
  refresh_expires_at timestamptz not null,
  rotated_at timestamptz,                  -- set when the refresh token was exchanged; presenting it again is reuse
  revoked_at timestamptz,
  created_at timestamptz not null default now()
);
create index oauth_token_grant_idx on ink.oauth_token (grant_id);
create index oauth_token_user_idx on ink.oauth_token (user_id);

create table ink.oauth_request (
  id uuid primary key,
  handle_hash text not null unique,        -- the opaque handle in the consent URL, hashed
  agent_client_id uuid not null references ink.agent_client(id),
  redirect_uri text not null,
  code_challenge text not null,
  resource text not null,
  scopes text[] not null,                  -- what the agent asked for
  state text,
  user_id uuid references ink.app_user(id) on delete cascade,
  grant_id uuid references ink.agent_grant(id) on delete cascade,
  decision text check (decision in ('approved', 'denied')),
  decided_at timestamptz,
  code_hash text unique,
  code_expires_at timestamptz,
  redeemed_at timestamptz,
  expires_at timestamptz not null,
  created_at timestamptz not null default now()
);

-- Who acted: audit rows from agents carry the client id; events and proposals already had the column.
-- No foreign keys on these three: they are append-only history and must outlive a cleaned-up client row.
alter table ink.audit_log add column agent_client_id uuid;
create index audit_log_agent_idx on ink.audit_log (agent_client_id, at) where agent_client_id is not null;

-- ---------- row-level security ----------

alter table ink.agent_client  enable row level security; alter table ink.agent_client  force row level security;
alter table ink.agent_grant   enable row level security; alter table ink.agent_grant   force row level security;
alter table ink.oauth_token   enable row level security; alter table ink.oauth_token   force row level security;
alter table ink.oauth_request enable row level security; alter table ink.oauth_request force row level security;

-- You see the agents you have a grant with, and nothing else. Registering happens in definer functions.
create policy ac_sel on ink.agent_client for select to ink_app
  using (exists (select 1 from ink.agent_grant g where g.agent_client_id = agent_client.id and g.user_id = ink.app_uid()));

-- Your grants: read them, revoke them (only revoked_at can change; see the column grants below).
create policy ag_sel on ink.agent_grant for select to ink_app using (user_id = ink.app_uid());
create policy ag_upd on ink.agent_grant for update to ink_app
  using (user_id = ink.app_uid()) with check (user_id = ink.app_uid());

-- Your tokens, to revoke. Only hashes live here, and the app never selects them.
create policy ot_sel on ink.oauth_token for select to ink_app using (user_id = ink.app_uid());
create policy ot_upd on ink.oauth_token for update to ink_app
  using (user_id = ink.app_uid()) with check (user_id = ink.app_uid());

-- oauth_request: no policy and no grant. Only the definer functions below touch it.

grant select on ink.agent_client, ink.agent_grant, ink.oauth_token to ink_app;
grant update (revoked_at) on ink.agent_grant, ink.oauth_token to ink_app;

-- ---------- definer functions: the anonymous steps ----------

-- Register or refresh a client. Dynamic registration passes a fresh client_id; a metadata document
-- passes its URL, so a second call updates the cached copy.
create function ink.oauth_client_upsert(p_id uuid, p_client_id text, p_registration text, p_name text,
  p_redirects text[], p_client_uri text, p_logo text) returns uuid
language plpgsql volatile security definer set search_path = ink, pg_temp
as $$
declare v_id uuid;
begin
  insert into ink.agent_client as a (id, client_id, registration, name, redirect_uris, client_uri, logo_uri, metadata_fetched_at)
    values (p_id, p_client_id, p_registration, p_name, p_redirects, p_client_uri, p_logo, case when p_registration = 'cimd' then now() end)
    on conflict (client_id) do update set
      name = excluded.name, redirect_uris = excluded.redirect_uris, client_uri = excluded.client_uri,
      logo_uri = excluded.logo_uri, metadata_fetched_at = excluded.metadata_fetched_at, updated_at = now()
      where a.registration = 'cimd'
    returning a.id into v_id;
  if v_id is null then select a.id into v_id from ink.agent_client a where a.client_id = p_client_id; end if;
  return v_id;
end $$;

create function ink.oauth_client_get(p_client_id text)
returns table (id uuid, client_id text, registration text, name text, client_uri text, logo_uri text, redirect_uris text[], metadata_fetched_at timestamptz)
language sql stable security definer set search_path = ink, pg_temp
as $$
  select a.id, a.client_id, a.registration, a.name, a.client_uri, a.logo_uri, a.redirect_uris, a.metadata_fetched_at
    from ink.agent_client a where a.client_id = p_client_id
$$;

-- A pending authorization, created by GET /oauth/authorize before anyone has signed in.
create function ink.oauth_request_create(p_id uuid, p_handle_hash text, p_client uuid, p_redirect text, p_challenge text,
  p_resource text, p_scopes text[], p_state text, p_ttl_sec integer) returns void
language sql volatile security definer set search_path = ink, pg_temp
as $$
  insert into ink.oauth_request (id, handle_hash, agent_client_id, redirect_uri, code_challenge, resource, scopes, state, expires_at)
  values (p_id, p_handle_hash, p_client, p_redirect, p_challenge, p_resource, p_scopes, p_state, now() + make_interval(secs => p_ttl_sec))
$$;

-- What the consent screen shows. Needs a signed-in user; only an undecided, unexpired request.
create function ink.oauth_request_view(p_handle_hash text)
returns table (client_id text, registration text, name text, client_uri text, logo_uri text, redirect_uri text, resource text, scopes text[], expires_at timestamptz)
language sql stable security definer set search_path = ink, pg_temp
as $$
  select a.client_id, a.registration, a.name, a.client_uri, a.logo_uri, r.redirect_uri, r.resource, r.scopes, r.expires_at
    from ink.oauth_request r join ink.agent_client a on a.id = r.agent_client_id
   where ink.app_uid() is not null and r.handle_hash = p_handle_hash and r.decision is null and r.expires_at > now()
$$;

-- The person's answer. Approving creates (or renews) the grant for this user and client, and stores the
-- code's hash. A grant that was revoked is renewed: every token from before stays dead.
create function ink.oauth_request_decide(p_handle_hash text, p_approve boolean, p_scopes text[], p_new_grant uuid,
  p_code_hash text, p_code_ttl_sec integer)
returns table (outcome text, redirect_uri text, state text)
language plpgsql volatile security definer set search_path = ink, pg_temp
as $$
#variable_conflict use_column
declare r ink.oauth_request%rowtype; v_grant uuid; v_scopes text[];
begin
  if ink.app_uid() is null then return query select 'invalid'::text, null::text, null::text; return; end if;
  select * into r from ink.oauth_request where handle_hash = p_handle_hash and decision is null and expires_at > now() for update;
  if not found then return query select 'invalid'::text, null::text, null::text; return; end if;
  if not p_approve then
    update ink.oauth_request set decision = 'denied', decided_at = now(), user_id = ink.app_uid() where id = r.id;
    return query select 'denied'::text, r.redirect_uri, r.state; return;
  end if;
  select coalesce(array_agg(s order by array_position(array['tasks:read', 'progress:write', 'tasks:propose'], s)), '{}') into v_scopes from unnest(p_scopes) s where s = any (r.scopes);
  if not ('tasks:read' = any (v_scopes)) then v_scopes := array_prepend('tasks:read', v_scopes); end if;
  insert into ink.agent_grant as g (id, user_id, agent_client_id, scopes, resource)
    values (p_new_grant, ink.app_uid(), r.agent_client_id, v_scopes, r.resource)
    on conflict (user_id, agent_client_id) do update set scopes = excluded.scopes, resource = excluded.resource, revoked_at = null
    returning g.id into v_grant;
  -- renewing: tokens issued before this consent are not revived
  update ink.oauth_token set revoked_at = now() where grant_id = v_grant and revoked_at is null;
  update ink.oauth_request set decision = 'approved', decided_at = now(), user_id = ink.app_uid(), grant_id = v_grant,
         code_hash = p_code_hash, code_expires_at = now() + make_interval(secs => p_code_ttl_sec) where id = r.id;
  return query select 'approved'::text, r.redirect_uri, r.state;
end $$;

-- Exchange a code, once. A second use of the same code revokes everything the first one produced.
create function ink.oauth_code_redeem(p_code_hash text)
returns table (outcome text, grant_id uuid, user_id uuid, client_id text, redirect_uri text, code_challenge text, resource text, scopes text[])
language plpgsql volatile security definer set search_path = ink, pg_temp
as $$
#variable_conflict use_column
declare r ink.oauth_request%rowtype; g ink.agent_grant%rowtype; a ink.agent_client%rowtype;
begin
  select * into r from ink.oauth_request where code_hash = p_code_hash for update;
  if not found then
    return query select 'invalid'::text, null::uuid, null::uuid, null::text, null::text, null::text, null::text, null::text[]; return;
  end if;
  if r.redeemed_at is not null then
    update ink.oauth_token set revoked_at = now() where grant_id = r.grant_id and revoked_at is null and created_at >= r.redeemed_at;
    return query select 'reused'::text, null::uuid, null::uuid, null::text, null::text, null::text, null::text, null::text[]; return;
  end if;
  update ink.oauth_request set redeemed_at = now() where id = r.id;
  if r.decision is distinct from 'approved' or r.code_expires_at <= now() then
    return query select 'expired'::text, null::uuid, null::uuid, null::text, null::text, null::text, null::text, null::text[]; return;
  end if;
  select * into g from ink.agent_grant where id = r.grant_id;
  select * into a from ink.agent_client where id = r.agent_client_id;
  if g.revoked_at is not null then
    return query select 'invalid'::text, null::uuid, null::uuid, null::text, null::text, null::text, null::text, null::text[]; return;
  end if;
  return query select 'ok'::text, g.id, g.user_id, a.client_id, r.redirect_uri, r.code_challenge, r.resource, g.scopes;
end $$;

create function ink.oauth_token_issue(p_id uuid, p_grant uuid, p_access_hash text, p_refresh_hash text,
  p_access_ttl_sec integer, p_refresh_ttl_sec integer, p_resource text) returns boolean
language plpgsql volatile security definer set search_path = ink, pg_temp
as $$
declare g ink.agent_grant%rowtype;
begin
  select * into g from ink.agent_grant where id = p_grant and revoked_at is null;
  if not found then return false; end if;
  insert into ink.oauth_token (id, grant_id, user_id, agent_client_id, access_hash, refresh_hash, resource, access_expires_at, refresh_expires_at)
    values (p_id, g.id, g.user_id, g.agent_client_id, p_access_hash, p_refresh_hash, p_resource,
            now() + make_interval(secs => p_access_ttl_sec), now() + make_interval(secs => p_refresh_ttl_sec));
  return true;
end $$;

-- Rotate a refresh token. The old one is spent; presenting it again revokes the whole grant's tokens.
create function ink.oauth_token_refresh(p_old_hash text, p_client_id text, p_new_id uuid, p_access_hash text, p_refresh_hash text,
  p_access_ttl_sec integer, p_refresh_ttl_sec integer)
returns table (outcome text, scopes text[], resource text)
language plpgsql volatile security definer set search_path = ink, pg_temp
as $$
#variable_conflict use_column
declare t ink.oauth_token%rowtype; g ink.agent_grant%rowtype; a ink.agent_client%rowtype;
begin
  select * into t from ink.oauth_token where refresh_hash = p_old_hash for update;
  if not found then return query select 'invalid'::text, null::text[], null::text; return; end if;
  select * into a from ink.agent_client where id = t.agent_client_id;
  if a.client_id is distinct from p_client_id then return query select 'invalid'::text, null::text[], null::text; return; end if;
  select * into g from ink.agent_grant where id = t.grant_id;
  if g.revoked_at is not null or t.revoked_at is not null then return query select 'revoked'::text, null::text[], null::text; return; end if;
  if t.rotated_at is not null then
    update ink.oauth_token set revoked_at = now() where grant_id = t.grant_id and revoked_at is null;
    return query select 'reused'::text, null::text[], null::text; return;
  end if;
  if t.refresh_expires_at <= now() then return query select 'expired'::text, null::text[], null::text; return; end if;
  update ink.oauth_token set rotated_at = now() where id = t.id;
  insert into ink.oauth_token (id, grant_id, user_id, agent_client_id, access_hash, refresh_hash, resource, access_expires_at, refresh_expires_at)
    values (p_new_id, t.grant_id, t.user_id, t.agent_client_id, p_access_hash, p_refresh_hash, t.resource,
            now() + make_interval(secs => p_access_ttl_sec), now() + make_interval(secs => p_refresh_ttl_sec));
  return query select 'ok'::text, g.scopes, t.resource;
end $$;

-- Who is this access token? Valid means: not expired, not revoked, grant not revoked. Marks the grant as used
-- (at most once a minute, so a busy agent does not write on every call).
create function ink.mcp_token_lookup(p_access_hash text)
returns table (grant_id uuid, user_id uuid, agent_client_id uuid, client_name text, scopes text[], resource text)
language plpgsql volatile security definer set search_path = ink, pg_temp
as $$
#variable_conflict use_column
begin
  return query
    select g.id, g.user_id, g.agent_client_id, a.name, g.scopes, t.resource
      from ink.oauth_token t join ink.agent_grant g on g.id = t.grant_id join ink.agent_client a on a.id = t.agent_client_id
     where t.access_hash = p_access_hash and t.revoked_at is null and t.access_expires_at > now() and g.revoked_at is null;
  if found then
    update ink.agent_grant set last_used_at = now()
     where id = (select t.grant_id from ink.oauth_token t where t.access_hash = p_access_hash)
       and (last_used_at is null or last_used_at < now() - interval '1 minute');
  end if;
end $$;

-- RFC 7009: the client revokes a token it holds (either kind); the pair dies together.
create function ink.oauth_token_revoke(p_hash text, p_client_id text) returns boolean
language sql volatile security definer set search_path = ink, pg_temp
as $$
  with u as (
    update ink.oauth_token t set revoked_at = coalesce(t.revoked_at, now())
     from ink.agent_client a
     where a.id = t.agent_client_id and a.client_id = p_client_id and (t.access_hash = p_hash or t.refresh_hash = p_hash)
     returning 1)
  select exists (select 1 from u)
$$;

-- Daily housekeeping: stale requests, long-dead tokens, registered clients nobody ever used.
create function ink.job_mcp_gc() returns jsonb
language plpgsql volatile security definer set search_path = ink, pg_temp
as $$
declare n_req int; n_tok int; n_cli int;
begin
  delete from ink.oauth_request where expires_at < now() - interval '1 day' and (redeemed_at is not null or decision is null or decision = 'denied' or code_expires_at < now());
  get diagnostics n_req = row_count;
  delete from ink.oauth_token where refresh_expires_at < now() - interval '7 days' or (revoked_at is not null and revoked_at < now() - interval '30 days');
  get diagnostics n_tok = row_count;
  delete from ink.agent_client c where c.registration = 'dcr' and c.created_at < now() - interval '7 days'
     and not exists (select 1 from ink.agent_grant g where g.agent_client_id = c.id)
     and not exists (select 1 from ink.oauth_request r where r.agent_client_id = c.id);
  get diagnostics n_cli = row_count;
  return jsonb_build_object('mcp_requests', n_req, 'mcp_tokens', n_tok, 'mcp_clients', n_cli);
end $$;

revoke all on function
  ink.oauth_client_upsert(uuid, text, text, text, text[], text, text),
  ink.oauth_client_get(text),
  ink.oauth_request_create(uuid, text, uuid, text, text, text, text[], text, integer),
  ink.oauth_request_view(text),
  ink.oauth_request_decide(text, boolean, text[], uuid, text, integer),
  ink.oauth_code_redeem(text),
  ink.oauth_token_issue(uuid, uuid, text, text, integer, integer, text),
  ink.oauth_token_refresh(text, text, uuid, text, text, integer, integer),
  ink.mcp_token_lookup(text),
  ink.oauth_token_revoke(text, text),
  ink.job_mcp_gc() from public;
grant execute on function
  ink.oauth_client_upsert(uuid, text, text, text, text[], text, text),
  ink.oauth_client_get(text),
  ink.oauth_request_create(uuid, text, uuid, text, text, text, text[], text, integer),
  ink.oauth_request_view(text),
  ink.oauth_request_decide(text, boolean, text[], uuid, text, integer),
  ink.oauth_code_redeem(text),
  ink.oauth_token_issue(uuid, uuid, text, text, integer, integer, text),
  ink.oauth_token_refresh(text, text, uuid, text, text, integer, integer),
  ink.mcp_token_lookup(text),
  ink.oauth_token_revoke(text, text),
  ink.job_mcp_gc() to ink_app;
