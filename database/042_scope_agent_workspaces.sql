-- Contract v1.8 (scope): an AI connection may be limited to the workspaces the person picks.
--
-- agent_grant.workspace_ids: the team ids (companies and the Personal space) this connection may see and work in.
-- NULL means "all your workspaces": every grant made before this migration stays NULL, so nothing breaks, and the
-- web app shows it as "All your workspaces" with a nudge to narrow it. A grant that has a list never grows by
-- itself: a company the person joins later is NOT in it until they add it (Change on the You page).
--
-- Enforcement, two layers:
--  1. The MCP layer (spine/src/mcp/tools.ts): a workspace outside the grant does not exist for the agent.
--  2. Row-level security: an agent session carries app.agent_grant; ink.app_tid() answers NULL for a team the grant
--     does not allow, so every policy written as team_id = app_tid() returns nothing even if a tool forgot to check.
--     The grant is read on every call, so Change takes effect at once, on tokens already issued.

alter table ink.agent_grant add column workspace_ids uuid[];
alter table ink.agent_grant add constraint agent_grant_workspaces_nonempty
  check (workspace_ids is null or cardinality(workspace_ids) >= 1);

-- Does this live grant allow team t? (definer: the agent's session may not read agent_grant by itself)
create function ink.agent_grant_allows(p_grant uuid, p_team uuid) returns boolean
language sql stable security definer set search_path = ink, pg_temp
as $$
  select exists (select 1 from ink.agent_grant g
                  where g.id = p_grant and g.revoked_at is null and (g.workspace_ids is null or p_team = any (g.workspace_ids)))
$$;
revoke all on function ink.agent_grant_allows(uuid, uuid) from public;
grant execute on function ink.agent_grant_allows(uuid, uuid) to ink_app;

-- Same body as 001, plus the agent gate. A normal session has no app.agent_grant, so it costs one current_setting.
create or replace function ink.app_tid() returns uuid language sql stable
as $$
  select case
    when coalesce(current_setting('app.agent_grant', true), '') = '' then nullif(current_setting('app.team_id', true), '')::uuid
    when ink.agent_grant_allows(current_setting('app.agent_grant', true)::uuid, nullif(current_setting('app.team_id', true), '')::uuid)
      then nullif(current_setting('app.team_id', true), '')::uuid
    else null
  end
$$;

-- ---------- the token lookup now also returns the workspaces ----------
drop function ink.mcp_token_lookup(text);
create function ink.mcp_token_lookup(p_access_hash text)
returns table (grant_id uuid, user_id uuid, agent_client_id uuid, client_name text, scopes text[], resource text, workspace_ids uuid[])
language plpgsql volatile security definer set search_path = ink, pg_temp
as $$
#variable_conflict use_column
begin
  return query
    select g.id, g.user_id, g.agent_client_id, a.name, g.scopes, t.resource, g.workspace_ids
      from ink.oauth_token t join ink.agent_grant g on g.id = t.grant_id join ink.agent_client a on a.id = t.agent_client_id
     where t.access_hash = p_access_hash and t.revoked_at is null and t.access_expires_at > now() and g.revoked_at is null;
  if found then
    update ink.agent_grant set last_used_at = now()
     where id = (select t.grant_id from ink.oauth_token t where t.access_hash = p_access_hash)
       and (last_used_at is null or last_used_at < now() - interval '1 minute');
  end if;
end $$;
revoke all on function ink.mcp_token_lookup(text) from public;
grant execute on function ink.mcp_token_lookup(text) to ink_app;

-- ---------- consent: the person's answer now carries the workspaces ----------
-- Same as 005 plus p_workspaces: it must be non-empty and every id must be a team the person is in
-- (outcome 'no_workspaces' / 'not_member' otherwise; nothing is stored).
drop function ink.oauth_request_decide(text, boolean, text[], uuid, text, integer);
create function ink.oauth_request_decide(p_handle_hash text, p_approve boolean, p_scopes text[], p_new_grant uuid,
  p_code_hash text, p_code_ttl_sec integer, p_workspaces uuid[])
returns table (outcome text, redirect_uri text, state text)
language plpgsql volatile security definer set search_path = ink, pg_temp
as $$
#variable_conflict use_column
declare r ink.oauth_request%rowtype; v_grant uuid; v_scopes text[]; v_ws uuid[];
begin
  if ink.app_uid() is null then return query select 'invalid'::text, null::text, null::text; return; end if;
  select * into r from ink.oauth_request where handle_hash = p_handle_hash and decision is null and expires_at > now() for update;
  if not found then return query select 'invalid'::text, null::text, null::text; return; end if;
  if not p_approve then
    update ink.oauth_request set decision = 'denied', decided_at = now(), user_id = ink.app_uid() where id = r.id;
    return query select 'denied'::text, r.redirect_uri, r.state; return;
  end if;
  select coalesce(array_agg(distinct w), '{}') into v_ws from unnest(coalesce(p_workspaces, '{}')) w;
  if cardinality(v_ws) = 0 then return query select 'no_workspaces'::text, null::text, null::text; return; end if;
  if exists (select 1 from unnest(v_ws) w where not exists (select 1 from ink.membership m where m.team_id = w and m.user_id = ink.app_uid())) then
    return query select 'not_member'::text, null::text, null::text; return;
  end if;
  select coalesce(array_agg(s order by array_position(array['tasks:read', 'progress:write', 'tasks:propose'], s)), '{}') into v_scopes from unnest(p_scopes) s where s = any (r.scopes);
  if not ('tasks:read' = any (v_scopes)) then v_scopes := array_prepend('tasks:read', v_scopes); end if;
  insert into ink.agent_grant as g (id, user_id, agent_client_id, scopes, resource, workspace_ids)
    values (p_new_grant, ink.app_uid(), r.agent_client_id, v_scopes, r.resource, v_ws)
    on conflict (user_id, agent_client_id) do update set scopes = excluded.scopes, resource = excluded.resource, workspace_ids = excluded.workspace_ids, revoked_at = null
    returning g.id into v_grant;
  update ink.oauth_token set revoked_at = now() where grant_id = v_grant and revoked_at is null;
  update ink.oauth_request set decision = 'approved', decided_at = now(), user_id = ink.app_uid(), grant_id = v_grant,
         code_hash = p_code_hash, code_expires_at = now() + make_interval(secs => p_code_ttl_sec) where id = r.id;
  return query select 'approved'::text, r.redirect_uri, r.state;
end $$;
revoke all on function ink.oauth_request_decide(text, boolean, text[], uuid, text, integer, uuid[]) from public;
grant execute on function ink.oauth_request_decide(text, boolean, text[], uuid, text, integer, uuid[]) to ink_app;

-- ---------- Change: edit a live grant's workspaces without reconnecting ----------
-- Only the person's own grant, only teams they are in, never empty. Tokens already issued keep working under the new list.
create function ink.agent_grant_set_workspaces(p_grant uuid, p_workspaces uuid[]) returns text
language plpgsql volatile security definer set search_path = ink, pg_temp
as $$
declare v_ws uuid[];
begin
  if ink.app_uid() is null then return 'invalid'; end if;
  select coalesce(array_agg(distinct w), '{}') into v_ws from unnest(coalesce(p_workspaces, '{}')) w;
  if cardinality(v_ws) = 0 then return 'no_workspaces'; end if;
  if exists (select 1 from unnest(v_ws) w where not exists (select 1 from ink.membership m where m.team_id = w and m.user_id = ink.app_uid())) then return 'not_member'; end if;
  update ink.agent_grant set workspace_ids = v_ws where id = p_grant and user_id = ink.app_uid() and revoked_at is null;
  if not found then return 'not_found'; end if;
  return 'ok';
end $$;
revoke all on function ink.agent_grant_set_workspaces(uuid, uuid[]) from public;
grant execute on function ink.agent_grant_set_workspaces(uuid, uuid[]) to ink_app;
