-- What a person's AI agent does is private to that person.
--
-- Rule (product owner): teammates must never see that a person's agent is working on, or finished,
-- a task. Only that person sees it. Teammates see the person's name and the result.
--
-- The bug: every MCP agent note (log_progress, capture progress, and the "Proposed ..." notes the propose
-- tools write) is a task_event of kind 'agent_note' whose `to` carries the agent's name, and the task
-- history select policy (ev_sel) let anyone who can see the task read it. Notes about a new to-do have no
-- task at all (task_id is null), and ev_sel shows those to the whole team. Agent proposals had the same
-- hole for managers: p_sel let any manager or owner read every pending proposal in the team, and an
-- agent's proposal carries `via` and `agent_name`.
--
-- The fix is in row-level security, so it holds for every path that reads these tables (sync pull, the
-- MCP get_task tool, any future route) and does not depend on the server code remembering to filter.
--
-- An agent_note row is written with actor_id = the person whose agent wrote it (the agent runs as that
-- person), so "readable only by the person whose agent wrote it" is: actor_id = the caller.
-- Must merge after the guest-removal change (017): it rebuilds p_sel and p_upd with both rules together.
-- Additive: no column or constraint changes; ordinary history is untouched.

-- Is this history event the outcome of an agent's proposal that the caller has no part in? The proposal table
-- hides it from them already; this lets the history policy ask the same question without being blocked by it
-- (definer). Approving an agent's change writes a proposal_decided event whose `to` carries the proposal id.
create function ink.app_agent_proposal_hidden(p_event_to jsonb) returns boolean
language sql stable security definer set search_path = ink, pg_temp
as $$
  select exists (
    select 1 from ink.proposal p
     where p.team_id = ink.app_tid()
       and p.source = 'agent'
       and p.reviewer_id is distinct from ink.app_uid()
       and p.proposed_by_user_id is distinct from ink.app_uid()
       and p.id::text = p_event_to ->> 'proposal_id'
  )
$$;
revoke all on function ink.app_agent_proposal_hidden(jsonb) from public;
grant execute on function ink.app_agent_proposal_hidden(jsonb) to ink_app;

-- Task history: an agent note is readable only by the person whose agent wrote it, and the decision on an
-- agent's proposal ("Approved a change to ...", which hints at an agent) only by the people it was for.
drop policy ev_sel on ink.task_event;
create policy ev_sel on ink.task_event for select to ink_app
  using (team_id = ink.app_tid() and ink.app_role_in(team_id) is not null
         and (task_id is null or ink.app_task_id_visible(task_id))
         and (kind <> 'agent_note' or actor_id = ink.app_uid())
         and (kind <> 'proposal_decided' or not ink.app_agent_proposal_hidden("to")));

-- Agent proposals: only the person they are for (reviewer) or whose agent made them. Managers and owners
-- still see and decide every other kind of proposal in their team (calls, voice, teammates). This keeps the
-- guest rule from 017 (a guest cannot read a proposal about a task they can no longer see), which an earlier
-- version of this file dropped.
drop policy p_sel on ink.proposal;
create policy p_sel on ink.proposal for select to ink_app
  using (team_id = ink.app_tid() and ink.app_role_in(team_id) is not null
         and (reviewer_id = ink.app_uid() or proposed_by_user_id = ink.app_uid()
              or (source <> 'agent' and ink.app_is_manager(team_id)))
         and (task_id is null or ink.app_role_in(team_id) <> 'guest' or ink.app_task_id_visible(task_id)));

drop policy p_upd on ink.proposal;
create policy p_upd on ink.proposal for update to ink_app
  using (team_id = ink.app_tid()
         and (reviewer_id = ink.app_uid() or (source <> 'agent' and ink.app_is_manager(team_id)))
         and (task_id is null or ink.app_role_in(team_id) <> 'guest' or ink.app_task_id_visible(task_id)))
  with check (team_id = ink.app_tid());

-- Audit log: the company owner reads the team's log, but not what another person's agent did. Every MCP tool
-- call is logged with the agent client id and the acting person, so those rows are readable by that person only.
drop policy al_sel on ink.audit_log;
create policy al_sel on ink.audit_log for select to ink_app
  using (team_id = ink.app_tid() and ink.app_role_in(team_id) = 'owner'
         and (agent_client_id is null or actor_id = ink.app_uid()));
