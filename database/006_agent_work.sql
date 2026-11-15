-- Contract v1.1: agents take work. Async offers a person's open tasks to their connected agent; the
-- agent says which it will take and which it can't, works on them with its own model, and reports
-- each one finished. Finished is a proposal: the task is only done when the person checks it.
--
-- One row per (task, agent). state:
--   taking    the agent said it will do it
--   cant      the agent said it can't (reason says why); it is not offered to that agent again
--   finished  the agent reported it done; a set_status proposal waits for the person (proposal_id)
--   accepted  the person said yes; the task is done
--   returned  the person said no; the task is offered again, with the note
--   released  the agent gave it back
-- Additive: nothing earlier changes meaning.

create table ink.agent_work (
  id uuid primary key,
  team_id uuid not null references ink.team(id) on delete cascade,
  task_id uuid not null references ink.task(id) on delete cascade,
  user_id uuid not null references ink.app_user(id) on delete cascade,   -- whose agent
  agent_client_id uuid not null,                                         -- no FK: history outlives a cleaned-up client
  agent_name text not null check (length(agent_name) between 1 and 80),
  state text not null check (state in ('taking', 'cant', 'finished', 'accepted', 'returned', 'released')),
  reason text check (length(reason) <= 500),
  result text check (length(result) <= 2000),
  result_url text check (length(result_url) <= 500),
  proposal_id uuid,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (task_id, agent_client_id)
);
create index agent_work_team_idx on ink.agent_work (team_id, updated_at);
create index agent_work_user_idx on ink.agent_work (user_id, agent_client_id);

alter table ink.agent_work enable row level security;
alter table ink.agent_work force row level security;

-- Read: your own agents' rows only. What your AI is doing is yours; teammates never see it.
create policy aw_sel on ink.agent_work for select to ink_app
  using (user_id = ink.app_uid() and team_id = ink.app_tid() and ink.app_role_in(team_id) is not null);
-- Write: only rows for your own agents, in your current team.
create policy aw_ins on ink.agent_work for insert to ink_app
  with check (user_id = ink.app_uid() and team_id = ink.app_tid() and ink.app_role_in(team_id) is not null);
create policy aw_upd on ink.agent_work for update to ink_app
  using (user_id = ink.app_uid() and team_id = ink.app_tid())
  with check (user_id = ink.app_uid() and team_id = ink.app_tid());

grant select, insert, update on ink.agent_work to ink_app;
