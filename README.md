# Async for AI tools

This is the part of [Async](https://async.adtivity.xyz) that your AI touches, published so you can check it
before you connect: the MCP server, the sign-in and consent step, the database rules that fence an AI in,
and the Async skill. MIT licensed.

Async's core (the app, sync and the rest of the server) is private. The server code here calls into it, so
this repository is for **reading and checking**, not for running on its own. It is copied from the code that
runs in production (private revision `a4034ad`, 15 November 2026).

## What an AI can and can't do

| It can | It can never |
|---|---|
| Read your tasks, people and projects, only in the workspaces you pick | Mark a task done without your check |
| Save to-dos that come up while you work | Delete a task or give one away |
| Take tasks it can do, and say when one is finished | Send email or messages outside Async |
| Suggest changes and new tasks, which wait for your yes | See a workspace you didn't tick |
| Ask a teammate on a task, as you, if you allow it | Keep access after you disconnect it |

Where that is enforced:

- `server/consts.ts`: the three scopes. There is no scope for done, delete or hand over, so no token can do them.
- `server/tools.ts`: every tool, its scope and its checks. Suggestions become proposals that wait in your Review list.
- `server/oauth.ts`: sign-in with OAuth and PKCE. You see who is asking, pick workspaces and scopes, and press Allow.
- `database/042_scope_agent_workspaces.sql`: row-level security, so even a tool that forgot a check sees nothing outside the workspaces you picked.
- `database/005_mcp.sql`, `006_agent_work.sql`, `018_agent_note_private.sql`: the agent tables, its work queue, and why teammates never see an agent's private notes.

## Connect

Server: `https://async.adtivity.xyz/mcp`. Step-by-step for Claude, ChatGPT, Cursor and others: [docs/connect.md](docs/connect.md).
Disconnect any time in Async under **You > Connected agents**. Access ends at once.

## The Async skill

`plugin/skills/async-capture/SKILL.md` tells your AI when to update Async (work finished, started or promised)
and that it only reports: you decide everything in Async with one tap.

- **Claude:** download it from Async (**Connect your AI > Make it automatic**) and upload it under Settings, Capabilities, Skills.
- **Claude Code:** `/plugin marketplace add async-dot/async-mcp`, then `/plugin install async@async`.

## Security

Found a problem? Email heyink.async@gmail.com. Please don't open a public issue for security reports.
