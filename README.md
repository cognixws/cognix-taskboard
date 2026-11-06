# Taskboard

A COGNIX[WS] extension: the processes of this machine in the bottom dock,
with the agent or workspace that owns each one. Same shape as
[Docboard](https://github.com/cognixws/cognix-docboard): a supervised
process, one isolated page, a bottom-dock tab and consent bound to the
content digest.

Person-only. No MCP server, no agent capability, no network.

## Install

In COGNIX[WS]: **Extensions → Install**, with the repository URL:

```
https://github.com/cognixws/cognix-taskboard
```

It adds the **Processes** tab to the bottom dock and the Taskboard tile to
Apps. The dock is absent below 768px; the tile opens the same page on the
phone.

## What it shows

- **Processes** — name, owner (agent or workspace), CPU, memory, disk I/O
  per second, threads, PID and state. CPU is a share of the whole machine,
  the way Task Manager counts it. Sort by CPU or memory, search, group by
  agent.
- **Agents** — the total CPU and memory of each agent and workspace, its
  biggest process and how the attribution was made: `likely` (a
  COGNIX[WS] terminal name or the process folder), or `unknown` when
  neither matches. This version does not claim `exact`; a terminal id door
  would be needed for that. The count is never presented as fact when it
  is a guess.
- **Performance** — machine totals over time, in memory for the last two
  minutes. No database in v1: the history is a derived cache and does not
  enter backups.

On Windows the daemon runs inside WSL. The extension then shows both sides:
the Linux environment (agents, dev servers, node) from `/proc`, and the
Windows host from a small one-shot helper executed through WSL interop. If
interop is off, the page says in one line that Windows apps are not visible
and shows only the Linux side. A computer that only runs Linux has no such
line: there is no Windows host to read.

`show_windows` in the extension settings turns the helper off. `update_ms`
sets the page's refresh (1, 2 or 5 seconds); the page pauses by itself when
hidden. `alerts` (off by default) files one Inbox note when an agent stays
above 80% CPU for a minute, at most one per agent every 30 minutes.

## Safety

Reading a process is what any local program can already do. Ending one is
the part with rules, and each row has a test:

| Condition | Action |
|---|---|
| Another user's process | read basic facts if the OS allows; **End task refused** |
| Elevated, system or protected process | **refused**; no UAC, no elevation |
| PiCode, its daemon, tmux, this extension, PID 0/1/4 | **refused** |
| A PID that was reused or already exited | **refused**; the list refreshes |
| Same user, ordinary process | host confirmation, then `SIGTERM`, then `SIGKILL` after 2 s if it is still the same process |
| Command line | on demand only; masked before display; never stored |

The host draws the confirmation, not the page (`picode.use("confirm")`).
The operation is bound to the PID, its start token and a revision; the
process rechecks all three immediately before it signals anything.

## PiCode's fonts

The page links `../__picode/tokens.css` and uses PiCode's own families:
`var(--pc-font)` for the interface and `var(--pc-font-code)` for numbers,
PIDs and command lines. No web fonts, no second palette. The theme follows
the app (dark, light or system).

## Tests

```
npm test
```

The suite covers the CPU delta, formatting, sorting, grouping, the safety
table and command-line masking, and runs the real process against a child
it starts and ends. The helper is built with `npm run helper` (Go,
`windows/amd64`, no external modules) and committed under `bin/`.

## Files

```
picode-extension.json   the reviewed manifest
process.mjs             HTTP server, samplers, operations, Host API
lib.mjs                 pure rules: delta, merge, sort, safety, masking
ui/processes.html       the dock page (PiCode tokens and fonts)
helper/                 the Windows process helper (Go)
bin/                    the built helper for windows/amd64
qa/preview.mjs          the page harness used for visual review
```
