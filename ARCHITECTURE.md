# Architecture

A single-file Flask app (`app/app.py`) serving a personal, password-gated
dashboard for daves-home-server. No frontend build step, no JS framework —
server-rendered Jinja templates plus small vanilla-JS polling/interaction
scripts, styled with plain inline `<style>` blocks (dark theme, shared color
palette across pages). Runs under gunicorn (2 workers) via systemd
(`daves-server-dashboard.service`), bound to `127.0.0.1:5002`.

## Auth

A single shared password (`DASHBOARD_PASSWORD` env var, falls back to a
hardcoded default) sets an `httponly`/`SameSite=Lax` cookie (`dsd_auth`).
Every route checks `authed()` and either redirects to `/login` (page routes)
or returns 403 JSON (`/api/...` routes). No per-user accounts, no CSRF
tokens — acceptable for a single-operator tool behind this cookie check, not
a pattern to copy for anything multi-user or public.

## Pages

| Route | Purpose |
|---|---|
| `/` | Main dashboard: Bluesky followers, site traffic, security audit, backups, media-resize status, cron jobs. Polls `/api/data` every 20s and patches the DOM in place (see `updateX()` functions in `index.html`). |
| `/site-traffic`, `/backup/<run_id>`, `/security/<when>` | Drill-down detail pages for their respective dashboard sections. |
| `/projects` | The Projects board (see below). Renders once server-side with the full board embedded as JSON; no polling — every user action calls its own API endpoint and patches local state/DOM directly. |
| `/login`, `/logout` | Password form / cookie clear. |

Most main-dashboard data sources are **read-only** from this app's point of
view — it reads state another process owns (media-resize's SQLite DB and
`/api/data`, site-traffic's SQLite DB, the security-audit log, backup JSON
logs, `crontab -l`). The Projects board is the one exception: this app owns
that schema outright.

## Projects board (`/projects`)

A small two-column Trello-like board — **Backlog** and **Current
projects** — for tracking coding-project / paper / blog-post ideas, added
2026-09 to replace a hand-maintained `TODO.md`-per-project section that used
to live inline on the main dashboard.

**Storage:** SQLite at `app/projects.db` (gitignored — runtime data, not
source; schema is created on load by `init_projects_db()`, idempotently, so
a fresh checkout just works). Two tables:

```
cards       (id, title, list_name['backlog'|'current'], position,
             description_html, tag[null|'code'|'blog'|'paper'],
             created_at, updated_at)
todo_items  (id, card_id -> cards.id ON DELETE CASCADE,
             text, checked, position)
```

Ordering within a list/card is a plain integer `position` column,
renumbered 0..n-1 on every insert/delete/move — simple and fast enough at
personal-board scale (tens of cards), no need for fractional positions or a
linked-list scheme.

**Card moves** (`move_project_card`) and **to-do reorders**
(`move_project_todo`) both work the same way: the client drags an item to a
visual position, computes the id of the item now immediately after it (or
`null` for "end of list"), and POSTs `{list_name, before_id}` /
`{before_id}`. The server rebuilds the target list's id order around that
anchor and renumbers. Cards additionally renumber their *old* list if they
changed columns.

**Rich text descriptions:** each card has a `contenteditable` description
editor (bold/italic/underline/bullet-list/link via `document.execCommand`).
Saved HTML is **not** trusted as-is — `sanitize_rich_text()`
(`_RichTextSanitizer`, an `HTMLParser` subclass) whitelists a small tag set
(`p br div span b strong i em u s strike ul ol li a blockquote code pre`),
strips every attribute except `href` on `<a>` (and only accepts
`http(s):`/`mailto:` schemes there, adding `target="_blank"
rel="noopener noreferrer"`), and drops `<script>`/`<style>` tags along with
their content entirely. This runs server-side on every save, not just
client-side, since browser-generated/pasted markup isn't trustworthy input
to store and later re-render as raw HTML even for a single-user tool.

**API** (all under `/api/projects/...`, all require `authed()`):

| Method & path | Action |
|---|---|
| `POST /cards` | Create a card (`title`, `list_name`, optional `tag`) |
| `PATCH /cards/<id>` | Update `title` and/or `description_html` and/or `tag` (only keys present in the JSON body are touched — `tag` uses a sentinel internally so it can be explicitly cleared with `""`/`null` without every other PATCH wiping it) |
| `DELETE /cards/<id>` | Delete a card (cascades its to-do items) |
| `POST /cards/<id>/move` | Move to `list_name`, inserted before `before_id` (or end) |
| `POST /cards/<id>/todos` | Add a to-do item |
| `PATCH /todos/<id>` | Update `text` and/or `checked` |
| `DELETE /todos/<id>` | Delete a to-do item |
| `POST /todos/<id>/move` | Reorder within its own card, inserted before `before_id` (or end) |

**Frontend state model:** `projects.html` embeds the initial board as JSON
(`<script id="board-data">`) and mirrors it in a JS object keyed by card id.
Every action (create/edit/move/delete, on a card or a to-do item) updates
that local mirror and the relevant DOM node(s) directly, alongside firing
the API call — there's no polling and no full-board re-fetch, so an
in-progress edit elsewhere on the page is never clobbered by another
action's response.

## Adding a new dashboard data source

Follow the existing pattern in `app.py`: a `get_x()` function that returns
plain dicts/lists (already display-formatted — e.g. `format_duration()`,
`timeago()` — rather than pushing formatting into the template), wired into
`build_dashboard()`, rendered in `index.html`, and mirrored in the
`updateX()` JS function called from `poll()`. Anything with its own
persistent state that only this app should own (like the Projects board)
gets its own SQLite file rather than overloading `build_dashboard()`'s
existing DBs, which are owned and written by other processes.

## Deployment

```
sudo systemctl restart daves-server-dashboard   # after any app.py/template change
sudo systemctl status daves-server-dashboard
```

No CI, no build step — edits are made directly on daves-home-server and
committed from there (see repo git history).
