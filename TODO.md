# Home Folder Re-org — To-Do

`/home/dave` has too many top-level folders and will keep growing as new
non-website projects get added. Plan: split project code from shared
infrastructure that almost every project reaches into by absolute path
(`secrets`, `.ssh`, `.config`, `.cloudflared`, `logs`, `ssh-backup` — these
stay put, unmoved, to avoid touching the ~20+ files across every repo that
hardcode `/home/dave/secrets/`). Only actual project-code folders move.
`Tech Docs` and `session-docs` were already removed (2026-09-12, both
superseded/no longer needed). See conversation history for the full survey
of what currently references what (crontab, systemd, per-repo grep).

1. [x] Decide final target layout under `/home/dave` — **done 2026-09-12**:
   `projects/` for active maintained code (`server-scripts`,
   `unofficial-andy`, `whatsapp-claude-bot`, `google-workspace-migration`);
   `staging/` for transient/working data (`encode-staging`, `scratch`).
   `secrets`, `.ssh`, `.config`, `.cloudflared`, `logs`, `ssh-backup` stay at
   top level, unmoved. Both empty directories created
   (`/home/dave/projects`, `/home/dave/staging`), ready to receive moves in
   the steps below.
2. [x] Move and fix `server-scripts` — **done 2026-09-12**, all in one sitting
   since a half-finished move would have broken the nightly backup/audit
   crons and the dashboard itself:
   1. [x] Moved `/home/dave/server-scripts` → `/home/dave/projects/server-scripts`.
   2. [x] Updated dave's crontab: the `security-audit.sh` and `backup.py`
      lines, plus the disabled `media-resize-remote-watchdog.sh` line, all
      referencing the old path.
   3. [x] Fixed the hardcoded venv shebang in `backup.py` and
      `refresh-tokens.py` (`#!/home/dave/server-scripts/venv/bin/python3`).
   4. [x] Fixed `security-audit.sh`'s own hardcoded log paths
      (`FINDINGS_LOG`, the Brevo error log, the success log) — these were
      absolute strings, not relative to the script, so the move alone would
      have broken them silently.
   5. [x] Rebuilt `venv/` fresh at the new path rather than `mv`-ing it (only
      dependency: `PyYAML==6.0.3` — also added a `requirements.txt`, which
      this repo was missing).
   6. [x] **Found and fixed a dashboard dependency that wasn't in the original
      plan**: `app.py` hardcodes `FINDINGS_LOG`/`FINDINGS_ROTATED_GLOB`/
      `BACKUP_LOGS_DIR` pointing straight at `server-scripts`'s log files —
      updated and restarted `daves-server-dashboard.service` (verified clean
      restart, no tracebacks, login redirect responds normally).
   7. [x] Updated path references in `BACKUP-DESIGN.md`,
      `SECURITY-AUDIT-DESIGN.md`, plus the cross-repo references in
      `media-resize/TODO.md` and `whatsapp-claude-bot/spec.md`.
   8. [x] Verified with `backup.py --dry-run` (23 actions, all `dry_run`, no
      failures) and `bash -n security-audit.sh` (syntax OK) from the new
      location before trusting tonight's scheduled cron run.
   9. [x] **Bonus fix surfaced by the dry-run**: `backup.yml` still had an
      enabled `Backup Tech Docs` action pointing at the `Tech Docs` folder
      deleted earlier in this reorg — removed it, otherwise tonight's real
      backup run would have errored on that step.
3. [x] Move and fix `unofficial-andy` — **done 2026-09-12**. Simpler than
   `server-scripts`: no systemd unit, no shebang self-reference, and (per
   [[feedback_reorg_docs]]) checked the dashboard for any dependency on it
   first — none found.
   1. [x] Moved `/home/dave/unofficial-andy` → `/home/dave/projects/unofficial-andy`.
   2. [x] Updated the `*/20 * * * *` crontab line (2 path refs on that one
      line — venv interpreter + `main.py` — plus the log-output redirect).
   3. [x] Rebuilt `venv/` fresh at the new path (`requests`, `atproto`,
      `yt-dlp`, `Pillow`).
   4. [x] Updated the self-referencing path in `ARCHITECTURE.md` (repo-wide
      doc grep found only this one hit).
   5. [x] Verified: ran `main.py` manually from the new location — clean
      exit, only a pre-existing/unrelated Instagram 429 rate-limit in the
      output, nothing path-related.
4. [x] Move and fix `whatsapp-claude-bot` — **done 2026-09-12**. Simplest
   move so far: the bot itself runs from `/opt/whatsapp-bot`, not from here
   (this repo is just the source, manually copied over), so no cron/systemd/
   dashboard dependency existed to fix — confirmed via a fresh survey before
   moving.
   1. [x] Moved `/home/dave/whatsapp-claude-bot` → `/home/dave/projects/whatsapp-claude-bot`.
   2. [x] Fixed the `sudo cp /home/dave/whatsapp-claude-bot/{...}
      /opt/whatsapp-bot/` deploy command and the `/opt` sandboxing-rationale
      prose in `spec.md`, plus the path mention in `TODO.md` — 4 hits total,
      repo-wide grep afterwards confirmed none left.
5. [x] Move `google-workspace-migration` — **done 2026-09-12**. Just 2 docs
   (`migration-plan.md`, `TODO.md`), no self-references, no cron/systemd —
   but the survey found the real touchpoint: the dashboard's own
   `PROJECT_TODOS` list hardcodes this repo's `TODO.md` path (same failure
   pattern as `server-scripts`'s log paths in item 2 — would have silently
   dropped this project's card off the dashboard).
   1. [x] Moved `/home/dave/google-workspace-migration` →
      `/home/dave/projects/google-workspace-migration`.
   2. [x] Updated the path in `app.py`'s `PROJECT_TODOS` and restarted
      `daves-server-dashboard.service` (verified clean restart, no
      tracebacks, serving normally).
6. [x] Move `encode-staging` — **done 2026-09-12**, to `/home/dave/staging/`
   (not `projects/` — matches the layout decision in item 1: transient
   working data, not maintained code). Touched more than expected: the
   media-resize app itself hardcodes this path in three places, not just
   the systemd unit.
   1. [x] Moved `/home/dave/encode-staging` → `/home/dave/staging/encode-staging`.
   2. [x] Updated `MR_STAGING_DIR` in both the live
      `/etc/systemd/system/media-resize-worker-server.service` and its
      checked-in copy at `/var/www/media-resize/systemd/`, then
      `sudo systemctl daemon-reload` (this worker is currently
      disabled/inactive — see media-resize's own `TODO.md` item 4 — so no
      restart needed there, just correctness for whenever it's re-enabled).
   3. [x] Updated `LOCAL_STAGING` in `/var/www/media-resize/app/app.py` and
      the `"server"` entry's `staging` field in `workers.json` — restarted
      `media-resize.service` (this one IS live) and verified clean restart.
   4. [x] Updated the 3 doc references in `RESIZE-MEDIA.md` (left the
      unrelated `/tmp/encode-staging` typo-path for `home-pc` alone — that's
      a different, pre-existing, documented bug on a different machine, not
      part of this move).
   5. [x] Updated the hardcoded path in `scratch/app_check.py`.
   6. [x] Repo-wide grep afterwards found no remaining `/home/dave/encode-staging`
      references anywhere except this to-do file's own history.
7. [ ] Decide on `scratch/` — it's one-off/disposable scripts with
   self-referencing absolute output paths; likely not worth fixing each one,
   just leave it where it is or accept old scripts break.
8. [ ] After each project above is moved and verified, remove its `.bak`/old
   copy rather than leaving both around.
