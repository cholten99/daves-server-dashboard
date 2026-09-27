import gzip
import glob
import html as html_lib
import http.cookiejar
import json
import os
import re
import sqlite3
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime, timedelta
from html.parser import HTMLParser

from guessit import guessit as _guessit
from flask import Flask, request, redirect, url_for, render_template, make_response, jsonify

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dsd-static-key-2026')

PASSWORD    = os.environ.get('DASHBOARD_PASSWORD', 'watchingdaves2026')
COOKIE_NAME = 'dsd_auth'
COOKIE_VAL  = 'granted'

FINDINGS_LOG   = '/home/dave/projects/server-scripts/audit-findings.log'
FINDINGS_ROTATED_GLOB = '/home/dave/projects/server-scripts/audit-findings.log.*.gz'
BACKUP_LOGS_DIR = '/home/dave/projects/server-scripts/logs'
MR_DB_PATH      = '/var/www/media-resize/state.db'
MR_WORKERS_PATH = '/var/www/media-resize/workers.json'

BOWSY_FEED_LOG  = '/home/dave/logs/bowsy-feed.log'

# Search hits (Search Console clicks) + page hits (Cloudflare Web Analytics
# RUM human pageloads) per site, pulled daily by site-traffic/pull_daily.py
# into this DB. Site list here must match SITES in that script -- it owns
# the data, this just reads it.
SITE_TRAFFIC_DB = '/var/www/site-traffic/site_traffic.db'
SITE_TRAFFIC_SITES = [
    ('alobear.co.uk',       'Alo Bear'),
    ('aloysius-bear.co.uk', 'Aloysius Bear'),
    ('bowsy.co.uk',         'Bowsy'),
    ('nationalstrategy.uk', 'National Strategy'),
    ('policycamp.org.uk',   'PolicyCamp'),
    ('transformgov.org.uk', 'TransformGov'),
    ('ukgovcamp.com',       'UK Gov Camp'),
    ('ukpolyamory.org',     'UK Polyamory'),
]

# Bluesky handles to show follower counts for, alphabetical by handle (matches
# how the user asked for the row to be ordered). Fetched live from Bluesky's
# public (unauthenticated) AppView API and cached in-process -- see
# BLUESKY_CACHE_TTL below -- rather than needing a whole new cron+DB pipeline
# like site-traffic has, since this is a single cheap number per account.
BLUESKY_API_BASE = 'https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile'
BLUESKY_ACCOUNTS = [
    ('bowsy.co.uk',                  'Bowsy'),
    ('policycamp.bsky.social',       'Policy Camp'),
    ('polyday.bsky.social',          'Poly Day'),
    ('still-love-it.bsky.social',    'Will You Still Love It Tomorrow'),
    ('transformgovtalks.bsky.social', 'TransformGov Talks'),
    ('uk-poly-assoc.bsky.social',    'UK Polyamory Association'),
    ('ukgovcamp.com',                'UK Gov Camp'),
    ('ukgovcomms.bsky.social',       'UK Gov Comms'),
    ('unofficialandy.bsky.social',   'Unofficial Andy'),
]
BLUESKY_CACHE_TTL = timedelta(minutes=15)
_bluesky_cache = {'fetched_at': None, 'data': []}

# Each project's to-do list lives in its own repo/directory as a hand-maintained
# TODO.md (no auto-sync script -- these are edited manually). Order here is
# display order on the dashboard.
PROJECT_TODOS = [
    ('Google Workspace Migration',        '/home/dave/projects/google-workspace-migration/TODO.md'),
    ('Daves Apps Restart',                '/var/www/daves-apps/daves-apps/TODO.md'),
    ('Notify Printer',                     '/var/www/notify-printer/TODO.md'),
]

# media-resize already computes per-worker encode progress/ETA itself (SSH-probes
# each worker, caches for 30s) -- rather than duplicating that, log into its own
# /api/data as a regular authenticated client and read the numbers back out.
MR_BASE_URL  = 'http://127.0.0.1:5001'
MR_PASSWORD  = os.environ.get('MEDIA_RESIZE_PASSWORD', 'makethemsmaller')
# A Mac worker toggle can take up to ~16s server-side (two SSH attempts --
# meshnet then LAN fallback -- at up to 8s each), plus overhead. This must
# stay comfortably above that; see mr_toggle_worker() for why a too-short
# timeout here is actively harmful, not just slow.
MR_TOGGLE_TIMEOUT = 25
_mr_cookie_jar = http.cookiejar.CookieJar()
_mr_opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(_mr_cookie_jar))

SECURITY_DAYS = 6
BACKUP_RUNS_LIMIT = 10
HD1_PREFIX = '/mnt/portable1'

# Ideas board: coding-project / paper / blog-post ideas, tracked as a small
# two-column Trello-like board (backlog -> current) rather than a hand-edited
# TODO.md like PROJECT_TODOS above. This app owns the schema outright (unlike
# the read-only DBs elsewhere in this file), so it creates it on load.
IDEAS_DB_PATH = os.path.join(os.path.dirname(__file__), 'ideas.db')
IDEAS_LISTS = ('backlog', 'current')

SEVERITY_RANK = {'CRITICAL': 3, 'HIGH': 2, 'MEDIUM': 1, 'LOW': 0}


# ── Auth ──────────────────────────────────────────────────────────────────────

def authed():
    return request.cookies.get(COOKIE_NAME) == COOKIE_VAL


# ── Helpers ───────────────────────────────────────────────────────────────────

_display_name_cache = {}


def display_name(filename):
    # Mirrors media-resize's own app.py so "in progress" filenames read the same
    # in both places, e.g. "12.Angry.Men.1957.720p.YIFY.mp4" -> "12 Angry Men.mkv".
    if filename in _display_name_cache:
        return _display_name_cache[filename]
    g = _guessit(filename)
    title = g.get('title', filename)
    season, episode = g.get('season'), g.get('episode')
    # guessit returns a list instead of an int for multi-episode files, e.g.
    # "S01E01-E02" -> episode=[1, 2] -- same bug exists in media-resize's own
    # app.py; take the first episode of the range rather than crashing.
    if isinstance(season, list):
        season = season[0] if season else None
    if isinstance(episode, list):
        episode = episode[0] if episode else None
    # guessit mis-parses British "Series N Episode M" naming: it finds the
    # episode fine but shoves "Series N" into alternative_title instead of
    # season. Recover the season from there rather than dropping it --
    # E06-only would still collide between e.g. Series 1 Episode 6 and
    # Series 2 Episode 6, the exact kind of clash this is meant to avoid.
    if season is None:
        alt = g.get('alternative_title') or ''
        if isinstance(alt, list):
            alt = alt[0] if alt else ''
        m = re.search(r'(?i)\bseries\s*(\d+)\b', alt)
        if m:
            season = int(m.group(1))
    part = g.get('part')
    if isinstance(part, list):
        part = part[0] if part else None
    part_suffix = f'.Part{part}' if part is not None else ''
    if season is not None and episode is not None:
        name = f'{title} S{season:02d}E{episode:02d}{part_suffix}.mkv'
    elif episode is not None:
        name = f'{title} E{episode:02d}{part_suffix}.mkv'
    else:
        # Same fallback-to-original-stem fix applied to media-resize's own
        # app.py on 2026-07-30: without it, unrelated files guessit reduces to
        # the same bare title (no season/episode found) show up here as if
        # they collide, even though media-resize's clean_stem() -- the function
        # that actually decides the delivery path -- already keeps them
        # distinct. Keep this mirrored fix in sync with the other copy.
        name = f'{os.path.splitext(filename)[0]}.mkv'
    _display_name_cache[filename] = name
    return name


def format_eta(seconds):
    # Matches media-resize's own ETA formatting exactly (durationHtml() in its
    # index.html) so the two pages read the same, right down to dropping
    # seconds once the estimate is a minute or more.
    if seconds is None:
        return None
    s = int(seconds)
    if s < 60:
        return f'{s}s'
    if s < 3600:
        return f'{s // 60}m'
    h, m = s // 3600, (s % 3600) // 60
    return f'{h}h {m}m' if m else f'{h}h'


def _mr_login():
    data = urllib.parse.urlencode({'password': MR_PASSWORD}).encode()
    req = urllib.request.Request(f'{MR_BASE_URL}/login', data=data, method='POST')
    _mr_opener.open(req, timeout=5).read()


def mr_toggle_worker(name):
    """POST to media-resize's own /toggle/<name> as an authenticated client --
    this dashboard has no worker state of its own, it just proxies the click.

    Toggle is a plain flip, not idempotent, so a timeout here must NOT be
    retried as if it were a fresh attempt -- media-resize's own handler can
    legitimately take close to MR_TOGGLE_TIMEOUT for a Mac worker (it tries
    an SSH launchctl call over meshnet, then a LAN fallback, before giving
    up), so a request that "times out" here may well have already flipped
    the flag server-side. Retrying blindly (as this used to) sends a second
    flip and cancels the first one out -- confirmed 2026-09-08, every click
    on macair-new's Enable button produced a load-then-unload pair in
    media-resize's toggle.log and left it right back where it started.

    Only a genuine auth failure (session expired, 403) is safe to retry --
    media-resize never touched its state for a rejected request."""
    req = urllib.request.Request(f'{MR_BASE_URL}/toggle/{name}', data=b'', method='POST')
    try:
        _mr_opener.open(req, timeout=MR_TOGGLE_TIMEOUT).read()
        return True
    except urllib.error.HTTPError as e:
        if e.code != 403:
            return False
        try:
            _mr_login()
            _mr_opener.open(req, timeout=MR_TOGGLE_TIMEOUT).read()
            return True
        except (urllib.error.URLError, OSError):
            return False
    except (urllib.error.URLError, OSError):
        return False


def get_media_resize_progress():
    """worker name -> {pct, estimated, eta_s, eta_display, stale_s}, sourced live
    from media-resize's own /api/data rather than re-probing workers over SSH.

    media-resize used to expose a separate 'active' list (one entry per busy
    worker); it now folds pct/estimated/eta_s/stale_s directly onto each entry
    in 'workers' instead (its dashboard merged a duplicate "In Progress" table
    into the Workers table). Read from there so idle workers -- which never
    appeared in 'active' anyway -- still round-trip harmlessly as all-None.
    """
    for attempt in (1, 2):
        try:
            resp = _mr_opener.open(f'{MR_BASE_URL}/api/data', timeout=5)
            payload = json.loads(resp.read())
            if 'error' in payload:
                raise PermissionError('not authed')
            progress = {}
            for w in payload.get('workers', []):
                progress[w['name']] = {
                    'pct':          w.get('pct'),
                    'estimated':    w.get('estimated'),
                    'eta_s':        w.get('eta_s'),
                    'eta_display':  format_eta(w.get('eta_s')),
                    'stale_s':      w.get('stale_s'),
                }
            return progress
        except (urllib.error.URLError, PermissionError, json.JSONDecodeError, OSError):
            if attempt == 1:
                try:
                    _mr_login()
                    continue
                except (urllib.error.URLError, OSError):
                    return {}
            return {}
    return {}


def timeago(ts):
    if not ts:
        return ''
    try:
        dt = datetime.fromisoformat(ts)
        diff = (datetime.now() - dt).total_seconds()
        if diff < 60:
            return 'just now'
        if diff < 3600:
            return f'{int(diff // 60)}m ago'
        h, m = int(diff // 3600), int((diff % 3600) // 60)
        return f'{h}h {m}m ago' if m else f'{h}h ago'
    except Exception:
        return ts


def format_duration(seconds):
    if seconds is None:
        return '—'
    seconds = int(round(seconds))
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    parts = []
    if h:
        parts.append(f'{h}h')
    if m:
        parts.append(f'{m}m')
    if s or not parts:
        parts.append(f'{s}s')
    return ' '.join(parts)


BLOCK_RE  = re.compile(r'=== (.*?) ===\n(.*?)(?=\n=== |\Z)', re.S)
ISSUE_RE  = re.compile(r'^\s*\[(\w+)\]\s*([^:]+):\s*(.*)$')
SECRET_FILE_PREFIX = 'Secret file publicly reachable:'


def _parse_findings_text(text, cutoff):
    blocks = []
    for m in BLOCK_RE.finditer(text):
        header, body = m.group(1).strip(), m.group(2)
        try:
            when = datetime.strptime(header, '%Y-%m-%d %H:%M')
        except ValueError:
            continue
        if when < cutoff:
            continue
        issues = []
        max_sev = None
        for line in body.splitlines():
            line = line.strip()
            if not line or line == 'No issues found.':
                continue
            im = ISSUE_RE.match(line)
            if im:
                sev, machine, message = im.groups()
                issues.append({'severity': sev, 'machine': machine.strip(), 'message': message.strip()})
                if max_sev is None or SEVERITY_RANK.get(sev, 0) > SEVERITY_RANK.get(max_sev, 0):
                    max_sev = sev
        blocks.append({'when': header, 'issues': issues, 'max_severity': max_sev})
    return blocks


def _collapse_secret_file_issues(issues):
    secret_issues = [i for i in issues if i['message'].startswith(SECRET_FILE_PREFIX)]
    if not secret_issues:
        return issues
    other_issues = [i for i in issues if not i['message'].startswith(SECRET_FILE_PREFIX)]
    count = len(secret_issues)
    other_issues.append({
        'severity': secret_issues[0]['severity'],
        'machine':  secret_issues[0]['machine'],
        'message':  f'{count} secret file{"s" if count != 1 else ""} publicly reachable',
    })
    return other_issues


def _gather_raw_findings_blocks(cutoff):
    blocks = []
    if os.path.exists(FINDINGS_LOG):
        with open(FINDINGS_LOG, 'r', errors='ignore') as f:
            blocks += _parse_findings_text(f.read(), cutoff)
    # The plain log rotates weekly, so a rotation right before "today" can leave
    # the live file with only one entry -- pull the most recent rotated archive
    # too so "last few days" doesn't go empty right after a rotation.
    rotated = sorted(glob.glob(FINDINGS_ROTATED_GLOB))[:2]
    for path in rotated:
        try:
            with gzip.open(path, 'rt', errors='ignore') as f:
                blocks += _parse_findings_text(f.read(), cutoff)
        except OSError:
            continue
    seen = set()
    unique = []
    for b in blocks:
        if b['when'] in seen:
            continue
        seen.add(b['when'])
        unique.append(b)
    unique.sort(key=lambda b: b['when'], reverse=True)
    return unique


def get_security_findings(days=SECURITY_DAYS):
    cutoff = datetime.now() - timedelta(days=days)
    blocks = _gather_raw_findings_blocks(cutoff)
    # The summary table gets the collapsed view (many individual "secret file
    # reachable" hits collapse to one count) -- full, uncollapsed detail is
    # only shown on the per-run detail page (see get_security_finding_detail).
    for b in blocks:
        b['issues'] = _collapse_secret_file_issues(b['issues'])
    return blocks


def get_security_finding_detail(when):
    cutoff = datetime.now() - timedelta(days=SECURITY_DAYS)
    blocks = _gather_raw_findings_blocks(cutoff)
    return next((b for b in blocks if b['when'] == when), None)


def get_backup_runs(limit=BACKUP_RUNS_LIMIT):
    runs = []
    for path in sorted(glob.glob(os.path.join(BACKUP_LOGS_DIR, '*.json')), reverse=True):
        try:
            with open(path, 'r') as f:
                d = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        try:
            started = datetime.fromisoformat(d['started_at'])
        except (KeyError, ValueError):
            continue
        actions = d.get('actions', [])
        completed = d.get('completed_at')
        duration_s = None
        if completed:
            try:
                duration_s = (datetime.fromisoformat(completed) - started).total_seconds()
            except ValueError:
                pass
        counts = Counter(a.get('status') for a in actions)
        runs.append({
            'run_id':            d.get('run_id', started.isoformat()),
            'started_at':        d['started_at'],
            'duration_s':        duration_s,
            'duration_display':  format_duration(duration_s),
            'dry_run':       bool(d.get('dry_run')),
            'total':         len(actions),
            'success':       counts.get('success', 0),
            'warning':       counts.get('warning', 0),
            'failed':        counts.get('failed', 0),
            'failed_names':  [a['name'] for a in actions if a.get('status') == 'failed'],
            'warning_names': [a['name'] for a in actions if a.get('status') == 'warning'],
        })
    runs.sort(key=lambda r: r['started_at'], reverse=True)
    runs = runs[:limit]

    # The only scheduled trigger is cron at 05:00 local time (see crontab);
    # anything else running is a manual/ad-hoc invocation. This is more robust
    # than comparing action counts, since backup.yml's enabled-action set
    # legitimately changes over time and would otherwise mislabel old scheduled
    # runs as "test" just because they ran fewer actions than today's config.
    for r in runs:
        if r['dry_run']:
            r['run_type'] = 'dry_run'
        else:
            started = datetime.fromisoformat(r['started_at'])
            r['run_type'] = 'full' if (started.hour, started.minute) == (5, 0) else 'test'

    return runs


RSYNC_NOISE_RE = re.compile(
    r'^(sending incremental file list|sent \d|total size is|building file list)'
)


def _parse_rsync_files(stdout):
    files = []
    for line in (stdout or '').splitlines():
        line = line.strip()
        if not line or line.endswith('/') or RSYNC_NOISE_RE.match(line):
            continue
        files.append(line)
    return files


def get_backup_run_detail(run_id):
    safe_id = os.path.basename(run_id)
    path = os.path.join(BACKUP_LOGS_DIR, f'{safe_id}.json')
    if not os.path.isfile(path):
        return None
    try:
        with open(path, 'r') as f:
            d = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None

    # backup.py groups actions into numbered steps and runs every action within
    # a step concurrently via ThreadPoolExecutor (steps themselves run one after
    # another) -- so a step's wall-clock time is bounded by its slowest action,
    # not the sum of all of them. Group the same way here so the page can show
    # that, rather than implying everything is purely cumulative.
    by_step = {}
    for a in d.get('actions', []):
        dest = a.get('destination', '') or ''
        duration_s = a.get('duration_seconds')
        entry = {
            'name':             a.get('name', ''),
            'destination':      dest,
            'status':           a.get('status', ''),
            'duration_seconds': duration_s,
            'duration_display': format_duration(duration_s),
        }
        rclone_summary = a.get('rclone_summary')
        if a.get('type') == 'rclone' and rclone_summary is not None:
            # backup.py now runs rclone with --use-json-log so this is a real
            # count, not a guess -- see _parse_rclone_json_log() there.
            entry['transfer_kind'] = 'rclone'
            entry['transferred']   = rclone_summary.get('transferred', 0)
            entry['checked']       = rclone_summary.get('checked', 0)
            entry['deleted']       = rclone_summary.get('deleted', 0)
            entry['file_count']    = entry['transferred']
            entry['files']         = a.get('rclone_changes', [])
            entry['warnings']      = a.get('rclone_warnings', [])
        elif a.get('type') == 'rclone':
            # Log predates the --use-json-log change -- rclone's stdout is
            # always empty by design, so there is no reliable count for these
            # older runs. Showing '0 files' here would just reintroduce the
            # exact took an hour, moved nothing? confusion this was meant
            # to fix, so say plainly that detail isn't available instead.
            entry['transfer_kind'] = 'rclone_legacy'
            entry['file_count']    = None
            entry['files']         = []
            entry['warnings']      = []
        else:
            files = _parse_rsync_files(a.get('stdout', ''))
            entry['transfer_kind'] = 'rsync'
            entry['file_count']    = len(files)
            entry['files']         = files
            entry['warnings']      = []
        by_step.setdefault(a.get('step', 0), []).append(entry)

    steps = []
    for step_num in sorted(by_step):
        step_actions = by_step[step_num]
        wall_s = max((a['duration_seconds'] or 0) for a in step_actions)
        concurrent = len(step_actions) > 1
        for a in step_actions:
            a['bar_pct'] = (
                min(100, round(100 * (a['duration_seconds'] or 0) / wall_s))
                if concurrent and wall_s else None
            )
        steps.append({
            'step':          step_num,
            'concurrent':    concurrent,
            'wall_display':  format_duration(wall_s),
            'actions':       step_actions,
        })

    return {
        'run_id':     d.get('run_id', safe_id),
        'started_at': d.get('started_at', ''),
        'dry_run':    bool(d.get('dry_run')),
        'steps':      steps,
    }


def get_media_resize_status():
    result = {
        'reachable': False,
        'workers': [],
        'queue_count': 0,
        'done_count': 0,
        'failed_count': 0,
        'saved_gb': 0.0,
        'saved_pct': 0.0,
    }
    try:
        con = sqlite3.connect(MR_DB_PATH, timeout=5)
        con.row_factory = sqlite3.Row
        active_rows = con.execute(
            "SELECT path, status, worker, host, started_at FROM files "
            "WHERE status IN ('claimed','encoding','syncing','syncing_back') "
            "ORDER BY started_at"
        ).fetchall()
        queue_count = con.execute("SELECT COUNT(*) c FROM files WHERE status='queued'").fetchone()['c']
        done_count = con.execute("SELECT COUNT(*) c FROM files WHERE status='done'").fetchone()['c']
        failed_count = con.execute("SELECT COUNT(*) c FROM files WHERE status='fail'").fetchone()['c']
        totals = con.execute(
            "SELECT COALESCE(SUM(size_in - size_out), 0) saved, COALESCE(SUM(size_in), 0) total_in "
            "FROM files WHERE status='done'"
        ).fetchone()
        con.close()

        result['reachable'] = True
        result['queue_count'] = queue_count
        result['done_count'] = done_count
        result['failed_count'] = failed_count
        saved, total_in = totals['saved'] or 0, totals['total_in'] or 0
        result['saved_gb'] = round(saved / (1024 ** 3), 1)
        result['saved_pct'] = round((saved / total_in * 100) if total_in else 0.0, 1)
    except (sqlite3.Error, OSError):
        return result

    active_by_worker = {
        r['worker']: {
            'filename':   display_name(os.path.basename(r['path'])),
            'status':     r['status'],
            'started_at': r['started_at'] or '',
        } for r in active_rows if r['worker']
    }

    progress_by_worker = get_media_resize_progress()

    try:
        with open(MR_WORKERS_PATH, 'r') as f:
            workers = json.load(f)
        result['workers'] = [{
            'name':          w['name'],
            'display':       w.get('display', w['name']),
            'enabled':       w.get('enabled', True),
            'busy':          w['name'] in active_by_worker,
            'current_file':  active_by_worker.get(w['name'], {}).get('filename'),
            'current_status': active_by_worker.get(w['name'], {}).get('status'),
            'started_at':    active_by_worker.get(w['name'], {}).get('started_at'),
            'pct':           progress_by_worker.get(w['name'], {}).get('pct'),
            'estimated':     progress_by_worker.get(w['name'], {}).get('estimated'),
            'eta_display':   progress_by_worker.get(w['name'], {}).get('eta_display'),
            'stale_s':       progress_by_worker.get(w['name'], {}).get('stale_s'),
        } for w in workers]
    except (OSError, json.JSONDecodeError, KeyError):
        pass

    return result


JOB_LOG_LINE_RE = re.compile(r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?:,\d+)? (\w+)(?: [^\s:]+)?: (.*)$')


def _last_job_status(log_path):
    if not os.path.isfile(log_path):
        return None
    try:
        with open(log_path, 'r', errors='ignore') as f:
            lines = f.readlines()
    except OSError:
        return None
    for line in reversed(lines):
        m = JOB_LOG_LINE_RE.match(line.strip())
        if not m:
            continue
        ts, level, msg = m.groups()
        if level.upper() == 'ERROR':
            return {'last_run': ts, 'status': 'fail', 'message': msg}
        return {'last_run': ts, 'status': 'ok', 'message': msg}
    return None


def _site_traffic_rows(con, domain, days=7):
    # page_human/page_bot come from Cloudflare Web Analytics (RUM, real
    # browser beacon) -- raw page_views/page_requests count every response
    # including crawlers/scrapers and turned out to be ~100-1000x real human
    # traffic on these sites (verified 2026-07-13), so RUM is what's displayed.
    return con.execute(
        "SELECT date, search_clicks, page_human FROM daily_stats "
        "WHERE site=? AND date >= date('now', ?) ORDER BY date",
        (domain, f'-{days - 1} days'),
    ).fetchall()


def _latest_non_null(rows, key):
    # Search Console lags 1-2 days behind Cloudflare, so the most recent row
    # can have one metric populated and the other still NULL -- report each
    # metric's own most recent value rather than freezing both on one row.
    for row in reversed(rows):
        if row[key] is not None:
            return row[key]
    return 0


def get_bluesky_followers():
    """Live-fetches follower counts from Bluesky's public AppView API,
    cached in-process for BLUESKY_CACHE_TTL. A failed/unresolvable handle
    (e.g. a typo, or a handle that genuinely isn't registered) shows as
    'error' rather than silently dropping the row or showing 0, since those
    two cases mean very different things here."""
    now = datetime.now()
    if _bluesky_cache['fetched_at'] and now - _bluesky_cache['fetched_at'] < BLUESKY_CACHE_TTL:
        return _bluesky_cache['data']

    results = []
    for handle, display in BLUESKY_ACCOUNTS:
        entry = {'name': display, 'handle': handle, 'followers': None, 'ok': False}
        try:
            url = f'{BLUESKY_API_BASE}?{urllib.parse.urlencode({"actor": handle})}'
            with urllib.request.urlopen(url, timeout=8) as resp:
                data = json.loads(resp.read())
            entry['followers'] = data.get('followersCount', 0)
            entry['ok'] = True
        except (urllib.error.URLError, OSError, json.JSONDecodeError, KeyError, ValueError):
            pass
        results.append(entry)

    _bluesky_cache['fetched_at'] = now
    _bluesky_cache['data'] = results
    return results


def get_site_traffic():
    """Feeds the summary table on the main dashboard. Data comes from
    site-traffic/pull_daily.py's daily cron pull, not computed here."""
    try:
        con = sqlite3.connect(SITE_TRAFFIC_DB, timeout=5)
        con.row_factory = sqlite3.Row
    except sqlite3.Error:
        return []
    results = []
    for domain, display in SITE_TRAFFIC_SITES:
        rows = _site_traffic_rows(con, domain)
        results.append({
            'name':          display,
            'search_daily':  _latest_non_null(rows, 'search_clicks'),
            'search_weekly': sum(r['search_clicks'] or 0 for r in rows),
            'page_daily':    _latest_non_null(rows, 'page_human'),
            'page_weekly':   sum(r['page_human'] or 0 for r in rows),
        })
    con.close()
    return results


SPARKLINE_W, SPARKLINE_H = 300, 56
SPARKLINE_PAD_X, SPARKLINE_PAD_Y = 6, 10


def _sparkline(days, series):
    """Precomputes SVG polyline points + per-point dot positions for a single-
    series trend chart, scaled to [0, max(series)] so zero is grounded at the
    baseline. Geometry is computed here, not in the template, matching how the
    rest of this file precomputes display values (eta_display, etc.)."""
    n = len(series)
    if n == 0:
        return None
    vmax = max(series) or 1
    plot_w = SPARKLINE_W - 2 * SPARKLINE_PAD_X
    plot_h = SPARKLINE_H - 2 * SPARKLINE_PAD_Y
    step = plot_w / (n - 1) if n > 1 else 0
    dots = []
    for i, v in enumerate(series):
        x = round(SPARKLINE_PAD_X + step * i, 1)
        y = round(SPARKLINE_PAD_Y + plot_h * (1 - v / vmax), 1)
        dots.append({'x': x, 'y': y, 'v': v, 'day': days[i]})
    return {
        'points': ' '.join(f"{d['x']},{d['y']}" for d in dots),
        'dots':   dots,
        'last':   dots[-1],
        'width':  SPARKLINE_W,
        'height': SPARKLINE_H,
        'baseline_y': round(SPARKLINE_PAD_Y + plot_h, 1),
    }


def get_site_traffic_detail():
    """Per-day breakdown for the expanded /site-traffic page."""
    try:
        con = sqlite3.connect(SITE_TRAFFIC_DB, timeout=5)
        con.row_factory = sqlite3.Row
    except sqlite3.Error:
        return []
    sites = []
    for domain, display in SITE_TRAFFIC_SITES:
        rows = _site_traffic_rows(con, domain)
        days = [datetime.strptime(r['date'], '%Y-%m-%d').strftime('%a %d %b') for r in rows]
        search_series = [r['search_clicks'] or 0 for r in rows]
        page_series = [r['page_human'] or 0 for r in rows]
        sites.append({
            'name':          display,
            'days':          days,
            'search_series': search_series,
            'page_series':   page_series,
            'search_daily':  _latest_non_null(rows, 'search_clicks'),
            'search_weekly': sum(search_series),
            'page_daily':    _latest_non_null(rows, 'page_human'),
            'page_weekly':   sum(page_series),
            'search_chart':  _sparkline(days, search_series),
            'page_chart':    _sparkline(days, page_series),
        })
    con.close()
    return sites


def _cron_schedule_human(schedule):
    """Best-effort plain-English rendering of a 5-field cron schedule. Falls
    back to the raw cron expression for anything more exotic than a fixed
    daily/hourly time or a '*/N' step, which covers every job in dave's
    crontab as of writing."""
    minute, hour, dom, month, dow = schedule.split()
    if dom == '*' and month == '*' and dow == '*':
        if minute == '*' and hour == '*':
            return 'Every minute'
        if hour == '*' and minute.startswith('*/'):
            return f'Every {minute[2:]} minutes'
        if hour == '*' and minute.isdigit():
            return f'Hourly at :{int(minute):02d}'
        if hour.isdigit() and minute.isdigit():
            return f'Daily at {int(hour):02d}:{int(minute):02d}'
    return schedule


# Human descriptions for known cron commands, matched by substring against
# the full command line -- keyed on a stable bit of the path/script name so
# unrelated flags/redirects in the crontab entry don't break the match. Log
# path is used to show a real Last run/Status (via _last_job_status), where
# the script actually writes timestamped 'LEVEL: message' lines; None where
# it doesn't (or where another dashboard section -- Security audit, Backups
# -- already covers that job's status in more detail than a one-line badge
# could).
CRON_JOB_INFO = [
    # needle,                       description,                                                     log path
    ('security-audit.sh',          'Security audit scan',                                            None),
    ('backup.py',                  'Server backup run',                                               None),
    ('fetch-latest-post.py',       'Fetch latest Bowsy blog post',                                    BOWSY_FEED_LOG),
    ('site-traffic/pull_daily.py', 'Pull site traffic stats (Search Console + Cloudflare)',           '/var/www/site-traffic/logs/pull.log'),
    ('unofficial-andy/main.py',    "Cross-post TikTok/Instagram to Bluesky ('Unofficial Andy')",      '/home/dave/projects/unofficial-andy/logs/cron.log'),
    ('count_listens.py',           'Count podcast listens (all shows)',                               None),
    ('sync_podcast_host.py',       'Sync TransformGov Talks podcast stats',                            None),
    ('selfheal.py',                'Media-resize self-heal (auto-fix stuck jobs)',                     '/var/www/media-resize/logs/selfheal-cron.log'),
    ('update_rebuild_docs.py',     'Rebuild-docs drift check (SERVER-BACKUP.md / home-pc-backup.md)',  None),
]


def _cron_job_info(command):
    for needle, desc, log_path in CRON_JOB_INFO:
        if needle in command:
            return desc, log_path
    # Fallback for anything not in the table above: the first path-looking
    # token's filename, minus extension, so a new cron job at least shows
    # something better than the full command line. Skip interpreter
    # executables (python, python3, bash, sh, ...) -- a venv path like
    # ".../venv/bin/python3 /path/to/real_script.py" would otherwise match
    # on "python3" itself and show that instead of the actual script.
    INTERPRETERS = {'python', 'python3', 'python2', 'bash', 'sh', 'node', 'perl', 'ruby'}
    for token in command.split():
        if '/' in token and os.path.splitext(os.path.basename(token))[0] not in INTERPRETERS:
            return os.path.splitext(os.path.basename(token))[0], None
    return command, None


def get_cron_jobs():
    """Full live listing of dave's own crontab (`crontab -l`) -- i.e. all
    non-system cron jobs, as opposed to root's /etc/crontab / /etc/cron.d
    entries. Commented-out '# DISABLED ...' lines are skipped since they
    aren't actually scheduled."""
    try:
        out = subprocess.run(['crontab', '-l'], capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    jobs = []
    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split(None, 5)
        if len(parts) < 6:
            continue
        schedule, command = ' '.join(parts[:5]), parts[5]
        description, log_path = _cron_job_info(command)
        status = (log_path and _last_job_status(log_path)) or \
            {'last_run': None, 'status': 'unknown', 'message': 'No log entries found'}
        jobs.append({
            'schedule': schedule,
            'schedule_human': _cron_schedule_human(schedule),
            'command': command,
            'description': description,
            **status,
        })
    return jobs


TODO_ITEM_RE = re.compile(r'^(?:\d+\.|-)\s*\[([ xX~])\]\s*(.*)$')


def _parse_todo_md(path):
    """Pulls checkbox items ('1. [x] ...' / '- [ ] ...') out of a hand-maintained
    TODO.md. Indented lines directly under an item are folded into its detail
    text (for a hover tooltip); anything unindented (headings, new paragraphs)
    ends the current item instead of being absorbed into it."""
    items = []
    try:
        with open(path, 'r', errors='ignore') as f:
            lines = f.readlines()
    except OSError:
        return items

    current = None
    for raw in lines:
        stripped = raw.strip()
        m = TODO_ITEM_RE.match(stripped)
        if m:
            if current:
                items.append(current)
            state, text = m.groups()
            current = {'state': state.lower(), 'summary': text.strip(), 'detail': text.strip()}
        elif current is not None and raw[:1].isspace() and stripped and not stripped.startswith('#'):
            current['detail'] += ' ' + stripped
        else:
            if current:
                items.append(current)
            current = None
    if current:
        items.append(current)
    return items


def get_project_todos():
    projects = []
    for name, path in PROJECT_TODOS:
        items = _parse_todo_md(path)
        for i, item in enumerate(items, 1):
            item['number'] = i
            # detail always starts with summary's own text (see _parse_todo_md) --
            # extra is just whatever got folded in beyond that (indented sub-bullet
            # lines), so it can be shown as its own visible line rather than only
            # in a hover-only title attribute.
            item['extra'] = item['detail'][len(item['summary']):].strip()
        projects.append({
            'name':       name,
            'slug':       re.sub(r'\W+', '-', name.lower()).strip('-'),
            'todo_items': items,
            'done':       sum(1 for i in items if i['state'] == 'x'),
            'total':      len(items),
        })
    return projects


# ── Ideas board ──────────────────────────────────────────────────────────────

IDEAS_ALLOWED_TAGS = {
    'p', 'br', 'div', 'span', 'b', 'strong', 'i', 'em', 'u', 's', 'strike',
    'ul', 'ol', 'li', 'a', 'blockquote', 'code', 'pre',
}
IDEAS_VOID_TAGS = {'br'}
IDEAS_LINK_SCHEME_RE = re.compile(r'^(https?:|mailto:)', re.I)


class _RichTextSanitizer(HTMLParser):
    """Whitelist-based cleaner for card description HTML saved from the
    contenteditable editor. Runs server-side even with a single user, since
    browser-generated markup (execCommand output, pasted content) isn't
    otherwise trustworthy input to store and later re-render as raw HTML.
    Strips every attribute except href on <a>, and drops disallowed tags
    while keeping their text content (script/style content is dropped too)."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.out = []
        self._drop_depth = 0

    def handle_starttag(self, tag, attrs):
        if tag in ('script', 'style'):
            self._drop_depth += 1
            return
        if self._drop_depth or tag not in IDEAS_ALLOWED_TAGS:
            return
        if tag == 'a':
            href = dict(attrs).get('href', '')
            if IDEAS_LINK_SCHEME_RE.match(href):
                safe_href = html_lib.escape(href, quote=True)
                self.out.append(f'<a href="{safe_href}" target="_blank" rel="noopener noreferrer">')
            else:
                self.out.append('<a>')
        else:
            self.out.append(f'<{tag}>')

    def handle_startendtag(self, tag, attrs):
        if tag in IDEAS_VOID_TAGS and not self._drop_depth:
            self.out.append(f'<{tag}>')

    def handle_endtag(self, tag):
        if tag in ('script', 'style'):
            self._drop_depth = max(0, self._drop_depth - 1)
            return
        if self._drop_depth or tag not in IDEAS_ALLOWED_TAGS or tag in IDEAS_VOID_TAGS:
            return
        self.out.append(f'</{tag}>')

    def handle_data(self, data):
        if not self._drop_depth:
            self.out.append(html_lib.escape(data))


def sanitize_rich_text(raw):
    parser = _RichTextSanitizer()
    parser.feed(raw or '')
    parser.close()
    return ''.join(parser.out)


def init_ideas_db():
    con = sqlite3.connect(IDEAS_DB_PATH)
    con.executescript("""
        CREATE TABLE IF NOT EXISTS cards (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            title             TEXT NOT NULL,
            list_name         TEXT NOT NULL CHECK(list_name IN ('backlog', 'current')),
            position          INTEGER NOT NULL,
            description_html  TEXT NOT NULL DEFAULT '',
            created_at        TEXT NOT NULL,
            updated_at        TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS todo_items (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            card_id   INTEGER NOT NULL REFERENCES cards(id) ON DELETE CASCADE,
            text      TEXT NOT NULL,
            checked   INTEGER NOT NULL DEFAULT 0,
            position  INTEGER NOT NULL
        );
    """)
    con.commit()
    con.close()


def _ideas_con():
    con = sqlite3.connect(IDEAS_DB_PATH)
    con.execute('PRAGMA foreign_keys = ON')
    con.row_factory = sqlite3.Row
    return con


def get_ideas_board():
    con = _ideas_con()
    cards = con.execute('SELECT * FROM cards ORDER BY list_name, position').fetchall()
    todo_rows = con.execute('SELECT * FROM todo_items ORDER BY card_id, position').fetchall()
    con.close()

    todos_by_card = {}
    for t in todo_rows:
        todos_by_card.setdefault(t['card_id'], []).append({
            'id': t['id'], 'text': t['text'], 'checked': bool(t['checked']),
        })

    board = {name: [] for name in IDEAS_LISTS}
    for c in cards:
        items = todos_by_card.get(c['id'], [])
        board[c['list_name']].append({
            'id':               c['id'],
            'title':            c['title'],
            'description_html': c['description_html'],
            'todo_items':       items,
            'done_count':       sum(1 for i in items if i['checked']),
            'total_count':      len(items),
        })
    return board


def create_idea_card(title, list_name):
    now = datetime.now().isoformat(timespec='seconds')
    con = _ideas_con()
    pos = con.execute(
        'SELECT COALESCE(MAX(position), -1) + 1 p FROM cards WHERE list_name=?', (list_name,)
    ).fetchone()['p']
    cur = con.execute(
        'INSERT INTO cards (title, list_name, position, description_html, created_at, updated_at) '
        'VALUES (?, ?, ?, ?, ?, ?)',
        (title, list_name, pos, '', now, now),
    )
    con.commit()
    new_id = cur.lastrowid
    con.close()
    return new_id


def update_idea_card(card_id, title=None, description_html=None):
    fields, values = [], []
    if title is not None:
        fields.append('title = ?')
        values.append(title)
    if description_html is not None:
        fields.append('description_html = ?')
        values.append(sanitize_rich_text(description_html))
    if not fields:
        return
    fields.append('updated_at = ?')
    values.append(datetime.now().isoformat(timespec='seconds'))
    values.append(card_id)
    con = _ideas_con()
    con.execute(f'UPDATE cards SET {", ".join(fields)} WHERE id = ?', values)
    con.commit()
    con.close()


def _renumber_list(con, list_name):
    ids = [r['id'] for r in con.execute(
        'SELECT id FROM cards WHERE list_name = ? ORDER BY position', (list_name,)
    ).fetchall()]
    for i, cid in enumerate(ids):
        con.execute('UPDATE cards SET position = ? WHERE id = ?', (i, cid))


def move_idea_card(card_id, list_name, before_id=None):
    con = _ideas_con()
    row = con.execute('SELECT list_name FROM cards WHERE id = ?', (card_id,)).fetchone()
    if row is None:
        con.close()
        return
    old_list = row['list_name']

    target_ids = [r['id'] for r in con.execute(
        'SELECT id FROM cards WHERE list_name = ? AND id != ? ORDER BY position',
        (list_name, card_id),
    ).fetchall()]
    idx = target_ids.index(before_id) if before_id in target_ids else len(target_ids)
    target_ids.insert(idx, card_id)
    for i, cid in enumerate(target_ids):
        con.execute('UPDATE cards SET list_name = ?, position = ? WHERE id = ?', (list_name, i, cid))

    if old_list != list_name:
        _renumber_list(con, old_list)

    con.commit()
    con.close()


def delete_idea_card(card_id):
    con = _ideas_con()
    row = con.execute('SELECT list_name FROM cards WHERE id = ?', (card_id,)).fetchone()
    con.execute('DELETE FROM cards WHERE id = ?', (card_id,))
    if row:
        _renumber_list(con, row['list_name'])
    con.commit()
    con.close()


def create_idea_todo(card_id, text):
    con = _ideas_con()
    pos = con.execute(
        'SELECT COALESCE(MAX(position), -1) + 1 p FROM todo_items WHERE card_id = ?', (card_id,)
    ).fetchone()['p']
    cur = con.execute(
        'INSERT INTO todo_items (card_id, text, checked, position) VALUES (?, ?, 0, ?)',
        (card_id, text, pos),
    )
    con.commit()
    new_id = cur.lastrowid
    con.close()
    return new_id


def update_idea_todo(todo_id, text=None, checked=None):
    fields, values = [], []
    if text is not None:
        fields.append('text = ?')
        values.append(text)
    if checked is not None:
        fields.append('checked = ?')
        values.append(1 if checked else 0)
    if not fields:
        return
    values.append(todo_id)
    con = _ideas_con()
    con.execute(f'UPDATE todo_items SET {", ".join(fields)} WHERE id = ?', values)
    con.commit()
    con.close()


def delete_idea_todo(todo_id):
    con = _ideas_con()
    con.execute('DELETE FROM todo_items WHERE id = ?', (todo_id,))
    con.commit()
    con.close()


init_ideas_db()


def build_dashboard():
    return {
        'project_todos': get_project_todos(),
        'bluesky_followers': get_bluesky_followers(),
        'site_traffic': get_site_traffic(),
        'security': get_security_findings(),
        'backups':  get_backup_runs(),
        'media_resize': get_media_resize_status(),
        'cron_jobs': get_cron_jobs(),
    }


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    if not authed():
        return redirect(url_for('login'))
    data = build_dashboard()
    return render_template('index.html', **data, timeago=timeago)


@app.route('/api/data')
def api_data():
    if not authed():
        return jsonify({'error': 'forbidden'}), 403
    return jsonify(build_dashboard())


@app.route('/ideas')
def ideas_page():
    if not authed():
        return redirect(url_for('login'))
    return render_template('ideas.html', board=get_ideas_board())


@app.route('/api/ideas/cards', methods=['POST'])
def api_ideas_create_card():
    if not authed():
        return jsonify({'error': 'forbidden'}), 403
    data = request.get_json(force=True, silent=True) or {}
    title = (data.get('title') or '').strip()
    list_name = data.get('list_name')
    if not title or list_name not in IDEAS_LISTS:
        return jsonify({'error': 'invalid'}), 400
    card_id = create_idea_card(title, list_name)
    return jsonify({'id': card_id})


@app.route('/api/ideas/cards/<int:card_id>', methods=['PATCH'])
def api_ideas_update_card(card_id):
    if not authed():
        return jsonify({'error': 'forbidden'}), 403
    data = request.get_json(force=True, silent=True) or {}
    update_idea_card(card_id, title=data.get('title'), description_html=data.get('description_html'))
    return jsonify({'ok': True})


@app.route('/api/ideas/cards/<int:card_id>', methods=['DELETE'])
def api_ideas_delete_card(card_id):
    if not authed():
        return jsonify({'error': 'forbidden'}), 403
    delete_idea_card(card_id)
    return jsonify({'ok': True})


@app.route('/api/ideas/cards/<int:card_id>/move', methods=['POST'])
def api_ideas_move_card(card_id):
    if not authed():
        return jsonify({'error': 'forbidden'}), 403
    data = request.get_json(force=True, silent=True) or {}
    list_name = data.get('list_name')
    if list_name not in IDEAS_LISTS:
        return jsonify({'error': 'invalid'}), 400
    move_idea_card(card_id, list_name, before_id=data.get('before_id'))
    return jsonify({'ok': True})


@app.route('/api/ideas/cards/<int:card_id>/todos', methods=['POST'])
def api_ideas_create_todo(card_id):
    if not authed():
        return jsonify({'error': 'forbidden'}), 403
    data = request.get_json(force=True, silent=True) or {}
    text = (data.get('text') or '').strip()
    if not text:
        return jsonify({'error': 'invalid'}), 400
    todo_id = create_idea_todo(card_id, text)
    return jsonify({'id': todo_id})


@app.route('/api/ideas/todos/<int:todo_id>', methods=['PATCH'])
def api_ideas_update_todo(todo_id):
    if not authed():
        return jsonify({'error': 'forbidden'}), 403
    data = request.get_json(force=True, silent=True) or {}
    update_idea_todo(todo_id, text=data.get('text'), checked=data.get('checked'))
    return jsonify({'ok': True})


@app.route('/api/ideas/todos/<int:todo_id>', methods=['DELETE'])
def api_ideas_delete_todo(todo_id):
    if not authed():
        return jsonify({'error': 'forbidden'}), 403
    delete_idea_todo(todo_id)
    return jsonify({'ok': True})


@app.route('/media-resize/toggle/<name>', methods=['POST'])
def media_resize_toggle(name):
    if not authed():
        return redirect(url_for('login'))
    mr_toggle_worker(name)
    return redirect(url_for('index'))


@app.route('/site-traffic')
def site_traffic():
    if not authed():
        return redirect(url_for('login'))
    return render_template('site_traffic.html', sites=get_site_traffic_detail())


@app.route('/backup/<run_id>')
def backup_detail(run_id):
    if not authed():
        return redirect(url_for('login'))
    detail = get_backup_run_detail(run_id)
    if detail is None:
        return render_template('backup_detail.html', run_id=run_id, not_found=True)
    return render_template('backup_detail.html', not_found=False, **detail)


@app.route('/security/<when>')
def security_detail(when):
    if not authed():
        return redirect(url_for('login'))
    detail = get_security_finding_detail(when)
    if detail is None:
        return render_template('security_detail.html', when=when, not_found=True)
    return render_template('security_detail.html', not_found=False, **detail)


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        if request.form.get('password') == PASSWORD:
            resp = make_response(redirect(url_for('index')))
            resp.set_cookie(COOKIE_NAME, COOKIE_VAL, httponly=True, samesite='Lax')
            return resp
        error = 'Wrong password.'
    return render_template('login.html', error=error)


@app.route('/logout')
def logout():
    resp = make_response(redirect(url_for('login')))
    resp.delete_cookie(COOKIE_NAME)
    return resp


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5002, debug=False)
