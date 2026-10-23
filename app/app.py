import gzip
import glob
import hashlib
import hmac
import html as html_lib
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

from flask import (Flask, request, redirect, url_for, render_template, jsonify,
                   send_file, session)

app = Flask(__name__)

# Overridable only so a test instance can run with throwaway values
SECRETS_DIR = os.environ.get('DSD_SECRETS_DIR', '/home/dave/secrets')


def _read_secret(name):
    with open(os.path.join(SECRETS_DIR, name)) as f:
        return f.read().strip()


# Both used to be hard-coded defaults here, and this repo is public on GitHub,
# so the password was readable by anyone -- and login was a fixed cookie value
# (dsd_auth=granted) that anyone could set without the password at all.
# Found 2026-10-22 when adding the Backups page, which serves backed-up files.
# Now: the password and session-signing key live only in the secrets store,
# and login is a signed Flask session that can't be forged without the key.
app.secret_key = _read_secret('dashboard_secret_key')
PASSWORD = _read_secret('dashboard_password')
app.config.update(
    PERMANENT_SESSION_LIFETIME=timedelta(days=30),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    # Only ever served over HTTPS (Cloudflare tunnel); DSD_INSECURE_COOKIES=1
    # is for testing on 127.0.0.1 without it.
    SESSION_COOKIE_SECURE=os.environ.get('DSD_INSECURE_COOKIES') != '1',
)

FINDINGS_LOG   = '/home/dave/projects/server-scripts/audit-findings.log'
FINDINGS_ROTATED_GLOB = '/home/dave/projects/server-scripts/audit-findings.log.*.gz'
BACKUP_LOGS_DIR = '/home/dave/projects/server-scripts/logs'

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


SECURITY_DAYS = 6
BACKUP_RUNS_LIMIT = 10
HD1_PREFIX = '/mnt/portable1'

# Projects board: coding-project / paper / blog-post ideas, tracked as a small
# two-column Trello-like board (backlog -> current) rather than a hand-edited
# TODO.md like PROJECT_TODOS above. This app owns the schema outright (unlike
# the read-only DBs elsewhere in this file), so it creates it on load.
PROJECTS_DB_PATH = os.path.join(os.path.dirname(__file__), 'projects.db')
PROJECTS_LISTS = ('backlog', 'current')
PROJECT_TAGS = ('code', 'blog', 'paper')
_UNSET = object()

SEVERITY_RANK = {'CRITICAL': 3, 'HIGH': 2, 'MEDIUM': 1, 'LOW': 0}


# ── Auth ──────────────────────────────────────────────────────────────────────

def authed():
    return session.get('authed') is True


# Single sign-on for the other *.bowsy.co.uk admin tools (Sonarr, Radarr,
# Prowlarr, qBittorrent, media-resize): logging in here also sets this cookie
# on the parent domain, and Apache's bowsy-sso-gate in front of each of those
# vhosts lets a request through only if it carries it (see
# server-scripts/apache/). Derived from the secret key rather than stored
# separately, so rotating dashboard_secret_key rotates it too -- after which
# server-scripts/apache/install-sso-token.sh must be re-run so Apache agrees.
SSO_COOKIE = 'bowsy_sso'
SSO_DOMAIN = '.bowsy.co.uk'
SSO_TOKEN = hmac.new(app.secret_key.encode(), b'bowsy-sso-v1', hashlib.sha256).hexdigest()


def _safe_next(url):
    """url if it's an https page on one of our own subdomains, else None --
    an open redirect after login would be a phishing aid."""
    try:
        u = urllib.parse.urlparse(url or '')
    except ValueError:
        return None
    host = (u.hostname or '').lower()
    if u.scheme == 'https' and (host == 'bowsy.co.uk' or host.endswith('.bowsy.co.uk')):
        return url
    return None


@app.after_request
def _no_referrer(resp):
    # qBittorrent's CSRF check rejects any page load whose Referer is another
    # site, so following its link from here (or being sent back to it after
    # logging in) got a bare "Unauthorized". Sending no Referer keeps its
    # CSRF protection on; nothing on these pages relies on Referer anyway.
    resp.headers['Referrer-Policy'] = 'no-referrer'
    return resp


@app.after_request
def _keep_sso_cookie(resp):
    # Also covers sessions that logged in before SSO existed
    if authed() and request.cookies.get(SSO_COOKIE) != SSO_TOKEN:
        resp.set_cookie(SSO_COOKIE, SSO_TOKEN, max_age=30 * 86400, domain=SSO_DOMAIN,
                        secure=app.config['SESSION_COOKIE_SECURE'], httponly=True, samesite='Lax')
    return resp


# ── Helpers ───────────────────────────────────────────────────────────────────

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


JOB_LOG_LINE_RE = re.compile(r'^\[?(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})(?:[.,]\d+)?\]?(?:\s+(\w+)(?: [^\s:]+)?:)?\s*(.*)$')


def _last_job_status(log_path):
    # log_path may contain a glob (e.g. update_rebuild_docs.py writes a fresh
    # timestamped file per run, not one fixed path) -- resolve to the most
    # recently modified match first.
    if '*' in log_path:
        matches = glob.glob(log_path)
        if not matches:
            return None
        log_path = max(matches, key=os.path.getmtime)
    if not os.path.isfile(log_path):
        return None
    try:
        with open(log_path, 'r', errors='ignore') as f:
            lines = f.readlines()
    except OSError:
        return None
    for line in reversed(lines):
        stripped = line.strip()
        if not stripped:
            continue
        m = JOB_LOG_LINE_RE.match(stripped)
        if not m:
            continue
        ts, level, msg = m.groups()
        ts = ts.replace('T', ' ')
        # Only a genuine 'LEVEL: message' line (fetch-latest-post.py etc) can
        # report fail -- logs that just prefix a bare timestamp (selfheal.py's
        # "[ts] clean run", the watchdog's "ts run start") have no level
        # concept, so those always read as ok; the raw text is still shown as
        # the message so anything worth noticing (e.g. the watchdog's "SSH ...
        # failed" lines) is visible even though it isn't flagged red here.
        if level and level.upper() == 'ERROR':
            return {'last_run': ts, 'status': 'fail', 'message': msg}
        return {'last_run': ts, 'status': 'ok', 'message': msg or (level or '')}
    # No line matched any timestamp pattern at all (count_listens.py,
    # sync_podcast_host.py -- neither prefixes its own output) -- fall back to
    # the log file's own mtime plus its last non-empty line, rather than
    # reporting unknown just because the script doesn't timestamp its lines.
    for line in reversed(lines):
        stripped = line.strip()
        if stripped:
            return {
                'last_run': datetime.fromtimestamp(os.path.getmtime(log_path)).strftime('%Y-%m-%d %H:%M:%S'),
                'status': 'ok',
                'message': stripped,
            }
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


# cron's single-token schedule shortcuts (crontab(5)), e.g. the @reboot entry
# that restarts Claude Code Remote Control after the box comes back up.
CRON_SHORTCUTS = {
    '@reboot': 'At boot',
    '@hourly': 'Hourly', '@daily': 'Daily', '@midnight': 'Daily',
    '@weekly': 'Weekly', '@monthly': 'Monthly', '@yearly': 'Yearly', '@annually': 'Yearly',
}


def _cron_schedule_human(schedule):
    """Best-effort plain-English rendering of a 5-field cron schedule. Falls
    back to the raw cron expression for anything more exotic than a fixed
    daily/hourly time or a '*/N' step, which covers every job in dave's
    crontab as of writing."""
    if schedule.startswith('@'):
        return CRON_SHORTCUTS.get(schedule, schedule)
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
# path is used to show a real Last run/Status via _last_job_status(), which
# handles several line formats (bracketed or bare timestamps, with or
# without a 'LEVEL:'/'LEVEL extra:' prefix, ISO-8601 'T' separators) and
# falls back to the log file's own mtime if no line has a parseable
# timestamp at all -- so the only two log_path values that don't resolve to
# a real ok/fail are security-audit.sh and backup.py, which use a sentinel
# instead of None: another section already covers their status in more
# detail than a one-line badge could -- Security audit just above on the
# System page (SEE_ABOVE -> 'see_above'), backup runs on the Backups page
# (SEE_BACKUPS_PAGE -> 'see_backups', a link there) -- rather than 'unknown',
# which is reserved for a job that's genuinely unaccounted for.
SEE_ABOVE = 'SEE_ABOVE'
SEE_BACKUPS_PAGE = 'SEE_BACKUPS_PAGE'
CRON_JOB_INFO = [
    # needle,                       description,                                                     log path
    ('security-audit.sh',          'Security audit scan',                                            SEE_ABOVE),
    ('backup.py',                  'Server backup run',                                               SEE_BACKUPS_PAGE),
    ('fetch-latest-post.py',       'Fetch latest Bowsy blog post',                                    BOWSY_FEED_LOG),
    ('site-traffic/pull_daily.py', 'Pull site traffic stats (Search Console + Cloudflare)',           '/var/www/site-traffic/logs/pull.log'),
    ('unofficial-andy/main.py',    "Cross-post TikTok/Instagram to Bluesky ('Unofficial Andy')",      '/home/dave/projects/unofficial-andy/logs/cron.log'),
    ('count_listens.py',           'Count podcast listens (all shows)',                               '/home/dave/logs/podcast-listens.log'),
    ('sync_podcast_host.py',       'Sync TransformGov Talks podcast stats',                            '/home/dave/logs/tgt-podcast-sync.log'),
    ('selfheal.py',                'Media-resize self-heal (auto-fix stuck jobs)',                     '/var/www/media-resize/logs/selfheal-cron.log'),
    ('media-resize-remote-watchdog.sh', 'Media-resize remote worker watchdog',                         '/home/dave/projects/server-scripts/media-resize-remote-watchdog.log'),
    ('remote-control/new-instance.sh', 'Start a Claude Code Remote Control instance after reboot',     '/home/dave/logs/claude-remote-control/reboot-start.log'),
    ('nordvpn-watchdog.sh',         'NordVPN watchdog (reconnect if internet lost while VPN "Connected")', '/home/dave/logs/nordvpn-watchdog.log'),
    # Writes a fresh timestamped file per run rather than one fixed path --
    # _last_job_status() resolves the glob to the most recently modified match.
    ('update_rebuild_docs.py',     'Rebuild-docs drift check (SERVER-BACKUP.md / home-pc-backup.md)',  os.path.join(BACKUP_LOGS_DIR, '*-rebuild-docs.log')),
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
        if line.startswith('@'):
            parts = line.split(None, 1)
            if len(parts) < 2:
                continue
            schedule, command = parts
        else:
            parts = line.split(None, 5)
            if len(parts) < 6:
                continue
            schedule, command = ' '.join(parts[:5]), parts[5]
        description, log_path = _cron_job_info(command)
        if log_path == SEE_ABOVE:
            status = {'last_run': None, 'status': 'see_above', 'message': 'Covered above (Security audit)'}
        elif log_path == SEE_BACKUPS_PAGE:
            status = {'last_run': None, 'status': 'see_backups', 'message': 'Run history is on the Backups page'}
        else:
            status = (log_path and _last_job_status(log_path)) or \
                {'last_run': None, 'status': 'unknown', 'message': 'No log entries found'}
        jobs.append({
            'type': 'Crontab',
            'link': None,
            'schedule': schedule,
            'schedule_human': _cron_schedule_human(schedule),
            'command': command,
            'description': description,
            **status,
        })
    return jobs



# systemd's single-unit time spans as `systemctl show` prints them, e.g. "6h",
# "1min", "1d 12h" -- shown as-is, just with the property name translated.
TIMER_MONOTONIC_LABELS = {
    'OnBootUSec': 'after boot',
    'OnStartupUSec': 'after boot',
    'OnActiveUSec': 'after timer start',
    'OnUnitActiveUSec': 'since last run',
    'OnUnitInactiveUSec': 'since last finish',
}
DOW_NAMES = {'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'}


def _calendar_human(spec):
    """Best-effort plain-English rendering of one systemd OnCalendar=
    expression in the normalized form `systemctl show` prints
    ("[DOW ]Y-M-D H:M:S"). Covers the daily/weekly/monthly/every-N-minutes
    shapes this box's timers use; anything else falls back to the raw spec."""
    parts = spec.split()
    dow = parts[0] if len(parts) == 3 and parts[0].split(',')[0][:3] in DOW_NAMES else None
    if dow:
        parts = parts[1:]
    if len(parts) != 2:
        return spec
    date, time = parts
    hms = time.split(':')
    if len(hms) != 3:
        return spec
    hour, minute = hms[0], hms[1]
    if hour == '*' and '/' in minute:
        return f'Every {minute.split("/")[1]} minutes'
    if hour == '*' and all(m.isdigit() for m in minute.split(',')):
        when = 'hourly at ' + ', '.join(f':{int(m):02d}' for m in minute.split(','))
    elif minute.isdigit() and all(h.isdigit() for h in hour.split(',')):
        when = 'at ' + ', '.join(f'{int(h):02d}:{int(minute):02d}' for h in hour.split(','))
    else:
        return spec
    if date == '*-*-*':
        prefix = f'Weekly ({dow})' if dow else ('Daily' if not when.startswith('hourly') else '')
    elif date.endswith('-01') and date.count('*') == 2:
        prefix = 'Monthly'
    else:
        return spec
    text = f'{prefix} {when}'.strip()
    return text[0].upper() + text[1:]


def _systemctl_show(units, props, user=False):
    """`systemctl show` for several units in one call, parsed into a dict per
    unit keyed by Id."""
    cmd = ['systemctl'] + (['--user'] if user else []) + ['show', '-p', ','.join(['Id'] + props), '--'] + units
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return {}
    result = {}
    for block in out.strip().split('\n\n'):
        d = dict(line.split('=', 1) for line in block.splitlines() if '=' in line)
        if 'Id' in d:
            result[d['Id']] = d
    return result


def get_systemd_timers():
    """Every systemd timer on the box (system and dave's user ones) as rows
    for the same table as get_cron_jobs(), since scheduled work lives in both
    places -- e.g. apt-daily-upgrade.timer, the unattended upgrades whose
    service restarts took the box offline on 2026-10-23, never showed up in
    crontab. Status comes from the activated service's last Result; a run
    skipped by an ExecCondition/Condition (e.g. upgrade-guard.sh refusing
    while a backup is active) shows as a warning rather than a failure."""
    jobs = []
    for user in (False, True):
        cmd = ['systemctl'] + (['--user'] if user else []) + ['list-timers', '--all', '--no-pager', '-o', 'json']
        try:
            timers = json.loads(subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout or '[]')
        except (OSError, subprocess.SubprocessError, ValueError):
            continue
        if not timers:
            continue
        timer_props = _systemctl_show([t['unit'] for t in timers],
                                      ['TimersCalendar', 'TimersMonotonic', 'RandomizedDelayUSec'], user)
        svc_props = _systemctl_show([t['activates'] for t in timers],
                                    ['Description', 'Result', 'ConditionResult'], user)
        for t in timers:
            tp = timer_props.get(t['unit'], {})
            sp = svc_props.get(t['activates'], {})
            raw, human = [], []
            for m in re.finditer(r'\{ OnCalendar=(.*?) ;', tp.get('TimersCalendar', '')):
                raw.append(m.group(1))
                human.append(_calendar_human(m.group(1)))
            for m in re.finditer(r'\{ (On\w+USec)=(.*?) ;', tp.get('TimersMonotonic', '')):
                raw.append(f'{m.group(1)}={m.group(2)}')
                label = TIMER_MONOTONIC_LABELS.get(m.group(1), m.group(1))
                human.append(f'Every {m.group(2)} {label}' if m.group(1).startswith('OnUnit') else f'{m.group(2)} {label}')
            delay = tp.get('RandomizedDelayUSec', '0')
            schedule_human = '; '.join(human) or '—'
            if delay not in ('0', ''):
                schedule_human += f' (+ up to {delay} random)'
            last_run = datetime.fromtimestamp(t['last'] / 1e6).isoformat() if t.get('last') else None
            result = sp.get('Result', '')
            if not last_run:
                status, message = 'unknown', 'Not yet run'
            elif sp.get('ConditionResult') == 'no' or result in ('exec-condition', 'condition'):
                # Neutral, not a warning: several stock timers (fstrim,
                # e2scrub, xfs_scrub) skip by design on every run.
                status, message = 'skipped', 'Skipped (a start condition was not met)'
            elif result == 'success':
                status, message = 'ok', 'Succeeded'
            else:
                status, message = 'fail', f'Result: {result or "unknown"}'
            jobs.append({
                'type': 'systemd timer (user)' if user else 'systemd timer',
                'link': None,
                'schedule': ' ; '.join(raw),
                'schedule_human': schedule_human,
                'command': f"{t['unit']} -> {t['activates']}",
                'description': sp.get('Description') or t['unit'],
                'last_run': last_run,
                'status': status,
                'message': message,
            })
    # Some units share a Description (sysstat-collect/-summary are both
    # "system activity accounting tool"); tell those apart by unit name.
    counts = {}
    for j in jobs:
        counts[j['description']] = counts.get(j['description'], 0) + 1
    for j in jobs:
        if counts[j['description']] > 1:
            j['description'] += f" ({j['command'].split(' -> ')[0]})"
    return sorted(jobs, key=lambda j: j['description'].lower())

CC_ROUTINES_PATH = os.path.join(os.path.dirname(__file__), 'cc_routines.json')


def get_cc_routines():
    """Scheduled cloud agent routines (claude.ai/code/routines) -- these run
    on Anthropic's infrastructure, not as entries in this server's crontab,
    so they can't be discovered live the way get_cron_jobs() discovers local
    ones. Instead this reads a snapshot file that gets refreshed by hand
    (via a Claude Code session with routines access) whenever a routine is
    added, changed, or run -- deliberately not a live API call from here,
    since that would mean putting a claude.ai auth credential in this
    always-on, internet-facing app."""
    try:
        with open(CC_ROUTINES_PATH) as f:
            routines = json.load(f)
    except (OSError, json.JSONDecodeError):
        return []
    jobs = []
    for r in routines:
        if not r.get('enabled', True):
            continue
        if r.get('last_run_status') == 'ROUTINE_RUN_STATUS_SUCCEEDED':
            status, message = 'ok', 'Succeeded'
        elif r.get('last_run_status') and 'FAIL' in r['last_run_status']:
            status, message = 'fail', 'Failed'
        else:
            status, message = 'unknown', 'Not yet run'
        jobs.append({
            'type': 'Cloud',
            'link': r.get('routine_url'),
            'schedule': r.get('cron_expression', ''),
            'schedule_human': r.get('schedule_human', ''),
            'command': r.get('routine_url', ''),
            'description': r.get('description', r.get('name', '')),
            'last_run': r.get('last_run_at'),
            'status': status,
            'message': message,
        })
    return jobs


# ── Always-on processes ──────────────────────────────────────────────────────────
# Dave's own long-running services, as opposed to base-OS daemons (ssh, cron,
# NetworkManager, dbus, ...) that systemd also reports as running. This is a
# whitelist rather than a filter over the full unit list on purpose -- the
# base-OS set changes with every Ubuntu/snap update, but this list only
# changes when Dave actually adds or removes one of his own services.
PROCESS_INFO = [
    # systemd unit,                       human name,                      link (live URL) or None
    ('apache2.service',                   'Apache (web server)',           None),
    ('mysql.service',                     'MySQL (database)',              None),
    ('cloudflared.service',               'Cloudflare Tunnel',             None),
    ('jellyfin.service',                  'Jellyfin Media Server',         'https://jellyfin.bowsy.co.uk'),
    ('media-resize.service',              'Media Resize',                  'https://media-resize.bowsy.co.uk'),
    ('notify-printer-viewer.service',     'Notify Printer (viewer)',       'https://notify-printer-viewer.bowsy.co.uk'),
    ('notify-printer-pappl.service',      'Notify Printer (IPP server)',   'https://notify-printer.bowsy.co.uk'),
    ('notify-printer-internal.service',   'Notify Printer (internal API)', None),
    ('daves-server-dashboard.service',    'Server Dashboard (this app)',   'https://daves-server-dashboard.bowsy.co.uk'),
    ('nordvpnd.service',                  'NordVPN client',                None),
]


def _systemd_active_since(unit):
    """ISO timestamp of when this unit entered its current active state, or
    None if it isn't running / systemctl can't be read. Goes via `date -d`
    because ActiveEnterTimestamp's rendered form (e.g. 'Tue 2026-10-13
    00:49:37 BST') isn't reliably parseable by strptime's %Z across
    timezones, but `date` already understands systemd's own format."""
    try:
        raw = subprocess.run(
            ['systemctl', 'show', '-p', 'ActiveEnterTimestamp', '--value', unit],
            capture_output=True, text=True, timeout=5
        ).stdout.strip()
        if not raw:
            return None
        epoch = subprocess.run(
            ['date', '-d', raw, '+%s'], capture_output=True, text=True, timeout=5
        ).stdout.strip()
        return datetime.fromtimestamp(int(epoch)).isoformat()
    except (OSError, subprocess.SubprocessError, ValueError):
        return None


def get_running_processes():
    """Live status of Dave's own always-on services -- see PROCESS_INFO."""
    processes = []
    for unit, name, link in PROCESS_INFO:
        try:
            state = subprocess.run(
                ['systemctl', 'is-active', unit],
                capture_output=True, text=True, timeout=5
            ).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            state = 'unknown'
        running = state == 'active'
        processes.append({
            'name': name,
            'link': link,
            'running': running,
            'since': _systemd_active_since(unit) if running else None,
        })
    return processes


# ── Projects board ──────────────────────────────────────────────────────────────

PROJECTS_ALLOWED_TAGS = {
    'p', 'br', 'div', 'span', 'b', 'strong', 'i', 'em', 'u', 's', 'strike',
    'ul', 'ol', 'li', 'a', 'blockquote', 'code', 'pre',
}
PROJECTS_VOID_TAGS = {'br'}
PROJECTS_LINK_SCHEME_RE = re.compile(r'^(https?:|mailto:)', re.I)


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
        if self._drop_depth or tag not in PROJECTS_ALLOWED_TAGS:
            return
        if tag == 'a':
            href = dict(attrs).get('href', '')
            if PROJECTS_LINK_SCHEME_RE.match(href):
                safe_href = html_lib.escape(href, quote=True)
                self.out.append(f'<a href="{safe_href}" target="_blank" rel="noopener noreferrer">')
            else:
                self.out.append('<a>')
        else:
            self.out.append(f'<{tag}>')

    def handle_startendtag(self, tag, attrs):
        if tag in PROJECTS_VOID_TAGS and not self._drop_depth:
            self.out.append(f'<{tag}>')

    def handle_endtag(self, tag):
        if tag in ('script', 'style'):
            self._drop_depth = max(0, self._drop_depth - 1)
            return
        if self._drop_depth or tag not in PROJECTS_ALLOWED_TAGS or tag in PROJECTS_VOID_TAGS:
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


def init_projects_db():
    con = sqlite3.connect(PROJECTS_DB_PATH)
    con.executescript("""
        CREATE TABLE IF NOT EXISTS cards (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            title             TEXT NOT NULL,
            list_name         TEXT NOT NULL CHECK(list_name IN ('backlog', 'current')),
            position          INTEGER NOT NULL,
            description_html  TEXT NOT NULL DEFAULT '',
            tag               TEXT,
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
    try:
        # Migration for DBs created before the tag column existed; harmless
        # no-op (caught below) on a fresh DB where CREATE TABLE already added it.
        con.execute('ALTER TABLE cards ADD COLUMN tag TEXT')
    except sqlite3.OperationalError:
        pass
    con.commit()
    con.close()


def _projects_con():
    con = sqlite3.connect(PROJECTS_DB_PATH)
    con.execute('PRAGMA foreign_keys = ON')
    con.row_factory = sqlite3.Row
    return con


def get_projects_board():
    con = _projects_con()
    cards = con.execute('SELECT * FROM cards ORDER BY list_name, position').fetchall()
    todo_rows = con.execute('SELECT * FROM todo_items ORDER BY card_id, position').fetchall()
    con.close()

    todos_by_card = {}
    for t in todo_rows:
        todos_by_card.setdefault(t['card_id'], []).append({
            'id': t['id'], 'text': t['text'], 'checked': bool(t['checked']),
        })

    board = {name: [] for name in PROJECTS_LISTS}
    for c in cards:
        items = todos_by_card.get(c['id'], [])
        board[c['list_name']].append({
            'id':               c['id'],
            'title':            c['title'],
            'description_html': c['description_html'],
            'tag':              c['tag'],
            'todo_items':       items,
            'done_count':       sum(1 for i in items if i['checked']),
            'total_count':      len(items),
        })
    return board


def create_project_card(title, list_name, tag=None):
    now = datetime.now().isoformat(timespec='seconds')
    tag = tag if tag in PROJECT_TAGS else None
    con = _projects_con()
    pos = con.execute(
        'SELECT COALESCE(MAX(position), -1) + 1 p FROM cards WHERE list_name=?', (list_name,)
    ).fetchone()['p']
    cur = con.execute(
        'INSERT INTO cards (title, list_name, position, description_html, tag, created_at, updated_at) '
        'VALUES (?, ?, ?, ?, ?, ?, ?)',
        (title, list_name, pos, '', tag, now, now),
    )
    con.commit()
    new_id = cur.lastrowid
    con.close()
    return new_id


def update_project_card(card_id, title=None, description_html=None, tag=_UNSET):
    fields, values = [], []
    if title is not None:
        fields.append('title = ?')
        values.append(title)
    if description_html is not None:
        fields.append('description_html = ?')
        values.append(sanitize_rich_text(description_html))
    if tag is not _UNSET:
        fields.append('tag = ?')
        values.append(tag if tag in PROJECT_TAGS else None)
    if not fields:
        return
    fields.append('updated_at = ?')
    values.append(datetime.now().isoformat(timespec='seconds'))
    values.append(card_id)
    con = _projects_con()
    con.execute(f'UPDATE cards SET {", ".join(fields)} WHERE id = ?', values)
    con.commit()
    con.close()


def _renumber_list(con, list_name):
    ids = [r['id'] for r in con.execute(
        'SELECT id FROM cards WHERE list_name = ? ORDER BY position', (list_name,)
    ).fetchall()]
    for i, cid in enumerate(ids):
        con.execute('UPDATE cards SET position = ? WHERE id = ?', (i, cid))


def move_project_card(card_id, list_name, before_id=None):
    con = _projects_con()
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


def delete_project_card(card_id):
    con = _projects_con()
    row = con.execute('SELECT list_name FROM cards WHERE id = ?', (card_id,)).fetchone()
    con.execute('DELETE FROM cards WHERE id = ?', (card_id,))
    if row:
        _renumber_list(con, row['list_name'])
    con.commit()
    con.close()


def create_project_todo(card_id, text):
    con = _projects_con()
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


def update_project_todo(todo_id, text=None, checked=None):
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
    con = _projects_con()
    con.execute(f'UPDATE todo_items SET {", ".join(fields)} WHERE id = ?', values)
    con.commit()
    con.close()


def delete_project_todo(todo_id):
    con = _projects_con()
    con.execute('DELETE FROM todo_items WHERE id = ?', (todo_id,))
    con.commit()
    con.close()


def move_project_todo(todo_id, before_id=None):
    """Reorders a to-do item within its own card's list -- unlike cards, to-do
    items never move between parents via drag-and-drop, so this only ever
    touches one card_id's rows."""
    con = _projects_con()
    row = con.execute('SELECT card_id FROM todo_items WHERE id = ?', (todo_id,)).fetchone()
    if row is None:
        con.close()
        return
    card_id = row['card_id']
    ids = [r['id'] for r in con.execute(
        'SELECT id FROM todo_items WHERE card_id = ? AND id != ? ORDER BY position',
        (card_id, todo_id),
    ).fetchall()]
    idx = ids.index(before_id) if before_id in ids else len(ids)
    ids.insert(idx, todo_id)
    for i, tid in enumerate(ids):
        con.execute('UPDATE todo_items SET position = ? WHERE id = ?', (i, tid))
    con.commit()
    con.close()


init_projects_db()


def build_dashboard():
    return {
        'bluesky_followers': get_bluesky_followers(),
        'site_traffic': get_site_traffic(),
    }


def build_system():
    return {
        'security': get_security_findings(),
        'cron_jobs': get_cron_jobs() + get_systemd_timers() + get_cc_routines(),
        'processes': get_running_processes(),
    }


# ── Backup browser ────────────────────────────────────────────────────────────
#
# Read-only view of any step-1 backup item (backup.yml) as it was after any
# kept night's run, from HD1. Reuses server-scripts' own history helpers so
# this can't drift from how backup.py writes history and restore.py reads it
# (see BACKUP-HISTORY-PLAN.md there): a night's manifest says which files
# existed; each one's version from that night is either still in the mirror
# or in changes/<first later night that replaced or deleted it>/.

SERVER_SCRIPTS_DIR = '/home/dave/projects/server-scripts'
BACKUP_MANAGED_ROOT = '/mnt/portable1/managed/'
BACKUP_KEEP_NIGHTS = 7
# Items that are credentials rather than data: one web login away from every
# key on the server is too close. restore.py still reaches them.
BACKUP_HIDDEN_DESTS = {
    '/mnt/portable1/managed/config/secrets/',
    '/mnt/portable1/managed/config/ssh-backup/',
    '/mnt/portable1/managed/config/cloudflared/',
    '/mnt/portable1/managed/config/whatsapp-bot-auth/',
}
BACKUP_SEARCH_LIMIT = 500

import sys as _sys
if SERVER_SCRIPTS_DIR not in _sys.path:
    _sys.path.insert(0, SERVER_SCRIPTS_DIR)
import backup as _bk  # noqa: E402  (server-scripts' backup.py)

_manifest_cache = {}


def human_size(n):
    if n is None or n < 0:
        return '—'
    for unit in ('B', 'KB', 'MB', 'GB'):
        if n < 1024 or unit == 'GB':
            return f'{n:.0f} {unit}' if unit == 'B' else f'{n:.1f} {unit}'
        n /= 1024


def backup_items():
    """[(slug, action)] for every browsable step-1 item, in backup.yml order."""
    import yaml
    with open(os.path.join(SERVER_SCRIPTS_DIR, 'backup.yml')) as f:
        actions = yaml.safe_load(f).get('actions', [])
    items = []
    for a in actions:
        if (a.get('enabled') and a.get('history_dir') and a['type'] in ('rsync', 'rclone')
                and a['destination'].startswith(BACKUP_MANAGED_ROOT)
                and a['destination'] not in BACKUP_HIDDEN_DESTS):
            items.append((_bk.manifest_path(a, 'x').rsplit('/', 1)[1][:-len('.tsv.gz')], a))
    return items


def backup_item_label(name):
    """'Rclone Google Drive (Annie)' -> 'Google Drive: Annie', 'Rsync ~/scratch
    to portable HD #1' -> '~/scratch': the job names describe the copy step,
    the page only needs to say what was copied."""
    m = re.fullmatch(r'Rclone Google Drive \((.+)\)', name)
    if m:
        return f'Google Drive: {m.group(1)}'
    name = re.sub(r'^(Backup|Rsync|Copy) ', '', name)
    name = re.sub(r' to portable HD #1$', '', name)
    first = name.split(' ', 1)[0]
    # Capitalise 'alobear', but leave deliberate casing like 'qBittorrent'
    if first.islower():
        name = name[:1].upper() + name[1:]
    return name


def backup_item(slug):
    return next((a for s, a in backup_items() if s == slug), None)


def backup_nights(action):
    """Nights (newest first) that have a manifest for this item, i.e. can be
    browsed, limited to the kept window."""
    nights = _bk.list_nights('local', _bk.history_root(action))
    have = [n for n in nights if os.path.exists(_bk.manifest_path(action, n))]
    return list(reversed(have))[:BACKUP_KEEP_NIGHTS]


def _night_manifest(action, night):
    key = (action['name'], night)
    if key not in _manifest_cache:
        if len(_manifest_cache) > 20:
            _manifest_cache.clear()
        _manifest_cache[key] = _bk.read_manifest(action, night)
    return _manifest_cache[key]


def _clean_rel(rel):
    """Normalise a user-supplied relative path; None if it tries to escape."""
    rel = (rel or '').strip('/')
    parts = [p for p in rel.split('/') if p not in ('', '.')]
    if any(p == '..' for p in parts):
        return None
    return '/'.join(parts)


def backup_listing(action, night, rel):
    """(folders, files) directly inside rel as of night ('now' for the live
    mirror). folders: [name]; files: [(name, size)]. None if rel isn't a
    folder that existed then."""
    if night == 'now':
        base = os.path.join(action['destination'], rel)
        if not os.path.isdir(base):
            # An item added to backup.yml has no folder until its first run
            return ([], []) if not rel else None
        folders, files = [], []
        for e in os.scandir(base):
            if e.is_dir(follow_symlinks=False):
                folders.append(e.name)
            elif e.is_file(follow_symlinks=False):
                files.append((e.name, e.stat(follow_symlinks=False).st_size))
        return sorted(folders, key=str.lower), sorted(files, key=lambda f: f[0].lower())
    manifest = _night_manifest(action, night)
    if manifest is None:
        return None
    prefix = rel + '/' if rel else ''
    folders, files = set(), []
    for path, size in manifest.items():
        if not path.startswith(prefix):
            continue
        rest = path[len(prefix):]
        if '/' in rest:
            folders.add(rest.split('/', 1)[0])
        else:
            files.append((rest, size))
    if rel and not folders and not files:
        return None
    return sorted(folders, key=str.lower), sorted(files, key=lambda f: f[0].lower())


def backup_search(action, night, query):
    """[(relpath, size)] whose file name contains query (case-insensitive)."""
    q = query.lower()
    if night == 'now':
        rows = ((p, s) for p, s, _ in _bk.list_files('local', action['destination']))
    else:
        rows = (_night_manifest(action, night) or {}).items()
    hits = [(p, s) for p, s in rows if q in os.path.basename(p).lower()]
    return sorted(hits, key=lambda h: h[0].lower())[:BACKUP_SEARCH_LIMIT]


def backup_locate(action, night, rel):
    """Absolute path on HD1 holding rel as it was after night, or None."""
    candidates = []
    if night != 'now':
        manifest = _night_manifest(action, night)
        if manifest is None or rel not in manifest:
            return None
        tmpl = _bk.history_template(action)
        for n in _bk.list_nights('local', _bk.history_root(action)):
            if n > night:
                candidates.append((os.path.join(tmpl.replace('{date}', n), rel), tmpl.replace('{date}', n)))
    candidates.append((os.path.join(action['destination'], rel), action['destination']))
    for path, root in candidates:
        # realpath on both sides: a symlink in a backup must not lead out of it
        if os.path.isfile(path) and os.path.realpath(path).startswith(os.path.realpath(root) + os.sep):
            return path
    return None


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


@app.route('/system')
def system_page():
    if not authed():
        return redirect(url_for('login'))
    return render_template('system.html', **build_system(), timeago=timeago)


@app.route('/api/system-data')
def api_system_data():
    if not authed():
        return jsonify({'error': 'forbidden'}), 403
    return jsonify(build_system())


@app.route('/projects')
def projects_page():
    if not authed():
        return redirect(url_for('login'))
    return render_template('projects.html', board=get_projects_board())


@app.route('/api/projects/cards', methods=['POST'])
def api_projects_create_card():
    if not authed():
        return jsonify({'error': 'forbidden'}), 403
    data = request.get_json(force=True, silent=True) or {}
    title = (data.get('title') or '').strip()
    list_name = data.get('list_name')
    if not title or list_name not in PROJECTS_LISTS:
        return jsonify({'error': 'invalid'}), 400
    card_id = create_project_card(title, list_name, tag=data.get('tag'))
    return jsonify({'id': card_id})


@app.route('/api/projects/cards/<int:card_id>', methods=['PATCH'])
def api_projects_update_card(card_id):
    if not authed():
        return jsonify({'error': 'forbidden'}), 403
    data = request.get_json(force=True, silent=True) or {}
    # 'tag' is treated as _UNSET unless the key was actually sent, so a client
    # can explicitly clear it (tag: null/'') without every other PATCH wiping it.
    kwargs = {'title': data.get('title'), 'description_html': data.get('description_html')}
    if 'tag' in data:
        kwargs['tag'] = data['tag']
    update_project_card(card_id, **kwargs)
    return jsonify({'ok': True})


@app.route('/api/projects/cards/<int:card_id>', methods=['DELETE'])
def api_projects_delete_card(card_id):
    if not authed():
        return jsonify({'error': 'forbidden'}), 403
    delete_project_card(card_id)
    return jsonify({'ok': True})


@app.route('/api/projects/cards/<int:card_id>/move', methods=['POST'])
def api_projects_move_card(card_id):
    if not authed():
        return jsonify({'error': 'forbidden'}), 403
    data = request.get_json(force=True, silent=True) or {}
    list_name = data.get('list_name')
    if list_name not in PROJECTS_LISTS:
        return jsonify({'error': 'invalid'}), 400
    move_project_card(card_id, list_name, before_id=data.get('before_id'))
    return jsonify({'ok': True})


@app.route('/api/projects/cards/<int:card_id>/todos', methods=['POST'])
def api_projects_create_todo(card_id):
    if not authed():
        return jsonify({'error': 'forbidden'}), 403
    data = request.get_json(force=True, silent=True) or {}
    text = (data.get('text') or '').strip()
    if not text:
        return jsonify({'error': 'invalid'}), 400
    todo_id = create_project_todo(card_id, text)
    return jsonify({'id': todo_id})


@app.route('/api/projects/todos/<int:todo_id>', methods=['PATCH'])
def api_projects_update_todo(todo_id):
    if not authed():
        return jsonify({'error': 'forbidden'}), 403
    data = request.get_json(force=True, silent=True) or {}
    update_project_todo(todo_id, text=data.get('text'), checked=data.get('checked'))
    return jsonify({'ok': True})


@app.route('/api/projects/todos/<int:todo_id>', methods=['DELETE'])
def api_projects_delete_todo(todo_id):
    if not authed():
        return jsonify({'error': 'forbidden'}), 403
    delete_project_todo(todo_id)
    return jsonify({'ok': True})


@app.route('/api/projects/todos/<int:todo_id>/move', methods=['POST'])
def api_projects_move_todo(todo_id):
    if not authed():
        return jsonify({'error': 'forbidden'}), 403
    data = request.get_json(force=True, silent=True) or {}
    move_project_todo(todo_id, before_id=data.get('before_id'))
    return jsonify({'ok': True})


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


def _backup_night_options(action):
    """[(value, label)] for the 'when' drop-down: the live backup, then each
    earlier kept night."""
    today = datetime.now().date()
    opts = [('now', 'Now (latest backup)')]
    for n in backup_nights(action):
        d = datetime.strptime(n, '%Y-%m-%d').date()
        ago = (today - d).days
        if ago <= 0:
            continue
        opts.append((n, f'{ago} day{"s" if ago != 1 else ""} ago ({d.strftime("%a %-d %b")})'))
    return opts


@app.route('/backups')
def backups_page():
    if not authed():
        return redirect(url_for('login'))
    items = [{'slug': s, 'name': backup_item_label(a['name']), 'nights': _backup_night_options(a)}
             for s, a in backup_items()]
    items.sort(key=lambda it: it['name'].lower())
    return render_template('backups.html', items=items, backups=get_backup_runs())


@app.route('/backups/browse/<slug>/<night>/', defaults={'rel': ''})
@app.route('/backups/browse/<slug>/<night>/<path:rel>')
def backups_browse(slug, night, rel):
    if not authed():
        return redirect(url_for('login'))
    action = backup_item(slug)
    rel = _clean_rel(rel)
    if action is None or rel is None or (night != 'now' and night not in backup_nights(action)):
        return render_template('backup_browse.html', not_found=True, slug=slug, night=night), 404
    label = dict(_backup_night_options(action)).get(night, night)
    query = (request.args.get('q') or '').strip()
    ctx = dict(not_found=False, slug=slug, night=night, night_label=label, item_name=action['name'],
               rel=rel, crumbs=rel.split('/') if rel else [], query=query, human_size=human_size)
    ctx['item_name'] = backup_item_label(action['name'])
    if query:
        return render_template('backup_browse.html', hits=backup_search(action, night, query), **ctx)
    listing = backup_listing(action, night, rel)
    if listing is None:
        return render_template('backup_browse.html', **dict(ctx, not_found=True)), 404
    folders, files = listing
    return render_template('backup_browse.html', folders=folders, files=files, **ctx)


@app.route('/backups/file/<slug>/<night>/<path:rel>')
def backups_file(slug, night, rel):
    if not authed():
        return redirect(url_for('login'))
    action = backup_item(slug)
    rel = _clean_rel(rel)
    if action is None or not rel or (night != 'now' and night not in backup_nights(action)):
        return 'Not found', 404
    path = backup_locate(action, night, rel)
    if path is None:
        # Possible for a file the Drive leg's --track-renames moved; HD1's own
        # history has no renames, so this should be rare here
        return 'That version of the file is no longer in the backup.', 404
    return send_file(path, as_attachment=True, download_name=os.path.basename(rel))


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    next_url = _safe_next(request.args.get('next'))
    if authed():
        return redirect(next_url or url_for('index'))
    if request.method == 'POST':
        if hmac.compare_digest(request.form.get('password', ''), PASSWORD):
            session.clear()
            session['authed'] = True
            session.permanent = True
            return redirect(next_url or url_for('index'))
        error = 'Wrong password.'
    return render_template('login.html', error=error)


@app.route('/logout')
def logout():
    session.clear()
    resp = redirect(url_for('login'))
    resp.delete_cookie(SSO_COOKIE, domain=SSO_DOMAIN)
    return resp


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5002, debug=False)
