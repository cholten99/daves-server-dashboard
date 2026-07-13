import gzip
import glob
import http.cookiejar
import json
import os
import re
import sqlite3
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime, timedelta

from guessit import guessit as _guessit
from flask import Flask, request, redirect, url_for, render_template, make_response, jsonify

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dsd-static-key-2026')

PASSWORD    = os.environ.get('DASHBOARD_PASSWORD', 'watchingdaves2026')
COOKIE_NAME = 'dsd_auth'
COOKIE_VAL  = 'granted'

FINDINGS_LOG   = '/home/dave/server-scripts/audit-findings.log'
FINDINGS_ROTATED_GLOB = '/home/dave/server-scripts/audit-findings.log.*.gz'
BACKUP_LOGS_DIR = '/home/dave/server-scripts/logs'
MR_DB_PATH      = '/var/www/media-resize/state.db'
MR_WORKERS_PATH = '/var/www/media-resize/workers.json'

BOWSY_FEED_LOG  = '/home/dave/logs/bowsy-feed.log'

# Search hits (Search Console clicks) + page hits (Cloudflare pageViews) per
# site, pulled daily by site-traffic/pull_daily.py into this DB. Site list
# here must match SITES in that script -- it owns the data, this just reads it.
SITE_TRAFFIC_DB = '/var/www/site-traffic/site_traffic.db'
SITE_TRAFFIC_SITES = [
    ('bowsy.co.uk',         'Bowsy'),
    ('transformgov.org.uk', 'TransformGov'),
    ('ukpolyamory.org',     'UK Polyamory'),
]

# Each project's to-do list lives in its own repo/directory as a hand-maintained
# TODO.md (no auto-sync script -- these are edited manually). Order here is
# display order on the dashboard.
PROJECT_TODOS = [
    ('Backup',                            '/home/dave/server-scripts/TODO.md'),
    ('Media Resize',                      '/var/www/media-resize/TODO.md'),
    ('Site Traffic',                      '/var/www/site-traffic/TODO.md'),
    ('Podcast Host (Libsyn replacement)', '/var/www/podcast-host/TODO.md'),
    ('Google Workspace Migration',        '/home/dave/google-workspace-migration/TODO.md'),
]

# media-resize already computes per-worker encode progress/ETA itself (SSH-probes
# each worker, caches for 30s) -- rather than duplicating that, log into its own
# /api/data as a regular authenticated client and read the numbers back out.
MR_BASE_URL  = 'http://127.0.0.1:5001'
MR_PASSWORD  = os.environ.get('MEDIA_RESIZE_PASSWORD', 'makethemsmaller')
_mr_cookie_jar = http.cookiejar.CookieJar()
_mr_opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(_mr_cookie_jar))

SECURITY_DAYS = 6
BACKUP_RUNS_LIMIT = 10
HD1_PREFIX = '/mnt/portable1'

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
    name = f'{title} S{season:02d}E{episode:02d}.mkv' if season and episode else f'{title}.mkv'
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
    this dashboard has no worker state of its own, it just proxies the click."""
    for attempt in (1, 2):
        try:
            req = urllib.request.Request(f'{MR_BASE_URL}/toggle/{name}', data=b'', method='POST')
            _mr_opener.open(req, timeout=5).read()
            return True
        except (urllib.error.URLError, OSError):
            if attempt == 1:
                try:
                    _mr_login()
                    continue
                except (urllib.error.URLError, OSError):
                    return False
            return False
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

    hd1_actions = []
    for a in d.get('actions', []):
        dest = a.get('destination', '') or ''
        if not dest.startswith(HD1_PREFIX):
            continue
        files = _parse_rsync_files(a.get('stdout', ''))
        hd1_actions.append({
            'name':        a.get('name', ''),
            'destination': dest,
            'status':      a.get('status', ''),
            'file_count':  len(files),
            'files':       files,
        })

    return {
        'run_id':     d.get('run_id', safe_id),
        'started_at': d.get('started_at', ''),
        'dry_run':    bool(d.get('dry_run')),
        'actions':    hd1_actions,
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


JOB_LOG_LINE_RE = re.compile(r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?:,\d+)? (\w+): (.*)$')


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
    return con.execute(
        "SELECT date, search_clicks, page_views FROM daily_stats "
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
            'page_daily':    _latest_non_null(rows, 'page_views'),
            'page_weekly':   sum(r['page_views'] or 0 for r in rows),
        })
    con.close()
    return results


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
        sites.append({
            'name':          display,
            'days':          [datetime.strptime(r['date'], '%Y-%m-%d').strftime('%a %d %b') for r in rows],
            'search_series': [r['search_clicks'] or 0 for r in rows],
            'page_series':   [r['page_views'] or 0 for r in rows],
            'search_daily':  _latest_non_null(rows, 'search_clicks'),
            'search_weekly': sum(r['search_clicks'] or 0 for r in rows),
            'page_daily':    _latest_non_null(rows, 'page_views'),
            'page_weekly':   sum(r['page_views'] or 0 for r in rows),
        })
    con.close()
    return sites


def get_other_jobs():
    jobs = []
    for name, schedule, log_path in [
        ('Bowsy latest-post fetch',    'hourly',      BOWSY_FEED_LOG),
    ]:
        status = _last_job_status(log_path) or {'last_run': None, 'status': 'unknown', 'message': 'No log entries found'}
        jobs.append({'name': name, 'schedule': schedule, **status})
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
        projects.append({
            'name':       name,
            'slug':       re.sub(r'\W+', '-', name.lower()).strip('-'),
            'todo_items': items,
            'done':       sum(1 for i in items if i['state'] == 'x'),
            'total':      len(items),
        })
    return projects


def build_dashboard():
    return {
        'project_todos': get_project_todos(),
        'site_traffic': get_site_traffic(),
        'security': get_security_findings(),
        'backups':  get_backup_runs(),
        'media_resize': get_media_resize_status(),
        'other_jobs': get_other_jobs(),
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
