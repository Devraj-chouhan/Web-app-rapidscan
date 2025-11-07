import os
import re
import uuid
import queue
import signal
import sqlite3
import threading
from datetime import datetime
from subprocess import Popen, PIPE
from flask import Flask, Response, jsonify, render_template, request, redirect, url_for, session, send_file, abort
from werkzeug.security import generate_password_hash, check_password_hash
from xhtml2pdf import pisa

# Paths
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
RAPIDSCAN_PATH = os.path.join(BASE_DIR, 'rapidscan.py')

app = Flask(__name__, template_folder='templates', static_folder='static')
app.secret_key = os.environ.get('RAPIDSCAN_WEB_SECRET', 'dev-secret-change-me')

# Scan registry: scan_id -> { proc, queue, progress, total, done }
scans = {}
# Stored reports metadata in-memory for UI; persisted files remain created by RapidScan itself
reports = []  # list of {id, target, started_at, finished_at, vul_report_path, debug_log_path}
lock = threading.Lock()

ansi_escape = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
logo_suppress_until = re.compile(r"\[ Checking Available Security Scanning Tools Phase")

def db_path():
    return os.path.join(os.path.dirname(__file__), 'app.db')

def init_db():
    con = sqlite3.connect(db_path())
    cur = con.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    con.commit()
    con.close()

def login_required(view):
    from functools import wraps
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get('user_id'):
            if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
                return jsonify({'error': 'auth required'}), 401
            return redirect(url_for('login'))
        return view(*args, **kwargs)
    return wrapped

def _enqueue_output(proc, q, scan_meta):
    for line in iter(proc.stdout.readline, ''):
        clean = ansi_escape.sub('', line.rstrip('\n'))
        if not scan_meta.get('past_logo'):
            # Suppress initial ASCII logo/help. Start showing once the precheck header appears.
            if logo_suppress_until.search(clean):
                scan_meta['past_logo'] = True
            else:
                continue
        # Progress parsing
        # Example: "Deploying 3/81 | ..."
        m = re.search(r"Deploying\s+(\d+)\/(\d+)", clean)
        if m:
            try:
                cur = int(m.group(1))
                total = int(m.group(2))
                with lock:
                    scan_meta['progress'] = cur
                    scan_meta['total'] = total
            except Exception:
                pass
        q.put(clean)
    proc.stdout.close()
    proc.wait()
    with lock:
        scan_meta['done'] = True
    # On completion, try to locate generated reports and broadcast
    try:
        target = scan_meta.get('target')
        finished_at = datetime.utcnow().isoformat()
        vul_path = None
        dbg_path = None
        # Find latest rs.vul.* and rs.dbg.* for target
        for fname in sorted(os.listdir(BASE_DIR)):
            if target and fname.startswith(f"rs.vul.{target}."):
                vul_path = os.path.join(BASE_DIR, fname)
            if target and fname.startswith(f"rs.dbg.{target}."):
                dbg_path = os.path.join(BASE_DIR, fname)
        if vul_path:
            rep = {
                'id': uuid.uuid4().hex,
                'target': target,
                'started_at': scan_meta.get('started_at'),
                'finished_at': finished_at,
                'vul_report_path': vul_path,
                'debug_log_path': dbg_path,
            }
            with lock:
                reports.append(rep)
            # enqueue a notification line that UI global SSE can pick via /events
            try:
                global_events.put({'type': 'report', 'data': {'id': rep['id'], 'target': target}})
            except Exception:
                pass
    except Exception:
        pass

@app.route('/')
def index():
    if not session.get('user_id'):
        return redirect(url_for('login'))
    return redirect(url_for('dashboard'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = (request.form.get('email') or '').strip().lower()
        password = request.form.get('password') or ''
        con = sqlite3.connect(db_path())
        cur = con.cursor()
        cur.execute('SELECT id, password_hash FROM users WHERE email = ?', (email,))
        row = cur.fetchone()
        con.close()
        if not row or not check_password_hash(row[1], password):
            return render_template('login.html', error='Invalid credentials')
        session['user_id'] = row[0]
        session['email'] = email
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = (request.form.get('email') or '').strip().lower()
        password = request.form.get('password') or ''
        if not email or not password:
            return render_template('signup.html', error='Email and password are required')
        con = sqlite3.connect(db_path())
        cur = con.cursor()
        try:
            cur.execute('INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, ?)', (
                email, generate_password_hash(password), datetime.utcnow().isoformat()
            ))
            con.commit()
        except sqlite3.IntegrityError:
            con.close()
            return render_template('signup.html', error='Email already exists')
        con.close()
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.post('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/reports')
@login_required
def reports_page():
    with lock:
        rep_copy = list(reports)
    return render_template('reports.html', reports=rep_copy)

@app.route('/account')
@login_required
def account():
    return render_template('account.html', email=session.get('email'))

@app.post('/start')
@login_required
def start_scan():
    data = request.get_json(force=True, silent=True) or {}
    target = (data.get('target') or '').strip()
    skip_raw = (data.get('skip') or '').strip()
    if not target:
        return jsonify({ 'error': 'target is required' }), 400

    scan_id = uuid.uuid4().hex

    # Build command: python3 -u rapidscan.py -n [--skip ...] <target>
    cmd = ['python3', '-u', RAPIDSCAN_PATH, '-n']
    # Optional skip list: comma/space separated
    if skip_raw:
        for tok in re.split(r"[,\s]+", skip_raw):
            tok = tok.strip()
            if tok:
                cmd.extend(['--skip', tok])
    cmd.append(target)

    # Environment: avoid clearing server terminal affecting service
    env = os.environ.copy()

    proc = Popen(cmd, stdout=PIPE, stderr=PIPE, text=True, bufsize=1, universal_newlines=True, env=env)
    q = queue.Queue()
    meta = { 'proc': proc, 'queue': q, 'progress': 0, 'total': 0, 'done': False, 'past_logo': False, 'target': target, 'started_at': datetime.utcnow().isoformat() }
    with lock:
        scans[scan_id] = meta

    t = threading.Thread(target=_enqueue_output, args=(proc, q, meta), daemon=True)
    t.start()

    # Also read stderr and forward into same queue
    def _enqueue_err():
        for line in iter(proc.stderr.readline, ''):
            clean = ansi_escape.sub('', line.rstrip('\n'))
            q.put(clean)
        proc.stderr.close()
    threading.Thread(target=_enqueue_err, daemon=True).start()

    return jsonify({ 'scan_id': scan_id })

@app.get('/stream/<scan_id>')
@login_required
def stream(scan_id):
    with lock:
        meta = scans.get(scan_id)
    if not meta:
        return jsonify({ 'error': 'Invalid scan id' }), 404

    def event_stream():
        q = meta['queue']
        while True:
            try:
                line = q.get(timeout=0.5)
            except queue.Empty:
                pass
            else:
                yield f"data: {line}\n\n"
            with lock:
                done = meta['done']
                prog = meta['progress']
                total = meta['total']
            # Periodic progress events
            yield f"event: progress\ndata: {{\"progress\": {prog}, \"total\": {total}}}\n\n"
            if done and q.empty():
                yield "event: complete\ndata: done\n\n"
                break
    return Response(event_stream(), mimetype='text/event-stream')

@app.post('/stop/<scan_id>')
@login_required
def stop(scan_id):
    with lock:
        meta = scans.get(scan_id)
    if not meta:
        return jsonify({ 'error': 'Invalid scan id' }), 404
    proc = meta['proc']
    try:
        proc.send_signal(signal.SIGINT)
    except Exception:
        try:
            proc.terminate()
        except Exception:
            pass
    return jsonify({ 'status': 'stopping' })

@app.get('/status/<scan_id>')
@login_required
def status(scan_id):
    with lock:
        meta = scans.get(scan_id)
    if not meta:
        return jsonify({ 'error': 'Invalid scan id' }), 404
    return jsonify({ 'progress': meta['progress'], 'total': meta['total'], 'done': meta['done'] })

# Global events (reports completion)
global_events = queue.Queue()

@app.get('/events')
@login_required
def events():
    def gen():
        while True:
            try:
                evt = global_events.get(timeout=1)
            except queue.Empty:
                # keep-alive
                yield 'event: ping\ndata: {}\n\n'
                continue
            yield f"event: {evt.get('type','message')}\ndata: {jsonify(evt.get('data',{})).get_data(as_text=True)}\n\n"
    return Response(gen(), mimetype='text/event-stream')

@app.get('/reports/<rep_id>/download.pdf')
@login_required
def download_report_pdf(rep_id):
    with lock:
        rep = next((r for r in reports if r['id'] == rep_id), None)
    if not rep or not rep.get('vul_report_path'):
        abort(404)
    # Read text report and render into HTML template
    try:
        with open(rep['vul_report_path'], 'r', encoding='utf-8', errors='ignore') as f:
            vul_text = f.read()
    except Exception:
        vul_text = '(Report not found)'
    html = render_template('report_template.html', report=rep, vul_text=vul_text)
    # Generate PDF in-memory
    from io import BytesIO
    pdf_io = BytesIO()
    pisa.CreatePDF(src=html, dest=pdf_io)
    pdf_io.seek(0)
    return send_file(pdf_io, mimetype='application/pdf', as_attachment=True, download_name=f"rapidscan_{rep['target']}.pdf")

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', '8000'))
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)
