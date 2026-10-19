"""PayTask starter app. Demo payments by default; Daraja sandbox/production optional."""
import base64
import os
import secrets
import sqlite3
from datetime import datetime
from functools import wraps
from zoneinfo import ZoneInfo

import requests
from flask import Flask, abort, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'local-demo-only-change-before-deployment')
DB = os.path.join(os.path.dirname(__file__), 'paytask.db')
CATEGORIES = {
    'Technology': [('Mobile Internet', 'How often do you use mobile internet?'), ('Smartphones', 'What matters most when choosing a phone?'), ('Online Safety', 'How do you protect your accounts?')],
    'Education': [('Learning Habits', 'How do you prefer to learn new skills?'), ('Online Courses', 'What online course would you take?'), ('Study Tools', 'What helps you concentrate?')],
    'Health & Lifestyle': [('Exercise', 'How often do you exercise?'), ('Daily Routine', 'What is one habit you want to improve?'), ('Nutrition', 'What influences your food choices?')],
    'Shopping': [('Buying Habits', 'What products do you buy most often?'), ('Online Shopping', 'What makes you trust an online store?'), ('Price Comparison', 'How do you compare prices?')],
    'Entertainment': [('Music', 'What kind of music do you enjoy?'), ('Streaming', 'How often do you stream videos?'), ('Games', 'What types of games do you play?')],
    'Finance': [('Budgeting', 'How do you plan your monthly expenses?'), ('Mobile Money', 'What do you mainly use mobile money for?'), ('Saving', 'What helps you save money?')],
}
SURVEYS = {}
i = 1
for category, entries in CATEGORIES.items():
    for index, (title, question) in enumerate(entries):
        SURVEYS[i] = {'id': i, 'category': category, 'title': title, 'question': question, 'free': index == 0}
        i += 1

DEMO = os.environ.get('MPESA_MODE', 'demo') == 'demo'
MPESA_BASE = 'https://sandbox.safaricom.co.ke' if os.environ.get('MPESA_MODE') == 'sandbox' else 'https://api.safaricom.co.ke'

def db():
    conn = sqlite3.connect(DB, timeout=20)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys=ON')
    return conn

def init_db():
    with db() as c:
        c.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, password TEXT NOT NULL, bonus_credit INTEGER NOT NULL DEFAULT 50, earnings INTEGER NOT NULL DEFAULT 0)')
        # Older starter databases are migrated safely.
        columns = {r['name'] for r in c.execute('PRAGMA table_info(users)')}
        if 'earnings' not in columns:
            c.execute('ALTER TABLE users ADD COLUMN earnings INTEGER NOT NULL DEFAULT 0')
        c.execute('CREATE TABLE IF NOT EXISTS unlocked (user_id INTEGER NOT NULL, survey_id INTEGER NOT NULL, PRIMARY KEY(user_id,survey_id))')
        c.execute('CREATE TABLE IF NOT EXISTS responses (user_id INTEGER NOT NULL, survey_id INTEGER NOT NULL, answer TEXT NOT NULL, PRIMARY KEY(user_id,survey_id))')
        c.execute('CREATE TABLE IF NOT EXISTS payments (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, survey_id INTEGER NOT NULL, phone TEXT NOT NULL, checkout_id TEXT UNIQUE, status TEXT NOT NULL DEFAULT "pending", created_at TEXT DEFAULT CURRENT_TIMESTAMP)')
        c.execute('CREATE TABLE IF NOT EXISTS withdrawals (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, phone TEXT NOT NULL, amount INTEGER NOT NULL, status TEXT NOT NULL DEFAULT "pending", created_at TEXT DEFAULT CURRENT_TIMESTAMP)')
        c.execute('CREATE TABLE IF NOT EXISTS survey_catalog (id INTEGER PRIMARY KEY, category TEXT NOT NULL, title TEXT NOT NULL, question TEXT NOT NULL, is_free INTEGER NOT NULL DEFAULT 0, active INTEGER NOT NULL DEFAULT 1)')
        c.execute('CREATE TABLE IF NOT EXISTS admin_audit (id INTEGER PRIMARY KEY, action TEXT NOT NULL, details TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP)')
        c.execute('CREATE TABLE IF NOT EXISTS withdrawal_refs (withdrawal_id INTEGER PRIMARY KEY, mpesa_reference TEXT NOT NULL UNIQUE)')
        if not c.execute('SELECT 1 FROM survey_catalog LIMIT 1').fetchone():
            for item in SURVEYS.values():
                c.execute('INSERT INTO survey_catalog(id,category,title,question,is_free) VALUES(?,?,?,?,?)', (item['id'],item['category'],item['title'],item['question'],int(item['free'])))

def get_survey(survey_id):
    with db() as c:
        r = c.execute('SELECT * FROM survey_catalog WHERE id=? AND active=1', (survey_id,)).fetchone()
    return dict(id=r['id'], category=r['category'], title=r['title'], question=r['question'], free=bool(r['is_free'])) if r else None

def admin_required(f):
    @wraps(f)
    def inner(*args, **kwargs):
        if not session.get('admin'):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return inner

def login_required(f):
    @wraps(f)
    def inner(*a, **kw):
        if 'uid' not in session:
            return redirect(url_for('login'))
        return f(*a, **kw)
    return inner

@app.before_request
def csrf_protection():
    if 'csrf' not in session:
        session['csrf'] = secrets.token_urlsafe(32)
    if request.method == 'POST' and request.endpoint != 'mpesa_callback':
        if not secrets.compare_digest(request.form.get('csrf', ''), session['csrf']):
            abort(400, 'Invalid form token')

@app.context_processor
def helpers():
    return {'csrf': lambda: session.get('csrf', ''), 'demo': DEMO, 'is_admin': session.get('admin', False)}

def normalize_phone(phone):
    digits = ''.join(c for c in phone if c.isdigit())
    if digits.startswith('0') and len(digits) == 10:
        digits = '254' + digits[1:]
    elif digits.startswith('7') or digits.startswith('1'):
        if len(digits) == 9:
            digits = '254' + digits
    if len(digits) != 12 or not digits.startswith('254') or digits[3] not in '17':
        raise ValueError('Enter a valid Kenyan M-Pesa number, e.g. 0712345678')
    return digits

def mpesa_token():
    key, secret = os.environ['MPESA_CONSUMER_KEY'], os.environ['MPESA_CONSUMER_SECRET']
    r = requests.get(MPESA_BASE + '/oauth/v1/generate?grant_type=client_credentials', auth=(key, secret), timeout=15)
    r.raise_for_status()
    return r.json()['access_token']

def stk_push(phone, amount):
    shortcode = os.environ['MPESA_SHORTCODE']
    passkey = os.environ['MPESA_PASSKEY']
    timestamp = datetime.now(ZoneInfo('Africa/Nairobi')).strftime('%Y%m%d%H%M%S')
    password = base64.b64encode((shortcode + passkey + timestamp).encode()).decode()
    body = {'BusinessShortCode': shortcode, 'Password': password, 'Timestamp': timestamp,
            'TransactionType': 'CustomerPayBillOnline', 'Amount': amount,
            'PartyA': phone, 'PartyB': shortcode, 'PhoneNumber': phone,
            'CallBackURL': os.environ['MPESA_CALLBACK_URL'],
            'AccountReference': 'PayTask', 'TransactionDesc': 'Survey unlock'}
    r = requests.post(MPESA_BASE + '/mpesa/stkpush/v1/processrequest',
                      headers={'Authorization': 'Bearer ' + mpesa_token()}, json=body, timeout=20)
    r.raise_for_status()
    return r.json()

def stk_query(checkout_id):
    shortcode = os.environ['MPESA_SHORTCODE']
    timestamp = datetime.now(ZoneInfo('Africa/Nairobi')).strftime('%Y%m%d%H%M%S')
    password = base64.b64encode((shortcode + os.environ['MPESA_PASSKEY'] + timestamp).encode()).decode()
    r = requests.post(MPESA_BASE + '/mpesa/stkpushquery/v1/query',
        headers={'Authorization': 'Bearer ' + mpesa_token()},
        json={'BusinessShortCode': shortcode, 'Password': password, 'Timestamp': timestamp, 'CheckoutRequestID': checkout_id}, timeout=20)
    r.raise_for_status()
    return r.json()

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        if not name or '@' not in email or len(password) < 8:
            flash('Provide your name, a valid email and a password of at least 8 characters.')
        else:
            try:
                with db() as c:
                    cur = c.execute('INSERT INTO users(name,email,password) VALUES(?,?,?)', (name,email,generate_password_hash(password)))
                    session['uid'] = cur.lastrowid
                return redirect(url_for('dashboard'))
            except sqlite3.IntegrityError:
                flash('Email is already registered.')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        with db() as c:
            user = c.execute('SELECT * FROM users WHERE email=?', (request.form.get('email','').strip().lower(),)).fetchone()
        if user and check_password_hash(user['password'], request.form.get('password','')):
            session.clear()
            session['uid'] = user['id']
            return redirect(url_for('dashboard'))
        flash('Invalid email or password.')
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    with db() as c:
        user = c.execute('SELECT * FROM users WHERE id=?', (session['uid'],)).fetchone()
        unlocked = {r['survey_id'] for r in c.execute('SELECT survey_id FROM unlocked WHERE user_id=?', (session['uid'],))}
        completed = {r['survey_id'] for r in c.execute('SELECT survey_id FROM responses WHERE user_id=?', (session['uid'],))}
        withdrawals = c.execute('SELECT * FROM withdrawals WHERE user_id=? ORDER BY id DESC LIMIT 5', (session['uid'],)).fetchall()
        payments = c.execute('SELECT * FROM payments WHERE user_id=? ORDER BY id DESC LIMIT 5', (session['uid'],)).fetchall()
        rows = c.execute('SELECT * FROM survey_catalog WHERE active=1 ORDER BY category,id').fetchall()
        live_surveys = {r['id']: dict(id=r['id'], category=r['category'], title=r['title'], question=r['question'], free=bool(r['is_free'])) for r in rows}
        live_categories = {r['category']: [] for r in rows}
    return render_template('dashboard.html', user=user, categories=live_categories, surveys=live_surveys, unlocked=unlocked, completed=completed, withdrawals=withdrawals, payments=payments)

@app.route('/unlock/<int:survey_id>', methods=['POST'])
@login_required
def unlock(survey_id):
    item = get_survey(survey_id)
    if not item:
        abort(404)
    if item['free']:
        flash('This survey is free; no payment is needed.')
        return redirect(url_for('survey', survey_id=survey_id))
    try:
        phone = normalize_phone(request.form.get('phone', ''))
    except ValueError as e:
        flash(str(e))
        return redirect(url_for('dashboard'))
    with db() as c:
        if c.execute('SELECT 1 FROM unlocked WHERE user_id=? AND survey_id=?', (session['uid'],survey_id)).fetchone():
            flash('Already unlocked.')
            return redirect(url_for('dashboard'))
        if DEMO:
            # Demo never charges or unlocks paid surveys: no fake payment success.
            flash('Demo mode: no M-Pesa payment was made. Configure Daraja to unlock paid surveys.')
            return redirect(url_for('dashboard'))
    try:
        result = stk_push(phone, 30)
        if result.get('ResponseCode') != '0' or not result.get('CheckoutRequestID'):
            flash('M-Pesa did not accept the payment request. Please try again.')
        else:
            with db() as c:
                c.execute('INSERT INTO payments(user_id,survey_id,phone,checkout_id) VALUES(?,?,?,?)', (session['uid'], survey_id, phone, result['CheckoutRequestID']))
            flash('Check your phone for the M-Pesa prompt. After paying, select Verify payment on your dashboard.')
    except (requests.RequestException, KeyError, ValueError) as e:
        app.logger.warning('STK request failed: %s', e)
        flash('Unable to start M-Pesa payment. Check configuration and try again.')
    return redirect(url_for('dashboard'))

@app.route('/payment/<int:payment_id>/verify', methods=['POST'])
@login_required
def verify_payment(payment_id):
    with db() as c:
        payment = c.execute('SELECT * FROM payments WHERE id=? AND user_id=?', (payment_id,session['uid'])).fetchone()
    if not payment:
        abort(404)
    if payment['status'] != 'pending':
        flash('Payment status: ' + payment['status'])
        return redirect(url_for('dashboard'))
    try:
        result = stk_query(payment['checkout_id'])
        code = str(result.get('ResultCode', ''))
        if code == '0':
            with db() as c:
                c.execute('BEGIN IMMEDIATE')
                updated = c.execute("UPDATE payments SET status='paid' WHERE id=? AND status='pending'", (payment_id,))
                if updated.rowcount:
                    c.execute('INSERT OR IGNORE INTO unlocked(user_id,survey_id) VALUES(?,?)', (session['uid'],payment['survey_id']))
            flash('M-Pesa payment verified. Survey unlocked!')
        elif code and code not in ('1037',):
            with db() as c:
                c.execute("UPDATE payments SET status='failed' WHERE id=? AND status='pending'", (payment_id,))
            flash('Payment was not completed. You may try again.')
        else:
            flash('Payment is still processing. Check again shortly.')
    except (requests.RequestException, KeyError, ValueError) as e:
        app.logger.warning('Payment verification failed: %s', e)
        flash('Could not verify payment yet. Try again later.')
    return redirect(url_for('dashboard'))

@app.route('/mpesa/callback', methods=['POST'])
def mpesa_callback():
    # Unauthenticated callbacks must NEVER grant access or credit balances.
    # Use the authenticated Daraja status query above to verify payment.
    return {'ResultCode': 0, 'ResultDesc': 'Received'}, 200

@app.route('/survey/<int:survey_id>', methods=['GET','POST'])
@login_required
def survey(survey_id):
    item = get_survey(survey_id)
    if not item:
        abort(404)
    with db() as c:
        unlocked = item['free'] or bool(c.execute('SELECT 1 FROM unlocked WHERE user_id=? AND survey_id=?', (session['uid'],survey_id)).fetchone())
        if not unlocked:
            flash('Pay KSh 30 via M-Pesa to unlock this survey.')
            return redirect(url_for('dashboard'))
        if c.execute('SELECT 1 FROM responses WHERE user_id=? AND survey_id=?', (session['uid'],survey_id)).fetchone():
            flash('You have already completed this survey.')
            return redirect(url_for('dashboard'))
        if request.method == 'POST':
            answer = request.form.get('answer','').strip()
            if not answer or len(answer) > 2000:
                flash('Enter an answer of up to 2,000 characters.')
            else:
                c.execute('BEGIN IMMEDIATE')
                inserted = c.execute('INSERT OR IGNORE INTO responses(user_id,survey_id,answer) VALUES(?,?,?)', (session['uid'],survey_id,answer))
                if inserted.rowcount:
                    c.execute('UPDATE users SET earnings=earnings+100 WHERE id=?', (session['uid'],))
                    flash('Survey completed! KSh 100 demo earnings credited.')
                return redirect(url_for('dashboard'))
    return render_template('survey.html', item=item)

@app.route('/withdraw', methods=['POST'])
@login_required
def withdraw():
    try:
        phone = normalize_phone(request.form.get('phone',''))
        amount = int(request.form.get('amount','0'))
    except (ValueError, TypeError):
        flash('Enter a valid M-Pesa number and amount.')
        return redirect(url_for('dashboard'))
    if amount < 2500:
        flash('Minimum withdrawal is KSh 2,500.')
        return redirect(url_for('dashboard'))
    with db() as c:
        c.execute('BEGIN IMMEDIATE')
        updated = c.execute('UPDATE users SET earnings=earnings-? WHERE id=? AND earnings>=?', (amount,session['uid'],amount))
        if not updated.rowcount:
            flash('Insufficient earned balance.')
        else:
            c.execute('INSERT INTO withdrawals(user_id,phone,amount) VALUES(?,?,?)', (session['uid'],phone,amount))
            flash('Withdrawal request submitted and balance reserved. No M-Pesa payout has been sent. An administrator must review and process it.')
    return redirect(url_for('dashboard'))

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return redirect(url_for('home'))


@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = os.environ.get('PAYTASK_ADMIN_USER', '')
        password = os.environ.get('PAYTASK_ADMIN_PASSWORD', '')
        if username and password and secrets.compare_digest(request.form.get('username',''), username) and secrets.compare_digest(request.form.get('password',''), password):
            session.clear()
            session['admin'] = True
            return redirect(url_for('admin_dashboard'))
        flash('Invalid admin credentials or admin account not configured.')
    return render_template('admin_login.html')

@app.route('/admin')
@admin_required
def admin_dashboard():
    with db() as c:
        users = c.execute('SELECT id,name,email,bonus_credit,earnings FROM users ORDER BY id DESC LIMIT 100').fetchall()
        surveys = c.execute('SELECT * FROM survey_catalog ORDER BY category,id').fetchall()
        payments = c.execute('SELECT payments.*,users.email FROM payments JOIN users ON users.id=payments.user_id ORDER BY payments.id DESC LIMIT 100').fetchall()
        withdrawals = c.execute('SELECT withdrawals.*,users.email,withdrawal_refs.mpesa_reference FROM withdrawals JOIN users ON users.id=withdrawals.user_id LEFT JOIN withdrawal_refs ON withdrawal_refs.withdrawal_id=withdrawals.id ORDER BY withdrawals.id DESC LIMIT 100').fetchall()
        counts = dict(users=c.execute('SELECT COUNT(*) FROM users').fetchone()[0], completed=c.execute('SELECT COUNT(*) FROM responses').fetchone()[0], pending=c.execute("SELECT COUNT(*) FROM withdrawals WHERE status='pending'").fetchone()[0])
    return render_template('admin.html', users=users, surveys=surveys, payments=payments, withdrawals=withdrawals, counts=counts)

@app.route('/admin/surveys/add', methods=['POST'])
@admin_required
def admin_add_survey():
    category = request.form.get('category','').strip()[:80]
    title = request.form.get('title','').strip()[:120]
    question = request.form.get('question','').strip()[:1000]
    free = request.form.get('free') == 'on'
    if not all((category,title,question)):
        flash('Category, title and question are required.')
    else:
        with db() as c:
            c.execute('BEGIN IMMEDIATE')
            existing = c.execute('SELECT 1 FROM survey_catalog WHERE category=? AND is_free=1 AND active=1', (category,)).fetchone()
            if free and existing:
                flash('This category already has a free survey.')
            else:
                c.execute('INSERT INTO survey_catalog(category,title,question,is_free) VALUES(?,?,?,?)', (category,title,question,int(free)))
                c.execute('INSERT INTO admin_audit(action,details) VALUES(?,?)', ('add_survey', title))
                flash('Survey added.')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/surveys/<int:survey_id>/toggle', methods=['POST'])
@admin_required
def admin_toggle_survey(survey_id):
    with db() as c:
        c.execute('BEGIN IMMEDIATE')
        r = c.execute('SELECT * FROM survey_catalog WHERE id=?', (survey_id,)).fetchone()
        if not r:
            abort(404)
        if not r['active'] and r['is_free'] and c.execute('SELECT 1 FROM survey_catalog WHERE category=? AND is_free=1 AND active=1', (r['category'],)).fetchone():
            flash('Deactivate the other free survey in this category first.')
        else:
            c.execute('UPDATE survey_catalog SET active=? WHERE id=?', (1-r['active'],survey_id))
            c.execute('INSERT INTO admin_audit(action,details) VALUES(?,?)', ('toggle_survey',str(survey_id)))
            flash('Survey status changed.')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/withdrawals/<int:withdrawal_id>/review', methods=['POST'])
@admin_required
def admin_review_withdrawal(withdrawal_id):
    decision = request.form.get('decision')
    reference = request.form.get('reference','').strip()[:100]
    if decision not in ('reject','mark_paid') or (decision == 'mark_paid' and not reference):
        abort(400, 'Valid decision and M-Pesa reference required.')
    with db() as c:
        c.execute('BEGIN IMMEDIATE')
        w = c.execute('SELECT * FROM withdrawals WHERE id=? AND status="pending"', (withdrawal_id,)).fetchone()
        if not w:
            flash('Request already reviewed or not found.')
        elif decision == 'reject':
            c.execute('UPDATE withdrawals SET status="rejected" WHERE id=?', (withdrawal_id,))
            c.execute('UPDATE users SET earnings=earnings+? WHERE id=?', (w['amount'],w['user_id']))
            c.execute('INSERT INTO admin_audit(action,details) VALUES(?,?)', ('reject_withdrawal',str(withdrawal_id)))
            flash('Withdrawal rejected and reserved demo balance restored.')
        else:
            try:
                c.execute('INSERT INTO withdrawal_refs(withdrawal_id,mpesa_reference) VALUES(?,?)', (withdrawal_id,reference))
                c.execute('UPDATE withdrawals SET status="paid_manual" WHERE id=?', (withdrawal_id,))
                c.execute('INSERT INTO admin_audit(action,details) VALUES(?,?)', ('manual_payout_record',str(withdrawal_id)+' ref '+reference))
                flash('Recorded as manually paid. This action does NOT send M-Pesa funds.')
            except sqlite3.IntegrityError:
                flash('This M-Pesa reference is already recorded.')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/logout', methods=['POST'])
@admin_required
def admin_logout():
    session.clear()
    return redirect(url_for('home'))

init_db()
if __name__ == '__main__':
    app.run(debug=os.environ.get('FLASK_DEBUG') == '1')
