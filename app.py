import os
import sqlite3
import json
import secrets
from datetime import timedelta
from functools import wraps
from flask import Flask, request, jsonify, session, render_template, g
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.permanent_session_lifetime = timedelta(days=30)
DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cube_trainer.db')


def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DATABASE)
    db.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS training_state (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER UNIQUE NOT NULL,
            state_json TEXT NOT NULL DEFAULT '{}',
            updated_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    ''')
    db.commit()
    db.close()


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': '请先登录'}), 401
        return f(*args, **kwargs)
    return decorated


def get_user_state():
    db = get_db()
    row = db.execute(
        'SELECT state_json FROM training_state WHERE user_id = ?',
        (session['user_id'],)
    ).fetchone()
    if not row:
        return {}
    try:
        return json.loads(row['state_json'])
    except (json.JSONDecodeError, TypeError):
        return {}


def save_user_state(state_obj):
    db = get_db()
    state_json = json.dumps(state_obj, ensure_ascii=False)
    db.execute('''
        INSERT INTO training_state (user_id, state_json, updated_at)
        VALUES (?, ?, datetime('now'))
        ON CONFLICT(user_id) DO UPDATE SET
            state_json = excluded.state_json,
            updated_at = excluded.updated_at
    ''', (session['user_id'], state_json))
    db.commit()


# ---- Routes ----

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json(silent=True) or {}
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''

    if not username or not password:
        return jsonify({'error': '用户名和密码不能为空'}), 400
    if len(username) < 2 or len(username) > 20:
        return jsonify({'error': '用户名需2-20个字符'}), 400
    if len(password) < 3:
        return jsonify({'error': '密码至少3个字符'}), 400

    db = get_db()
    if db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone():
        return jsonify({'error': '用户名已存在，请换一个'}), 409

    pw_hash = generate_password_hash(password)
    db.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, pw_hash))
    user = db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
    db.execute('INSERT INTO training_state (user_id, state_json) VALUES (?, ?)',
               (user['id'], '{"mastered":{"oll21":true,"oll22":true,"pll_cw":true},"completedDays":{},"solveTimes":[],"startDate":""}'))
    db.commit()

    session['user_id'] = user['id']
    session['username'] = username
    session.permanent = True

    return jsonify({'ok': True, 'username': username})


@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''

    if not username or not password:
        return jsonify({'error': '请输入用户名和密码'}), 400

    db = get_db()
    user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

    if not user or not check_password_hash(user['password_hash'], password):
        return jsonify({'error': '用户名或密码错误'}), 401

    session['user_id'] = user['id']
    session['username'] = username
    session.permanent = True

    return jsonify({'ok': True, 'username': username})


@app.route('/api/auth/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'ok': True})


@app.route('/api/auth/me')
def me():
    if 'user_id' not in session:
        return jsonify({'logged_in': False})
    return jsonify({
        'logged_in': True,
        'username': session.get('username')
    })


@app.route('/api/state', methods=['GET'])
@login_required
def get_state():
    return jsonify({'state': get_user_state()})


@app.route('/api/state', methods=['PUT'])
@login_required
def put_state():
    data = request.get_json(silent=True) or {}
    save_user_state(data.get('state', {}))
    return jsonify({'ok': True})


if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port, debug=False)
