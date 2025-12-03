from flask import Flask, request, render_template_string, session, redirect, url_for, abort
import sqlite3
import os
import hashlib
import secrets

app = Flask(__name__)
app.secret_key = os.urandom(24)

app.config['SESSION_COOKIE_HTTPONLY'] = True  #cookie no es accesible desde JS
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  #reduce riesgo de CSRF básico
app.config['SESSION_COOKIE_SECURE'] = True

def get_db_connection():
    conn = sqlite3.connect('example.db')
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# CSRF
def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)
    return session['csrf_token']

def validate_csrf():
    form_token = request.form.get('csrf_token')
    session_token = session.get('csrf_token')
    if not form_token or not session_token or form_token != session_token:
        abort(400, description="Token CSRF inválido")

@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf_token())

#rutas
@app.route('/')
def index():
    return render_template_string('''
        <!doctype html>
        <html lang="en">
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
            <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" rel="stylesheet">
            <title>Welcome</title>
        </head>
        <body>
            <div class="container">
                <h1 class="mt-5">Welcome to the Example Application!</h1>
                <p class="lead">This is the home page. Please <a href="{{ url_for('login') }}">login</a>.</p>
            </div>
        </body>
        </html>
    ''')

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None

    if request.method == 'POST':
        validate_csrf()

        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if not username or not password:
            error = "Username y password son obligatorios."
        else:
            conn = get_db_connection()

            #consulta parametrizada y contraseña con hash
            query = "SELECT * FROM users WHERE username = ? AND password = ?"
            hashed_password = hash_password(password)
            user = conn.execute(query, (username, hashed_password)).fetchone()
            conn.close()

            if user:
                session['user_id'] = user['id']
                session['role'] = user['role']
                return redirect(url_for('dashboard'))
            else:
                error = "Credenciales inválidas."

    return render_template_string('''
        <!doctype html>
        <html lang="en">
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
            <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" rel="stylesheet">
            <title>Login</title>
        </head>
        <body>
            <div class="container">
                <h1 class="mt-5">Login</h1>
                {% if error %}
                    <div class="alert alert-danger" role="alert">{{ error }}</div>
                {% endif %}
                <form method="post">
                    <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
                    <div class="form-group">
                        <label for="username">Username</label>
                        <input type="text" class="form-control" id="username" name="username">
                    </div>
                    <div class="form-group">
                        <label for="password">Password</label>
                        <input type="password" class="form-control" id="password" name="password">
                    </div>
                    <button type="submit" class="btn btn-primary">Login</button>
                </form>
            </div>
        </body>
        </html>
    ''', error=error)

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = get_db_connection()
    comments = conn.execute(
        "SELECT comment FROM comments WHERE user_id = ?", (user_id,)
    ).fetchall()
    conn.close()

    #escapar comentarios para evitar XSS almacenado
    return render_template_string('''
        <!doctype html>
        <html lang="en">
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
            <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" rel="stylesheet">
            <title>Dashboard</title>
        </head>
        <body>
            <div class="container">
                <h1 class="mt-5">Welcome, user {{ user_id }}!</h1>
                <form action="{{ url_for('submit_comment') }}" method="post">
                    <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
                    <div class="form-group">
                        <label for="comment">Comment</label>
                        <textarea class="form-control" id="comment" name="comment" rows="3"></textarea>
                    </div>
                    <button type="submit" class="btn btn-primary">Submit Comment</button>
                </form>
                <h2 class="mt-5">Your Comments</h2>
                <ul class="list-group">
                    {% for comment in comments %}
                        <li class="list-group-item">{{ comment['comment'] | e }}</li>
                    {% endfor %}
                </ul>
                <a href="{{ url_for('logout') }}" class="btn btn-link mt-3">Logout</a>
            </div>
        </body>
        </html>
    ''', user_id=user_id, comments=comments)