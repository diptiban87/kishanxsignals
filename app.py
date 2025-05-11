import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, send_file, g, flash, jsonify, abort
from datetime import datetime, timedelta
import random
import csv
import io
import requests
from werkzeug.security import generate_password_hash, check_password_hash
import math
from scipy.stats import norm
import time
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
import pandas as pd
import numpy as np
import yfinance as yf
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import hashlib
import ipaddress
from flask_talisman import Talisman
from flask_sslify import SSLify
from security_config import (
    SECURITY_SETTINGS, API_SECURITY, FILE_SECURITY,
    encrypt_data, decrypt_data, validate_password
)
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from io import BytesIO

app = Flask(__name__)
app.secret_key = os.urandom(32)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(seconds=SECURITY_SETTINGS['PERMANENT_SESSION_LIFETIME'])

# Initialize security extensions
if SECURITY_SETTINGS['SSL_ENABLED']:
    sslify = SSLify(app)
    Talisman(app,
        force_https=True,
        strict_transport_security=SECURITY_SETTINGS['HSTS_ENABLED'],
        session_cookie_secure=SECURITY_SETTINGS['SESSION_COOKIE_SECURE'],
        content_security_policy={
            'default-src': "'self'",
            'script-src': "'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net",
            'style-src': "'self' 'unsafe-inline' https://fonts.googleapis.com",
            'font-src': "'self' https://fonts.gstatic.com",
            'img-src': "'self' data: https:",
            'connect-src': "'self'",
            'frame-src': "'self'",
            'object-src': "'none'",
            'media-src': "'self'",
            'form-action': "'self'"
        },
        feature_policy={
            'geolocation': "'none'",
            'camera': "'none'",
            'microphone': "'none'",
            'payment': "'none'",
            'usb': "'none'"
        }
    )

# Set session cookie settings
app.config.update(
    SESSION_COOKIE_HTTPONLY=SECURITY_SETTINGS['SESSION_COOKIE_HTTPONLY'],
    SESSION_COOKIE_SAMESITE=SECURITY_SETTINGS['SESSION_COOKIE_SAMESITE']
)

# Initialize rate limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=[API_SECURITY['RATE_LIMIT'], API_SECURITY['RATE_LIMIT_PER_IP']]
)

DATABASE = os.path.join(app.root_path, 'kishanx.db')

# Security configuration
ALLOWED_IPS = set()  # Add your allowed IPs here
MAX_DOWNLOADS_PER_DAY = 10
DOWNLOAD_COOLDOWN = 3600  # 1 hour in seconds

# --- Security helpers ---
def is_admin(user_id):
    """Check if user has admin privileges"""
    db = get_db()
    user = db.execute('SELECT is_admin FROM users WHERE id = ?', (user_id,)).fetchone()
    return user and user['is_admin'] == 1

def get_client_ip():
    """Get client IP address"""
    if request.headers.getlist("X-Forwarded-For"):
        return request.headers.getlist("X-Forwarded-For")[0]
    return request.remote_addr

def is_ip_allowed(ip):
    """Check if IP is in allowed list"""
    if not ALLOWED_IPS:  # If no IPs specified, allow all
        return True
    try:
        client_ip = ipaddress.ip_address(ip)
        return any(client_ip in ipaddress.ip_network(allowed_ip) for allowed_ip in ALLOWED_IPS)
    except ValueError:
        return False

def generate_file_token(filename, user_id):
    """Generate a secure token for file access"""
    timestamp = int(time.time())
    data = f"{filename}:{user_id}:{timestamp}:{app.secret_key}"
    return hashlib.sha256(data.encode()).hexdigest()

def verify_file_token(token, filename, user_id, max_age=3600):
    """Verify file access token"""
    try:
        timestamp = int(time.time())
        data = f"{filename}:{user_id}:{timestamp}:{app.secret_key}"
        expected_token = hashlib.sha256(data.encode()).hexdigest()
        return token == expected_token and (timestamp - int(time.time())) <= max_age
    except:
        return False

def admin_required(f):
    """Decorator to require admin privileges"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or not is_admin(session['user_id']):
            abort(403)  # Forbidden
        return f(*args, **kwargs)
    return decorated_function

def secure_file_access(f):
    """Decorator to secure file access"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
            
        # Check IP restrictions
        client_ip = get_client_ip()
        if not is_ip_allowed(client_ip):
            abort(403)  # Forbidden
            
        # Check download limits
        db = get_db()
        today = datetime.now().date().isoformat()
        downloads = db.execute(
            'SELECT COUNT(*) FROM file_downloads WHERE user_id = ? AND date = ?',
            (session['user_id'], today)
        ).fetchone()[0]
        
        if downloads >= MAX_DOWNLOADS_PER_DAY:
            flash('Daily download limit reached', 'error')
            return redirect(url_for('dashboard'))
            
        return f(*args, **kwargs)
    return decorated_function

# --- Database helpers ---
def get_db():
    if 'db' not in g:
        try:
            g.db = sqlite3.connect(DATABASE)
            g.db.row_factory = sqlite3.Row
            print("Database connection established")  # Debug log
        except Exception as e:
            print(f"Database connection error: {str(e)}")  # Debug log
            raise
    return g.db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    """Initialize the database with required tables"""
    try:
        conn = get_db()
        print("Initializing database...")  # Debug log
        
        # Create users table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                email TEXT,
                registered_at TEXT NOT NULL,
                is_admin INTEGER DEFAULT 0,
                download_count INTEGER DEFAULT 0,
                last_download TEXT
            )
        ''')
        
        # Create signals table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS signals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                timestamp TEXT NOT NULL,
                pair TEXT NOT NULL,
                direction TEXT NOT NULL,
                broker TEXT,
                price REAL,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Create file_downloads table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS file_downloads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                filename TEXT NOT NULL,
                date TEXT NOT NULL,
                ip_address TEXT,
                token TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Create access_logs table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS access_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        conn.commit()
        print("Database initialized successfully")  # Debug log
        
    except Exception as e:
        print(f"Database initialization error: {str(e)}")  # Debug log
        import traceback
        print(traceback.format_exc())  # Print full stack trace
        raise
    finally:
        if 'conn' in locals():
            conn.close()

with app.app_context():
    init_db()

# --- User helpers ---
def get_user_by_username(username):
    db = get_db()
    return db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

def get_user_by_id(user_id):
    db = get_db()
    return db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()

def create_user(username, password, email=None):
    """Create a new user with encrypted password"""
    try:
        conn = get_db()
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        print(f"Creating user: {username}")  # Debug log
        
        # First check if user exists
        existing_user = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
        if existing_user:
            print(f"User {username} already exists")  # Debug log
            return False
            
        # Create new user
        conn.execute('''
            INSERT INTO users (username, password, email, registered_at, is_admin, download_count) 
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (username, hashed_password, email, datetime.now().isoformat(), 0, 0))
        
        conn.commit()
        print(f"User created successfully: {username}")  # Debug log
        return True
        
    except sqlite3.IntegrityError as e:
        print(f"Database integrity error: {str(e)}")  # Debug log
        return False
    except Exception as e:
        print(f"Error creating user: {str(e)}")  # Debug log
        return False
    finally:
        if 'conn' in locals():
            conn.close()

def update_last_login(user_id):
    """Update user's last login timestamp"""
    try:
        conn = get_db()
        conn.execute('UPDATE users SET last_login = ? WHERE id = ?', 
                    (datetime.now().isoformat(), user_id))
        conn.commit()
    except Exception as e:
        print(f"Error updating last login: {str(e)}")
    finally:
        if 'conn' in locals():
            conn.close()

def verify_user(username, password):
    """Verify user credentials with rate limiting"""
    if 'login_attempts' not in session:
        session['login_attempts'] = 0
        session['last_attempt'] = datetime.now().timestamp()
    
    # Check if user is temporarily blocked
    if session['login_attempts'] >= SECURITY_SETTINGS['MAX_LOGIN_ATTEMPTS']:
        time_since_last = datetime.now().timestamp() - session['last_attempt']
        if time_since_last < SECURITY_SETTINGS['LOGIN_TIMEOUT']:
            return False
    
    try:
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        
        if user and user['password'] == hashlib.sha256(password.encode()).hexdigest():
            session['login_attempts'] = 0
            return user
        else:
            session['login_attempts'] = session.get('login_attempts', 0) + 1
            session['last_attempt'] = datetime.now().timestamp()
            return False
    except Exception as e:
        print(f"Error verifying user: {str(e)}")
        return False

# --- Signal helpers ---
def save_signal(user_id, time, pair, direction):
    db = get_db()
    db.execute('INSERT INTO signals (user_id, time, pair, direction, created_at) VALUES (?, ?, ?, ?, ?)',
               (user_id, time, pair, direction, datetime.now().isoformat()))
    db.commit()

def get_signals_for_user(user_id, limit=20):
    db = get_db()
    rows = db.execute('SELECT * FROM signals WHERE user_id = ? ORDER BY created_at DESC LIMIT ?', (user_id, limit)).fetchall()
    return [dict(row) for row in rows]

def get_signal_stats(user_id):
    db = get_db()
    total = db.execute('SELECT COUNT(*) FROM signals WHERE user_id = ?', (user_id,)).fetchone()[0]
    by_pair = db.execute('SELECT pair, COUNT(*) as count FROM signals WHERE user_id = ? GROUP BY pair', (user_id,)).fetchall()
    by_direction = db.execute('SELECT direction, COUNT(*) as count FROM signals WHERE user_id = ? GROUP BY direction', (user_id,)).fetchall()
    return total, by_pair, by_direction

# --- App logic ---
pairs = ["EURAUD", "USDCHF", "USDBRL", "AUDUSD", "GBPCAD", "EURCAD", "NZDUSD", "USDPKR", "EURUSD", "USDCAD", "AUDCHF", "GBPUSD", "EURGBP"]
brokers = ["Quotex", "Pocket Option", "Binolla", "IQ Option", "Bullex", "Exnova"]
API_KEY = "35BDZ47V6D5T4B8G"

price_cache = {}

# Symbol mapping for Indian markets
symbol_map = {
    # Major Indices
    "NIFTY50": "^NSEI",
    "BANKNIFTY": "^NSEBANK",
    "NSEBANK": "^NSEBANK",
    "NSEIT": "^CNXIT",
    "NSEINFRA": "^CNXINFRA",
    "NSEPHARMA": "^CNXPHARMA",
    "NSEFMCG": "^CNXFMCG",
    "NSEMETAL": "^CNXMETAL",
    "NSEENERGY": "^CNXENERGY",
    "NSEAUTO": "^CNXAUTO",
    # Additional Indices
    "NIFTYMIDCAP": "^NSEI_MIDCAP",
    "NIFTYSMALLCAP": "^NSEI_SMALLCAP",
    "NIFTYNEXT50": "^NSEI_NEXT50",
    "NIFTY100": "^NSEI_100",
    "NIFTY500": "^NSEI_500",
    # Sector Indices
    "NIFTYREALTY": "^NSEI_REALTY",
    "NIFTYPVTBANK": "^NSEI_PVTBANK",
    "NIFTYPSUBANK": "^NSEI_PSUBANK",
    "NIFTYFIN": "^NSEI_FIN",
    "NIFTYMEDIA": "^NSEI_MEDIA",
    # Popular Stocks
    "RELIANCE": "RELIANCE.NS",
    "TCS": "TCS.NS",
    "HDFCBANK": "HDFCBANK.NS",
    "INFY": "INFY.NS",
    "ICICIBANK": "ICICIBANK.NS",
    "HINDUNILVR": "HINDUNILVR.NS",
    "SBIN": "SBIN.NS",
    "BHARTIARTL": "BHARTIARTL.NS",
    "KOTAKBANK": "KOTAKBANK.NS",
    "BAJFINANCE": "BAJFINANCE.NS"
}

broker_payouts = {
    "Quotex": 0.85,
    "Pocket Option": 0.80,
    "Binolla": 0.78,
    "IQ Option": 0.82,
    "Bullex": 0.75,
    "Exnova": 0.77
}

def get_cached_realtime_forex(pair, api_key, cache_duration=60):
    now = time.time()
    if pair in price_cache:
        price, timestamp = price_cache[pair]
        if now - timestamp < cache_duration:
            return price
    price = get_realtime_forex(pair, api_key)
    price_cache[pair] = (price, now)
    return price

def get_indian_market_data(pair):
    """Fetch Indian market data from multiple free sources"""
    try:
        yahoo_symbol = symbol_map.get(pair)
        if not yahoo_symbol:
            print(f"Invalid symbol for real-time data: {pair}")
            return generate_fallback_data(pair)
            
        print(f"Fetching real-time data for {pair} using Yahoo symbol {yahoo_symbol}")
        
        # Try Yahoo Finance first
        try:
            ticker = yf.Ticker(yahoo_symbol)
            info = ticker.info
            
            if not info:
                raise Exception("No data received from Yahoo Finance")
                
            market_data = {
                'price': float(info.get('regularMarketPrice', 0)),
                'change': float(info.get('regularMarketChange', 0)),
                'change_percent': float(info.get('regularMarketChangePercent', 0)),
                'volume': int(info.get('regularMarketVolume', 0)),
                'high': float(info.get('regularMarketDayHigh', 0)),
                'low': float(info.get('regularMarketDayLow', 0)),
                'open': float(info.get('regularMarketOpen', 0)),
                'previous_close': float(info.get('regularMarketPreviousClose', 0)),
                'timestamp': int(time.time()),
                'is_demo': False
            }
            
            # Validate the data
            if market_data['price'] <= 0:
                raise Exception("Invalid price data received")
                
            print(f"Successfully fetched real-time data for {pair}")
            return market_data
            
        except Exception as e:
            print(f"Error fetching Yahoo Finance data for {pair}: {str(e)}")
            
        # Try NSE India as fallback
        try:
            nse_symbol = pair.replace("NIFTY50", "NIFTY 50").replace("BANKNIFTY", "NIFTY BANK")
            url = f"https://www.nseindia.com/api/quote-equity?symbol={nse_symbol}"
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'application/json',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate, br',
                'Connection': 'keep-alive'
            }
            
            response = requests.get(url, headers=headers, timeout=10)
            data = response.json()
            
            if 'priceInfo' not in data:
                raise Exception("Invalid NSE data format")
                
            price_info = data['priceInfo']
            market_data = {
                'price': float(price_info['lastPrice']),
                'change': float(price_info['change']),
                'change_percent': float(price_info['pChange']),
                'volume': int(price_info['totalTradedVolume']),
                'high': float(price_info['intraDayHighLow']['max']),
                'low': float(price_info['intraDayHighLow']['min']),
                'open': float(price_info['open']),
                'previous_close': float(price_info['previousClose']),
                'timestamp': int(time.time()),
                'is_demo': False
            }
            
            print(f"Successfully fetched NSE data for {pair}")
            return market_data
            
        except Exception as e:
            print(f"Error fetching NSE data for {pair}: {str(e)}")
            
        # If both sources fail, generate fallback data
        print(f"Using fallback data for {pair}")
        return generate_fallback_data(pair)
        
    except Exception as e:
        print(f"Unexpected error in get_indian_market_data for {pair}: {str(e)}")
        return generate_fallback_data(pair)

def get_realtime_forex(pair, api_key):
    # Special handling for Indian indices
    if pair in symbol_map:
        return get_indian_market_data(pair)['price']
    
    # Original forex logic for other pairs
    from_symbol = pair[:3]
    to_symbol = pair[3:]
    url = f"https://www.alphavantage.co/query?function=CURRENCY_EXCHANGE_RATE&from_currency={from_symbol}&to_currency={to_symbol}&apikey={api_key}"
    response = requests.get(url)
    data = response.json()
    try:
        rate = data["Realtime Currency Exchange Rate"]["5. Exchange Rate"]
        return float(rate)
    except Exception:
        # Fallback for forex pairs
        return round(random.uniform(1.0, 2.0), 5)

def black_scholes_call_put(S, K, T, r, sigma, option_type="call"):
    d1 = (math.log(S / K) + (r + 0.5 * sigma ** 2) * T) / (sigma * math.sqrt(T))
    d2 = d1 - sigma * math.sqrt(T)
    if option_type == "call":
        price = S * norm.cdf(d1) - K * math.exp(-r * T) * norm.cdf(d2)
    else:
        price = K * math.exp(-r * T) * norm.cdf(-d2) - S * norm.cdf(-d1)
    return price

DEMO_UNLOCK_PASSWORD = 'Indiandemo2021'
DEMO_TIMEOUT_MINUTES = 30

@app.before_request
def demo_lockout():
    allowed_routes = {'login', 'register', 'static', 'lock', 'unlock'}
    if request.endpoint in allowed_routes or request.endpoint is None:
        return
    if 'demo_start_time' not in session:
        session['demo_start_time'] = datetime.now().isoformat()
    start_time = datetime.fromisoformat(session['demo_start_time'])
    if (datetime.now() - start_time).total_seconds() > DEMO_TIMEOUT_MINUTES * 60:
        session['locked'] = True
        if request.endpoint not in {'lock', 'unlock'}:
            return redirect(url_for('lock'))
    else:
        session['locked'] = False

@app.route('/lock', methods=['GET'])
def lock():
    return render_template('lock.html')

@app.route('/unlock', methods=['POST'])
def unlock():
    password = request.form.get('password')
    if password == DEMO_UNLOCK_PASSWORD:
        session['demo_start_time'] = datetime.now().isoformat()
        session['locked'] = False
        return redirect(url_for('dashboard'))
    else:
        flash('Incorrect password. Please try again.', 'error')
        return render_template('lock.html')

@app.route('/get_demo_time')
@limiter.limit("30 per minute")  # Increased rate limit
def get_demo_time():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
        
    demo_timeout = DEMO_TIMEOUT_MINUTES
    start_time = session.get('demo_start_time')
    if not start_time:
        # fallback: reset timer
        session['demo_start_time'] = datetime.now().isoformat()
        start_time = session['demo_start_time']
    start_time = datetime.fromisoformat(start_time)
    elapsed = (datetime.now() - start_time).total_seconds()
    remaining = max(0, int(demo_timeout * 60 - elapsed))
    minutes = remaining // 60
    seconds = remaining % 60
    time_left = f"{minutes:02d}:{seconds:02d}"
    return jsonify({'time_left': time_left})

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def register():
    if request.method == 'POST':
        try:
            username = request.form.get('username')
            password = request.form.get('password')
            email = request.form.get('email', '')  # Make email optional
            
            print(f"Registration attempt - Username: {username}")  # Debug log
            
            if not username or not password:
                print("Missing username or password")  # Debug log
                flash('Username and password are required', 'error')
                return render_template('register.html', error='Username and password are required')
            
            # Check if username already exists
            if get_user_by_username(username):
                print(f"Username {username} already exists")  # Debug log
                flash('Username already exists', 'error')
                return render_template('register.html', error='Username already exists')
            
            # Validate password strength
            is_valid, message = validate_password(password)
            if not is_valid:
                print(f"Password validation failed: {message}")  # Debug log
                requirements = [
                    f"At least {SECURITY_SETTINGS['PASSWORD_MIN_LENGTH']} characters long",
                    "At least one special character (!@#$%^&*()_+-=[]{}|;:,.<>?)" if SECURITY_SETTINGS['REQUIRE_SPECIAL_CHARS'] else None,
                    "At least one number" if SECURITY_SETTINGS['REQUIRE_NUMBERS'] else None,
                    "At least one uppercase letter" if SECURITY_SETTINGS['REQUIRE_UPPERCASE'] else None,
                    "At least one lowercase letter" if SECURITY_SETTINGS['REQUIRE_LOWERCASE'] else None
                ]
                requirements = [req for req in requirements if req is not None]
                flash(message, 'error')
                return render_template('register.html', 
                                     error=message,
                                     password_requirements=requirements)
            
            # Create user
            if create_user(username, password, email):
                print(f"User {username} registered successfully")  # Debug log
                flash('Registration successful. Please log in.', 'success')
                return redirect(url_for('login'))
            else:
                print(f"Failed to create user {username}")  # Debug log
                flash('Failed to create user. Please try again.', 'error')
                return render_template('register.html', error='Failed to create user')
                
        except Exception as e:
            print(f"Registration error: {str(e)}")  # Debug log
            import traceback
            print(traceback.format_exc())  # Print full stack trace
            flash('An error occurred during registration', 'error')
            return render_template('register.html', error='An error occurred during registration')
            
    # For GET requests, show password requirements
    requirements = [
        f"At least {SECURITY_SETTINGS['PASSWORD_MIN_LENGTH']} characters long",
        "At least one special character (!@#$%^&*()_+-=[]{}|;:,.<>?)" if SECURITY_SETTINGS['REQUIRE_SPECIAL_CHARS'] else None,
        "At least one number" if SECURITY_SETTINGS['REQUIRE_NUMBERS'] else None,
        "At least one uppercase letter" if SECURITY_SETTINGS['REQUIRE_UPPERCASE'] else None,
        "At least one lowercase letter" if SECURITY_SETTINGS['REQUIRE_LOWERCASE'] else None
    ]
    requirements = [req for req in requirements if req is not None]
    return render_template('register.html', password_requirements=requirements)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        try:
            username = request.form["username"]
            password = request.form["password"]
            user = verify_user(username, password)
            
            if user:
                session["user_id"] = user["id"]
                update_last_login(user["id"])
                # Get the next page from the request args, default to dashboard
                next_page = request.args.get('next', url_for('dashboard'))
                return redirect(next_page)
            else:
                flash('Invalid username or password', 'error')
                return render_template("login.html", error="Invalid credentials")
        except Exception as e:
            print(f"Login error: {str(e)}")
            flash('An error occurred during login', 'error')
            return render_template("login.html", error="An error occurred during login")
            
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/profile", methods=["GET", "POST"])
def profile():
    if "user_id" not in session:
        return redirect(url_for("login"))
    user = get_user_by_id(session["user_id"])
    if request.method == "POST":
        new_password = request.form["new_password"]
        if new_password:
            db = get_db()
            db.execute('UPDATE users SET password = ? WHERE id = ?', (generate_password_hash(new_password), user["id"]))
            db.commit()
            flash("Password updated successfully.", "success")
    return render_template("profile.html", user=user)

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))
    user = get_user_by_id(session["user_id"])
    signals = get_signals_for_user(user["id"], limit=10)
    total, by_pair, by_direction = get_signal_stats(user["id"])
    pair_labels = [p['pair'] for p in by_pair]
    pair_counts = [p['count'] for p in by_pair]
    direction_labels = [d['direction'] for d in by_direction]
    direction_counts = [d['count'] for d in by_direction]
    return render_template(
        "dashboard.html",
        user=user,
        signals=signals,
        total=total,
        pair_labels=pair_labels,
        pair_counts=pair_counts,
        direction_labels=direction_labels,
        direction_counts=direction_counts
    )

@app.route("/", methods=["GET", "POST"])
def index():
    if "user_id" not in session:
        return redirect(url_for("login"))

    current_rate = None
    selected_pair = pairs[0]
    selected_broker = brokers[0]
    payout = broker_payouts[selected_broker]
    call_price = None
    put_price = None
    volatility = 0.2
    expiry = 1/365
    risk_free_rate = 0.01
    if request.method == "POST":
        pair = request.form["pair"]
        broker = request.form["broker"]
        signal_type = request.form["signal_type"].upper()
        start_hour = request.form["start_hour"]
        start_minute = request.form["start_minute"]
        end_hour = request.form["end_hour"]
        end_minute = request.form["end_minute"]
        start_str = f"{start_hour}:{start_minute}"
        end_str = f"{end_hour}:{end_minute}"
        selected_pair = pair
        selected_broker = broker
        payout = broker_payouts.get(broker, 0.75)
        current_rate = get_cached_realtime_forex(pair, API_KEY)
        if current_rate:
            S = current_rate
            K = S
            T = expiry
            r = risk_free_rate
            sigma = volatility
            call_price = black_scholes_call_put(S, K, T, r, sigma, option_type="call")
            put_price = black_scholes_call_put(S, K, T, r, sigma, option_type="put")
        try:
            start = datetime.strptime(start_str, "%H:%M")
            end = datetime.strptime(end_str, "%H:%M")
            if start >= end:
                return render_template("index.html", error="Start time must be before end time.", pairs=pairs, brokers=brokers, current_rate=current_rate, selected_pair=selected_pair, selected_broker=selected_broker, payout=payout, call_price=call_price, put_price=put_price, volatility=volatility, expiry=expiry, risk_free_rate=risk_free_rate)

            signals = []
            current = start
            while current < end:
                direction = random.choice(["CALL", "PUT"]) if signal_type == "BOTH" else signal_type
                signal_time = current.strftime("%H:%M")
                created_at = datetime.now().isoformat()
                
                # Save to database
                save_signal(session["user_id"], signal_time, pair, direction)
                
                # Add to signals list with all required fields
                signals.append({
                    "time": signal_time,
                    "pair": pair,
                    "direction": direction,
                    "created_at": created_at,
                    "broker": broker
                })
                current += timedelta(minutes=random.randint(1, 15))

            session["signals"] = signals
            return render_template("results.html", signals=signals, current_rate=current_rate, selected_pair=selected_pair, selected_broker=selected_broker, payout=payout, call_price=call_price, put_price=put_price, volatility=volatility, expiry=expiry, risk_free_rate=risk_free_rate)
        except ValueError:
            return render_template("index.html", error="Invalid time format.", pairs=pairs, brokers=brokers, current_rate=current_rate, selected_pair=selected_pair, selected_broker=selected_broker, payout=payout, call_price=call_price, put_price=put_price, volatility=volatility, expiry=expiry, risk_free_rate=risk_free_rate)

    # For GET requests, show the rate for the default pair and broker
    current_rate = get_cached_realtime_forex(selected_pair, API_KEY)
    if current_rate:
        S = current_rate
        K = S
        T = expiry
        r = risk_free_rate
        sigma = volatility
        call_price = black_scholes_call_put(S, K, T, r, sigma, option_type="call")
        put_price = black_scholes_call_put(S, K, T, r, sigma, option_type="put")
    return render_template("index.html", pairs=pairs, brokers=brokers, current_rate=current_rate, selected_pair=selected_pair, selected_broker=selected_broker, payout=payout, call_price=call_price, put_price=put_price, volatility=volatility, expiry=expiry, risk_free_rate=risk_free_rate)

@app.route("/download")
@limiter.limit("50 per hour")
def download():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Generate secure token
    token = generate_file_token('signals.csv', session['user_id'])
    
    # Log access
    log_access(session['user_id'], 'download', get_client_ip())
    
    # Create file in memory
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Time', 'Pair', 'Direction'])
    
    # Get signals for user
    signals = get_signals_for_user(session['user_id'])
    for signal in signals:
        writer.writerow([signal['time'], signal['pair'], signal['direction']])
    
    # Record download
    record_download(session['user_id'], 'signals.csv', get_client_ip(), token)
    
    # Encrypt file content if enabled
    if FILE_SECURITY['ENCRYPT_FILES']:
        content = encrypt_data(output.getvalue())
    else:
        content = output.getvalue()
    
    output.seek(0)
    return send_file(
        io.BytesIO(content),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'signals_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    )

@app.route("/api/price/<pair>")
def api_price(pair):
    current_rate = get_cached_realtime_forex(pair, API_KEY)
    volatility = 0.2
    expiry = 1/365
    risk_free_rate = 0.01
    call_price = put_price = None
    if current_rate:
        S = current_rate
        K = S
        T = expiry
        r = risk_free_rate
        sigma = volatility
        call_price = black_scholes_call_put(S, K, T, r, sigma, option_type="call")
        put_price = black_scholes_call_put(S, K, T, r, sigma, option_type="put")
    return jsonify({
        "rate": current_rate,
        "call_price": call_price,
        "put_price": put_price,
        "volatility": volatility,
        "expiry": expiry,
        "risk_free_rate": risk_free_rate
    })

# --- Indian Market Data ---
indian_pairs = [
    # Major Indices
    "NIFTY50", "BANKNIFTY", "NSEBANK", "NSEIT", "NSEINFRA", "NSEPHARMA", "NSEFMCG", "NSEMETAL", "NSEENERGY", "NSEAUTO",
    # Additional Indices
    "NIFTYMIDCAP", "NIFTYSMALLCAP", "NIFTYNEXT50", "NIFTY100", "NIFTY500",
    # Sector Indices
    "NIFTYREALTY", "NIFTYPVTBANK", "NIFTYPSUBANK", "NIFTYFIN", "NIFTYMEDIA",
    # Popular Stocks
    "RELIANCE", "TCS", "HDFCBANK", "INFY", "ICICIBANK", "HINDUNILVR", "SBIN", "BHARTIARTL", "KOTAKBANK", "BAJFINANCE"
]
indian_brokers = ["Zerodha", "Upstox", "Angel One", "Groww", "ICICI Direct", "HDFC Securities"]

@app.route("/indian", methods=["GET", "POST"])
def indian_market():
    if "user_id" not in session:
        return redirect(url_for("login"))

    current_rate = None
    selected_pair = indian_pairs[0]
    selected_broker = indian_brokers[0]
    payout = 0.75  # Indian brokers may not have payout, but keep for UI consistency
    call_price = None
    put_price = None
    volatility = 0.2
    expiry = 1/365
    risk_free_rate = 0.01
    if request.method == "POST":
        pair = request.form["pair"]
        broker = request.form["broker"]
        signal_type = request.form["signal_type"].upper()
        start_hour = request.form["start_hour"]
        start_minute = request.form["start_minute"]
        end_hour = request.form["end_hour"]
        end_minute = request.form["end_minute"]
        start_str = f"{start_hour}:{start_minute}"
        end_str = f"{end_hour}:{end_minute}"
        selected_pair = pair
        selected_broker = broker
        # For demo, use get_cached_realtime_forex with a fallback for Indian symbols
        try:
            current_rate = get_cached_realtime_forex(pair, API_KEY)
        except Exception:
            current_rate = round(random.uniform(10000, 50000), 2)
        if current_rate:
            S = current_rate
            K = S
            T = expiry
            r = risk_free_rate
            sigma = volatility
            call_price = black_scholes_call_put(S, K, T, r, sigma, option_type="call")
            put_price = black_scholes_call_put(S, K, T, r, sigma, option_type="put")
        try:
            start = datetime.strptime(start_str, "%H:%M")
            end = datetime.strptime(end_str, "%H:%M")
            if start >= end:
                return render_template("indian.html", error="Start time must be before end time.", pairs=indian_pairs, brokers=indian_brokers, current_rate=current_rate, selected_pair=selected_pair, selected_broker=selected_broker, payout=payout, call_price=call_price, put_price=put_price, volatility=volatility, expiry=expiry, risk_free_rate=risk_free_rate)

            signals = []
            current = start
            while current < end:
                direction = random.choice(["CALL", "PUT"]) if signal_type == "BOTH" else signal_type
                signals.append({
                    "time": current.strftime("%H:%M"),
                    "pair": pair,
                    "direction": direction
                })
                save_signal(session["user_id"], current.strftime("%H:%M"), pair, direction)
                current += timedelta(minutes=random.randint(1, 15))

            session["indian_signals"] = signals
            return render_template("indian.html", signals=signals, current_rate=current_rate, selected_pair=selected_pair, selected_broker=selected_broker, payout=payout, call_price=call_price, put_price=put_price, volatility=volatility, expiry=expiry, risk_free_rate=risk_free_rate, pairs=indian_pairs, brokers=indian_brokers)
        except ValueError:
            return render_template("indian.html", error="Invalid time format.", pairs=indian_pairs, brokers=indian_brokers, current_rate=current_rate, selected_pair=selected_pair, selected_broker=selected_broker, payout=payout, call_price=call_price, put_price=put_price, volatility=volatility, expiry=expiry, risk_free_rate=risk_free_rate)

    # For GET requests, show the rate for the default pair and broker
    try:
        current_rate = get_cached_realtime_forex(selected_pair, API_KEY)
    except Exception:
        current_rate = round(random.uniform(10000, 50000), 2)
    if current_rate:
        S = current_rate
        K = S
        T = expiry
        r = risk_free_rate
        sigma = volatility
        call_price = black_scholes_call_put(S, K, T, r, sigma, option_type="call")
        put_price = black_scholes_call_put(S, K, T, r, sigma, option_type="put")
    signals = session.get("indian_signals", [])
    return render_template("indian.html", pairs=indian_pairs, brokers=indian_brokers, current_rate=current_rate, selected_pair=selected_pair, selected_broker=selected_broker, payout=payout, call_price=call_price, put_price=put_price, volatility=volatility, expiry=expiry, risk_free_rate=risk_free_rate, signals=signals)

# --- OTC Market Data ---
otc_pairs = [
    "EURUSD_OTC", "GBPUSD_OTC", "USDJPY_OTC", "AUDUSD_OTC", "USDCHF_OTC", "USDCAD_OTC", "EURJPY_OTC", "EURGBP_OTC"
]
otc_brokers = ["Quotex", "Pocket Option", "Binolla", "IQ Option", "Bullex", "Exnova"]

@app.route("/otc", methods=["GET", "POST"])
def otc_market():
    if "user_id" not in session:
        return redirect(url_for("login"))

    current_rate = None
    selected_pair = otc_pairs[0]
    selected_broker = otc_brokers[0]
    payout = broker_payouts[selected_broker]
    call_price = None
    put_price = None
    volatility = 0.2
    expiry = 1/365
    risk_free_rate = 0.01
    if request.method == "POST":
        pair = request.form["pair"]
        broker = request.form["broker"]
        signal_type = request.form["signal_type"].upper()
        start_hour = request.form["start_hour"]
        start_minute = request.form["start_minute"]
        end_hour = request.form["end_hour"]
        end_minute = request.form["end_minute"]
        start_str = f"{start_hour}:{start_minute}"
        end_str = f"{end_hour}:{end_minute}"
        selected_pair = pair
        selected_broker = broker
        payout = broker_payouts.get(broker, 0.75)
        current_rate = get_cached_realtime_forex(pair.replace('_OTC',''), API_KEY)
        if current_rate:
            S = current_rate
            K = S
            T = expiry
            r = risk_free_rate
            sigma = volatility
            call_price = black_scholes_call_put(S, K, T, r, sigma, option_type="call")
            put_price = black_scholes_call_put(S, K, T, r, sigma, option_type="put")
        try:
            start = datetime.strptime(start_str, "%H:%M")
            end = datetime.strptime(end_str, "%H:%M")
            if start >= end:
                return render_template("otc.html", error="Start time must be before end time.", pairs=otc_pairs, brokers=otc_brokers, current_rate=current_rate, selected_pair=selected_pair, selected_broker=selected_broker, payout=payout, call_price=call_price, put_price=put_price, volatility=volatility, expiry=expiry, risk_free_rate=risk_free_rate)

            signals = []
            current = start
            while current < end:
                direction = random.choice(["CALL", "PUT"]) if signal_type == "BOTH" else signal_type
                signals.append({
                    "time": current.strftime("%H:%M"),
                    "pair": pair,
                    "direction": direction
                })
                save_signal(session["user_id"], current.strftime("%H:%M"), pair, direction)
                current += timedelta(minutes=random.randint(1, 15))

            session["otc_signals"] = signals
            return render_template("otc.html", signals=signals, current_rate=current_rate, selected_pair=selected_pair, selected_broker=selected_broker, payout=payout, call_price=call_price, put_price=put_price, volatility=volatility, expiry=expiry, risk_free_rate=risk_free_rate, pairs=otc_pairs, brokers=otc_brokers)
        except ValueError:
            return render_template("otc.html", error="Invalid time format.", pairs=otc_pairs, brokers=otc_brokers, current_rate=current_rate, selected_pair=selected_pair, selected_broker=selected_broker, payout=payout, call_price=call_price, put_price=put_price, volatility=volatility, expiry=expiry, risk_free_rate=risk_free_rate)

    # For GET requests, show the rate for the default pair and broker
    current_rate = get_cached_realtime_forex(selected_pair.replace('_OTC',''), API_KEY)
    if current_rate:
        S = current_rate
        K = S
        T = expiry
        r = risk_free_rate
        sigma = volatility
        call_price = black_scholes_call_put(S, K, T, r, sigma, option_type="call")
        put_price = black_scholes_call_put(S, K, T, r, sigma, option_type="put")
    signals = session.get("otc_signals", [])
    return render_template("otc.html", pairs=otc_pairs, brokers=otc_brokers, current_rate=current_rate, selected_pair=selected_pair, selected_broker=selected_broker, payout=payout, call_price=call_price, put_price=put_price, volatility=volatility, expiry=expiry, risk_free_rate=risk_free_rate, signals=signals)

@app.route("/download_otc")
@secure_file_access
@limiter.limit("10 per hour")
def download_otc():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    # Generate secure token
    token = generate_file_token('otc_signals.csv', session['user_id'])
    
    # Log access
    log_access(session['user_id'], 'download_otc_request', get_client_ip())
    
    # Create the file in memory
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Time', 'Pair', 'Direction', 'Broker'])
    
    # Get OTC signals from session
    otc_signals = session.get('otc_signals', [])
    for signal in otc_signals:
        writer.writerow([signal['time'], signal['pair'], signal['direction'], signal['broker']])
    
    # Record the download
    record_download(session['user_id'], 'otc_signals.csv', get_client_ip(), token)
    
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'otc_signals_{datetime.now().strftime("%Y%m%d")}.csv'
    )

@app.route("/download_indian")
@secure_file_access
@limiter.limit("10 per hour")
def download_indian():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    # Generate secure token
    token = generate_file_token('indian_signals.csv', session['user_id'])
    
    # Log the access
    log_access(session['user_id'], 'download_indian_request', get_client_ip())
    
    # Create the file in memory
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Time', 'Symbol', 'Direction', 'Price'])
    
    # Get Indian market signals from session
    indian_signals = session.get('indian_signals', [])
    for signal in indian_signals:
        writer.writerow([signal['time'], signal['pair'], signal['direction'], signal['price']])
    
    # Record the download
    record_download(session['user_id'], 'indian_signals.csv', get_client_ip(), token)
    
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'indian_signals_{datetime.now().strftime("%Y%m%d")}.csv'
    )

def calculate_technical_indicators(data):
    try:
        # Convert data to pandas DataFrame
        df = pd.DataFrame(data)
        
        # Calculate indicators using pandas
        df['SMA_20'] = df['close'].rolling(window=20).mean()
        df['EMA_20'] = df['close'].ewm(span=20, adjust=False).mean()
        
        # MACD
        exp1 = df['close'].ewm(span=12, adjust=False).mean()
        exp2 = df['close'].ewm(span=26, adjust=False).mean()
        df['MACD'] = exp1 - exp2
        df['Signal'] = df['MACD'].ewm(span=9, adjust=False).mean()
        
        # RSI
        delta = df['close'].diff()
        gain = (delta.where(delta > 0, 0)).rolling(window=14).mean()
        loss = (-delta.where(delta < 0, 0)).rolling(window=14).mean()
        rs = gain / loss
        df['RSI'] = 100 - (100 / (1 + rs))
        
        # Bollinger Bands
        df['BB_middle'] = df['close'].rolling(window=20).mean()
        df['BB_std'] = df['close'].rolling(window=20).std()
        df['BB_upper'] = df['BB_middle'] + (df['BB_std'] * 2)
        df['BB_lower'] = df['BB_middle'] - (df['BB_std'] * 2)
        
        return {
            'sma': df['SMA_20'].tolist(),
            'ema': df['EMA_20'].tolist(),
            'macd': df['MACD'].tolist(),
            'macd_signal': df['Signal'].tolist(),
            'rsi': df['RSI'].tolist(),
            'bollinger_upper': df['BB_upper'].tolist(),
            'bollinger_lower': df['BB_lower'].tolist()
        }
    except Exception as e:
        print(f"Error calculating indicators: {e}")
        return None

def get_historical_data(symbol, period='1mo', interval='1d'):
    """Fetch historical market data and calculate technical indicators"""
    try:
        yahoo_symbol = symbol_map.get(symbol)
        if not yahoo_symbol:
            print(f"Invalid symbol: {symbol}")
            return {
                'historical': None,
                'realtime': None,
                'error': f"Invalid symbol: {symbol}"
            }
        
        print(f"Fetching data for {symbol} using Yahoo symbol {yahoo_symbol}")
        
        # Fetch data from Yahoo Finance
        ticker = yf.Ticker(yahoo_symbol)
        df = ticker.history(period=period, interval=interval)
        
        if df.empty:
            print(f"No data received from Yahoo Finance for {symbol}")
            return {
                'historical': None,
                'realtime': None,
                'error': f"No data available for {symbol}"
            }
        
        # Calculate technical indicators
        # Simple Moving Averages
        df['SMA20'] = df['Close'].rolling(window=20).mean()
        
        # Exponential Moving Averages
        df['EMA20'] = df['Close'].ewm(span=20, adjust=False).mean()
        
        # MACD
        exp1 = df['Close'].ewm(span=12, adjust=False).mean()
        exp2 = df['Close'].ewm(span=26, adjust=False).mean()
        df['MACD'] = exp1 - exp2
        df['Signal'] = df['MACD'].ewm(span=9, adjust=False).mean()
        
        # RSI
        delta = df['Close'].diff()
        gain = (delta.where(delta > 0, 0)).rolling(window=14).mean()
        loss = (-delta.where(delta < 0, 0)).rolling(window=14).mean()
        rs = gain / loss
        df['RSI'] = 100 - (100 / (1 + rs))
        
        # Bollinger Bands
        df['BB_middle'] = df['Close'].rolling(window=20).mean()
        df['BB_std'] = df['Close'].rolling(window=20).std()
        df['BB_upper'] = df['BB_middle'] + (df['BB_std'] * 2)
        df['BB_lower'] = df['BB_middle'] - (df['BB_std'] * 2)
        
        # Replace NaN values with None for JSON serialization
        df = df.replace({np.nan: None})
        
        # Prepare the response data
        dates = df.index.strftime('%Y-%m-%d').tolist()
        
        historical_data = {
            'dates': dates,
            'prices': {
                'open': [round(x, 2) if x is not None else None for x in df['Open'].tolist()],
                'high': [round(x, 2) if x is not None else None for x in df['High'].tolist()],
                'low': [round(x, 2) if x is not None else None for x in df['Low'].tolist()],
                'close': [round(x, 2) if x is not None else None for x in df['Close'].tolist()],
                'volume': [int(x) if x is not None else None for x in df['Volume'].tolist()]
            },
            'indicators': {
                'sma': [round(x, 2) if x is not None else None for x in df['SMA20'].tolist()],
                'ema': [round(x, 2) if x is not None else None for x in df['EMA20'].tolist()],
                'macd': [round(x, 2) if x is not None else None for x in df['MACD'].tolist()],
                'macd_signal': [round(x, 2) if x is not None else None for x in df['Signal'].tolist()],
                'rsi': [round(x, 2) if x is not None else None for x in df['RSI'].tolist()],
                'bollinger_upper': [round(x, 2) if x is not None else None for x in df['BB_upper'].tolist()],
                'bollinger_middle': [round(x, 2) if x is not None else None for x in df['BB_middle'].tolist()],
                'bollinger_lower': [round(x, 2) if x is not None else None for x in df['BB_lower'].tolist()]
            }
        }
        
        # Get real-time data for current values
        realtime_data = get_indian_market_data(symbol)
        
        return {
            'historical': historical_data,
            'realtime': realtime_data
        }
        
    except Exception as e:
        print(f"Error in get_historical_data for {symbol}: {str(e)}")
        return {
            'historical': None,
            'realtime': None,
            'error': str(e)
        }

@app.route("/market_data/<symbol>")
def market_data(symbol):
    """API endpoint to get market data for a symbol"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        timeframe = request.args.get('timeframe', '1mo')
        print(f"Fetching data for {symbol} with timeframe {timeframe}")  # Debug log
        
        data = get_historical_data(symbol, period=timeframe)
        print(f"Received data: {data}")  # Debug log
        
        if not data:
            return jsonify({'error': 'No data available'}), 404
            
        if data.get('error'):
            return jsonify({'error': data['error']}), 500
            
        if not data.get('historical') or not data.get('realtime'):
            return jsonify({'error': 'Incomplete data received'}), 500
            
        return jsonify(data)
        
    except Exception as e:
        print(f"Error in market_data endpoint: {str(e)}")  # Debug log
        return jsonify({'error': str(e)}), 500

@app.route("/market_dashboard")
def market_dashboard():
    """Market data dashboard page"""
    if "user_id" not in session:
        return redirect(url_for("login"))
        
    return render_template("market_dashboard.html", 
                         indian_pairs=indian_pairs,
                         user=get_user_by_id(session["user_id"]))

@app.route("/legal")
def legal():
    """Legal information page"""
    if "user_id" not in session:
        return redirect(url_for("login"))
        
    return render_template("legal.html", 
                         user=get_user_by_id(session["user_id"]))

@app.route("/subscription")
def subscription():
    """Subscription plans page"""
    # Define subscription plans
    plans = [
        {
            "name": "Basic",
            "price": "₹999",
            "period": "month",
            "features": [
                "Basic Market Analysis",
                "Daily Trading Signals",
                "Email Notifications",
                "Basic Technical Indicators"
            ],
            "id": "basic"
        },
        {
            "name": "Pro",
            "price": "₹2,499",
            "period": "month",
            "features": [
                "Advanced Market Analysis",
                "Real-time Trading Signals",
                "Priority Email Support",
                "Advanced Technical Indicators",
                "Custom Alerts",
                "Market News Updates"
            ],
            "popular": True,
            "id": "pro"
        },
        {
            "name": "Premium",
            "price": "₹4,999",
            "period": "month",
            "features": [
                "All Pro Features",
                "1-on-1 Trading Support",
                "Custom Strategy Development",
                "Portfolio Analysis",
                "Risk Management Tools",
                "VIP Market Insights"
            ],
            "id": "premium"
        }
    ]
    
    # Get user if authenticated, otherwise pass None
    user = get_user_by_id(session["user_id"]) if "user_id" in session else None
    
    return render_template("subscription.html", 
                         user=user,
                         plans=plans)

@app.route("/subscribe/<plan_id>", methods=["POST"])
def subscribe(plan_id):
    """Handle subscription requests"""
    if "user_id" not in session:
        return jsonify({"error": "Please login to subscribe"}), 401
        
    user = get_user_by_id(session["user_id"])
    if not user:
        return jsonify({"error": "User not found"}), 404
        
    # Validate plan_id
    valid_plans = ["basic", "pro", "premium"]
    if plan_id not in valid_plans:
        return jsonify({"error": "Invalid subscription plan"}), 400
        
    try:
        # Here you would typically:
        # 1. Process payment
        # 2. Update user's subscription status in database
        # 3. Send confirmation email
        
        # For now, we'll just update the session
        session['subscription'] = {
            'plan': plan_id,
            'started_at': datetime.now().isoformat()
        }
        
        return jsonify({
            "success": True,
            "message": f"Successfully subscribed to {plan_id} plan",
            "redirect": url_for("dashboard")
        })
        
    except Exception as e:
        print(f"Error processing subscription: {str(e)}")
        return jsonify({"error": "Failed to process subscription. Please try again."}), 500

# Admin route to view access logs
@app.route("/admin/logs")
@admin_required
def view_logs():
    db = get_db()
    logs = db.execute('''
        SELECT al.*, u.username 
        FROM access_logs al 
        JOIN users u ON al.user_id = u.id 
        ORDER BY al.timestamp DESC 
        LIMIT 100
    ''').fetchall()
    return render_template('admin/logs.html', logs=logs)

# Admin route to manage allowed IPs
@app.route("/admin/ip-management", methods=['GET', 'POST'])
@admin_required
def manage_ips():
    if request.method == 'POST':
        action = request.form.get('action')
        ip = request.form.get('ip')
        
        if action == 'add' and ip:
            ALLOWED_IPS.add(ip)
        elif action == 'remove' and ip:
            ALLOWED_IPS.discard(ip)
            
    return render_template('admin/ip_management.html', allowed_ips=ALLOWED_IPS)

def log_access(user_id, action, ip_address):
    db = get_db()
    db.execute(
        'INSERT INTO access_logs (user_id, action, ip_address, timestamp) VALUES (?, ?, ?, ?)',
        (user_id, action, ip_address, datetime.now().isoformat())
    )
    db.commit()

def record_download(user_id, filename='signals.csv', ip_address=None, token=None):
    db = get_db()
    db.execute(
        'INSERT INTO file_downloads (user_id, filename, date, ip_address, token, created_at) VALUES (?, ?, ?, ?, ?, ?)',
        (user_id, filename, datetime.now().date().isoformat(), ip_address, token, datetime.now().isoformat())
    )
    db.execute(
        'UPDATE users SET download_count = download_count + 1, last_download = ? WHERE id = ?',
        (datetime.now().isoformat(), user_id)
    )
    db.commit()

def generate_pdf_report(signals, report_type="Signals"):
    """Generate a PDF report of signals"""
    try:
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        styles = getSampleStyleSheet()
        
        # Create custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            textColor=colors.HexColor('#2a4d8f')
        )
        
        # Create the story (content) for the PDF
        story = []
        
        # Add title
        story.append(Paragraph(f"Kishan X Trading {report_type}", title_style))
        story.append(Spacer(1, 20))
        
        # Get user info from database
        user = get_user_by_id(session['user_id'])
        if user:
            user_info = f"Generated for: {user['username']}"
        else:
            user_info = "Generated for: User"
        story.append(Paragraph(user_info, styles['Normal']))
        story.append(Spacer(1, 10))
        
        # Add timestamp
        timestamp = f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        story.append(Paragraph(timestamp, styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Create table data
        data = [['Time', 'Pair', 'Direction', 'Created At']]  # Headers
        
        # Add signal data
        if signals:
            for signal in signals:
                created_at = signal.get('created_at', 'N/A')
                if isinstance(created_at, str) and 'T' in created_at:
                    created_at = created_at.replace('T', ' ')[:16]
                data.append([
                    signal.get('time', 'N/A'),
                    signal.get('pair', 'N/A'),
                    signal.get('direction', 'N/A'),
                    created_at
                ])
        else:
            data.append(['No signals available', '', '', ''])
        
        # Create table
        table = Table(data)
        
        # Add table style
        table_style = TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2a4d8f')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ])
        table.setStyle(table_style)
        story.append(table)
        
        # Build PDF
        doc.build(story)
        buffer.seek(0)
        return buffer
    except Exception as e:
        print(f"Error generating PDF: {str(e)}")
        raise

@app.route("/download_pdf")
@secure_file_access
@limiter.limit("10 per hour")
def download_pdf():
    try:
        if 'user_id' not in session:
            return redirect(url_for('login'))
            
        # Generate secure token
        token = generate_file_token('signals.pdf', session['user_id'])
        
        # Log access
        log_access(session['user_id'], 'download_pdf', get_client_ip())
        
        # Get signals from database
        signals = get_signals_for_user(session['user_id'])
        
        if not signals:
            flash('No signals available to generate PDF', 'warning')
            return redirect(url_for('dashboard'))
        
        # Create PDF in memory
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        styles = getSampleStyleSheet()
        
        # Create the story (content) for the PDF
        story = []
        
        # Add title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            textColor=colors.HexColor('#2a4d8f')
        )
        story.append(Paragraph("Kishan X Trading Signals", title_style))
        story.append(Spacer(1, 20))
        
        # Add user info
        user = get_user_by_id(session['user_id'])
        user_info = f"Generated for: {user['username'] if user else 'User'}"
        story.append(Paragraph(user_info, styles['Normal']))
        story.append(Spacer(1, 10))
        
        # Add timestamp
        timestamp = f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        story.append(Paragraph(timestamp, styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Create table data
        data = [['Time', 'Pair', 'Direction', 'Broker', 'Created At']]  # Headers
        
        # Add signal data
        for signal in signals:
            created_at = signal.get('created_at', 'N/A')
            if isinstance(created_at, str) and 'T' in created_at:
                created_at = created_at.replace('T', ' ')[:16]
            data.append([
                signal.get('time', 'N/A'),
                signal.get('pair', 'N/A'),
                signal.get('direction', 'N/A'),
                signal.get('broker', 'N/A'),
                created_at
            ])
        
        # Create table
        table = Table(data)
        
        # Add table style
        table_style = TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2a4d8f')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ])
        table.setStyle(table_style)
        story.append(table)
        
        # Build PDF
        doc.build(story)
        buffer.seek(0)
        
        # Record download
        record_download(session['user_id'], 'signals.pdf', get_client_ip(), token)
        
        # Send file
        return send_file(
            buffer,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f'signals_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
        )
    except Exception as e:
        print(f"Error in download_pdf: {str(e)}")
        flash('Error generating PDF. Please try again.', 'error')
        return redirect(url_for('dashboard'))

@app.route("/download_otc_pdf")
@secure_file_access
@limiter.limit("10 per hour")
def download_otc_pdf():
    try:
        if 'user_id' not in session:
            return redirect(url_for('login'))
            
        # Generate secure token
        token = generate_file_token('otc_signals.pdf', session['user_id'])
        
        # Log access
        log_access(session['user_id'], 'download_otc_pdf', get_client_ip())
        
        # Get OTC signals from database
        signals = get_signals_for_user(session['user_id'])
        otc_signals = [s for s in signals if s.get('pair', '').endswith('_OTC')]
        
        if not otc_signals:
            flash('No OTC signals available to generate PDF', 'warning')
            return redirect(url_for('otc_market'))
        
        # Create PDF in memory
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        styles = getSampleStyleSheet()
        
        # Create the story (content) for the PDF
        story = []
        
        # Add title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            textColor=colors.HexColor('#2a4d8f')
        )
        story.append(Paragraph("Kishan X OTC Trading Signals", title_style))
        story.append(Spacer(1, 20))
        
        # Add user info
        user = get_user_by_id(session['user_id'])
        user_info = f"Generated for: {user['username'] if user else 'User'}"
        story.append(Paragraph(user_info, styles['Normal']))
        story.append(Spacer(1, 10))
        
        # Add timestamp
        timestamp = f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        story.append(Paragraph(timestamp, styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Create table data
        data = [['Time', 'Pair', 'Direction', 'Broker', 'Created At']]  # Headers
        
        # Add signal data
        for signal in otc_signals:
            created_at = signal.get('created_at', 'N/A')
            if isinstance(created_at, str) and 'T' in created_at:
                created_at = created_at.replace('T', ' ')[:16]
            data.append([
                signal.get('time', 'N/A'),
                signal.get('pair', 'N/A'),
                signal.get('direction', 'N/A'),
                signal.get('broker', 'N/A'),
                created_at
            ])
        
        # Create table
        table = Table(data)
        
        # Add table style
        table_style = TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2a4d8f')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ])
        table.setStyle(table_style)
        story.append(table)
        
        # Build PDF
        doc.build(story)
        buffer.seek(0)
        
        # Record download
        record_download(session['user_id'], 'otc_signals.pdf', get_client_ip(), token)
        
        # Send file
        return send_file(
            buffer,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f'otc_signals_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
        )
    except Exception as e:
        print(f"Error in download_otc_pdf: {str(e)}")
        flash('Error generating PDF. Please try again.', 'error')
        return redirect(url_for('otc_market'))

@app.route("/download_indian_pdf")
@secure_file_access
@limiter.limit("10 per hour")
def download_indian_pdf():
    try:
        if 'user_id' not in session:
            return redirect(url_for('login'))
            
        # Generate secure token
        token = generate_file_token('indian_signals.pdf', session['user_id'])
        
        # Log access
        log_access(session['user_id'], 'download_indian_pdf', get_client_ip())
        
        # Get Indian market signals from database
        signals = get_signals_for_user(session['user_id'])
        indian_signals = [s for s in signals if s.get('pair', '') in indian_pairs]
        
        if not indian_signals:
            flash('No Indian market signals available to generate PDF', 'warning')
            return redirect(url_for('indian_market'))
        
        # Create PDF in memory
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        styles = getSampleStyleSheet()
        
        # Create the story (content) for the PDF
        story = []
        
        # Add title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            textColor=colors.HexColor('#2a4d8f')
        )
        story.append(Paragraph("Kishan X Indian Market Signals", title_style))
        story.append(Spacer(1, 20))
        
        # Add user info
        user = get_user_by_id(session['user_id'])
        user_info = f"Generated for: {user['username'] if user else 'User'}"
        story.append(Paragraph(user_info, styles['Normal']))
        story.append(Spacer(1, 10))
        
        # Add timestamp
        timestamp = f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        story.append(Paragraph(timestamp, styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Create table data
        data = [['Time', 'Symbol', 'Direction', 'Broker', 'Created At']]  # Headers
        
        # Add signal data
        for signal in indian_signals:
            created_at = signal.get('created_at', 'N/A')
            if isinstance(created_at, str) and 'T' in created_at:
                created_at = created_at.replace('T', ' ')[:16]
            data.append([
                signal.get('time', 'N/A'),
                signal.get('pair', 'N/A'),
                signal.get('direction', 'N/A'),
                signal.get('broker', 'N/A'),
                created_at
            ])
        
        # Create table
        table = Table(data)
        
        # Add table style
        table_style = TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2a4d8f')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ])
        table.setStyle(table_style)
        story.append(table)
        
        # Build PDF
        doc.build(story)
        buffer.seek(0)
        
        # Record download
        record_download(session['user_id'], 'indian_signals.pdf', get_client_ip(), token)
        
        # Send file
        return send_file(
            buffer,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f'indian_signals_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
        )
    except Exception as e:
        print(f"Error in download_indian_pdf: {str(e)}")
        flash('Error generating PDF. Please try again.', 'error')
        return redirect(url_for('indian_market'))

if __name__ == "__main__":
    app.run(debug=True)
