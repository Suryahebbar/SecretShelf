# ============================================================
# SecretShelf | app/auth.py
# Purpose: Register, login, logout routes
# This is the authentication layer
# ============================================================

import jwt
import os
import hashlib
from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify, render_template, redirect, url_for
from passlib.hash import bcrypt
from .db import get_connection, return_connection, set_session_context
from dotenv import load_dotenv

load_dotenv()

auth_bp = Blueprint('auth', __name__)


# ============================================================
# HELPER: Generate JWT token
# ============================================================

def generate_token(user_id, username, role):
    """
    Generate a signed JWT token.
    Expires in 15 minutes -- short expiry is intentional.
    Attacker who steals a token has a limited window.
    """
    payload = {
        'user_id':  user_id,
        'username': username,
        'role':     role,
        'exp':      datetime.utcnow() + timedelta(minutes=15),
        'iat':      datetime.utcnow()  # issued at
    }
    return jwt.encode(
        payload,
        os.getenv('JWT_SECRET_KEY'),
        algorithm='HS256'
    )


# ============================================================
# ROUTE: GET /
# Redirect root to login
# ============================================================

@auth_bp.route('/')
def index():
    return redirect(url_for('auth.login_page'))


# ============================================================
# ROUTE: GET /login
# Render login page
# ============================================================

@auth_bp.route('/login', methods=['GET'])
def login_page():
    return render_template('login.html')


# ============================================================
# ROUTE: GET /register
# Render register page
# ============================================================

@auth_bp.route('/register', methods=['GET'])
def register_page():
    return render_template('register.html')


# ============================================================
# ROUTE: POST /api/auth/register
# Create a new user account
# ============================================================

@auth_bp.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()

    # Validate required fields
    required = ['username', 'email', 'password']
    for field in required:
        if not data.get(field):
            return jsonify({
                'error': f'{field} is required'
            }), 400

    username = data['username'].strip().lower()
    email    = data['email'].strip().lower()
    password = data['password']

    # Password strength check
    if len(password) < 8:
        return jsonify({
            'error': 'Password must be at least 8 characters'
        }), 400

    # Hash password with bcrypt rounds=12
    # rounds=12 means 2^12 = 4096 iterations
    # makes brute force very slow
    password_hash = bcrypt.hash(password, rounds=12)

    conn = get_connection()
    try:
        cursor = conn.cursor()

        # Check username not already taken
        cursor.execute(
            "SELECT id FROM users WHERE username = %s OR email = %s",
            (username, email)
        )
        if cursor.fetchone():
            return jsonify({
                'error': 'Username or email already exists'
            }), 409

        # Insert new user
        # Default role is viewer -- admin must upgrade manually
        cursor.execute(
            """
            INSERT INTO users (username, email, password_hash, role)
            VALUES (%s, %s, %s, 'viewer')
            RETURNING id, username, role
            """,
            (username, email, password_hash)
        )
        user = cursor.fetchone()
        conn.commit()
        cursor.close()

        return jsonify({
            'message': 'Account created successfully',
            'user': {
                'id':       user[0],
                'username': user[1],
                'role':     user[2]
            }
        }), 201

    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        return_connection(conn)


# ============================================================
# ROUTE: POST /api/auth/login
# Verify credentials and issue JWT
# ============================================================

@auth_bp.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()

    if not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Username and password required'}), 400

    username = data['username'].strip().lower()
    password = data['password']

    conn = get_connection()
    try:
        cursor = conn.cursor()

        # Fetch user -- only active users
        cursor.execute(
            """
            SELECT id, username, email, password_hash,
                   role, failed_attempts, locked_until, is_active
            FROM users
            WHERE username = %s
            """,
            (username,)
        )
        user = cursor.fetchone()

        # IMPORTANT: Always run bcrypt even if user not found
        # This prevents timing attacks
        # An attacker cannot tell if username exists
        # based on response time
        dummy_hash = '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4tbHMQWWla'

        if not user:
            # Run bcrypt anyway to waste time
            bcrypt.verify(password, dummy_hash)
            return jsonify({'error': 'Invalid credentials'}), 401

        user_id, uname, email, pw_hash, role, failed, locked_until, is_active = user

        # Check account is active
        if not is_active:
            return jsonify({'error': 'Account disabled'}), 401

        # Check account lockout
        if locked_until and locked_until > datetime.utcnow():
            return jsonify({
                'error': 'Account temporarily locked',
                'locked_until': locked_until.isoformat(),
                'message': 'Too many failed attempts. Try again later.'
            }), 423

        # Verify password
        if not bcrypt.verify(password, pw_hash):
            # Record failed attempt via stored procedure
            cursor.execute(
                "CALL record_failed_login(%s)",
                (username,)
            )
            conn.commit()
            return jsonify({'error': 'Invalid credentials'}), 401

        # Successful login -- reset failed attempts
        cursor.execute(
            "CALL reset_failed_attempts(%s)",
            (user_id,)
        )
        conn.commit()

        # Generate JWT token
        token = generate_token(user_id, uname, role)

        cursor.close()

        return jsonify({
            'message': 'Login successful',
            'token': token,
            'user': {
                'id':       user_id,
                'username': uname,
                'role':     role
            }
        }), 200

    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        return_connection(conn)


# ============================================================
# ROUTE: POST /api/auth/logout
# Blacklist the current JWT token
# ============================================================

@auth_bp.route('/api/auth/logout', methods=['POST'])
def logout():
    token = None

    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization']
        if auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]

    if not token:
        return jsonify({'error': 'No token provided'}), 400

    try:
        # Decode to get expiry time
        payload = jwt.decode(
            token,
            os.getenv('JWT_SECRET_KEY'),
            algorithms=['HS256']
        )
        exp = datetime.utcfromtimestamp(payload['exp'])
        user_id = payload['user_id']

    except jwt.ExpiredSignatureError:
        # Token already expired -- nothing to blacklist
        return jsonify({'message': 'Already logged out'}), 200
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 400

    # Hash the token before storing
    # Never store the raw token in the blacklist
    token_hash = hashlib.sha256(token.encode()).hexdigest()

    conn = get_connection()
    try:
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO jwt_blacklist (token_hash, user_id, expires_at)
            VALUES (%s, %s, %s)
            ON CONFLICT (token_hash) DO NOTHING
            """,
            (token_hash, user_id, exp)
        )
        conn.commit()
        cursor.close()

        return jsonify({'message': 'Logged out successfully'}), 200

    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        return_connection(conn)


# ============================================================
# ROUTE: GET /dashboard
# Render dashboard page -- protected by JWT in frontend
# ============================================================

@auth_bp.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')
