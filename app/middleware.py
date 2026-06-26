# ============================================================
# SecretShelf | app/middleware.py
# Purpose: JWT verification for protected routes
# Every route that needs authentication uses this decorator
# ============================================================

import jwt
import os
from functools import wraps
from flask import request, jsonify
from .db import get_connection, return_connection, set_session_context
from dotenv import load_dotenv
import hashlib

load_dotenv()

def token_required(f):
    """
    Decorator for protected routes.
    Usage: @token_required
    The decorated function receives current_user as first argument.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        # JWT is passed in Authorization header
        # Format: Bearer <token>
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]

        if not token:
            return jsonify({
                'error': 'Authentication required',
                'message': 'Please log in to access this resource'
            }), 401

        conn = get_connection()
        try:
            cursor = conn.cursor()

            # Step 1: Decode and verify JWT signature
            payload = jwt.decode(
                token,
                os.getenv('JWT_SECRET_KEY'),
                algorithms=['HS256']  # Pin algorithm -- reject 'none'
            )

            user_id = payload['user_id']
            user_role = payload['role']

            # Step 2: Check token is not blacklisted (logged out)
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            cursor.execute(
                "SELECT id FROM jwt_blacklist WHERE token_hash = %s",
                (token_hash,)
            )
            if cursor.fetchone():
                return jsonify({
                    'error': 'Token invalidated',
                    'message': 'This session has been logged out'
                }), 401

            # Step 3: Verify user still exists and is active
            cursor.execute(
                "SELECT id, username, role, is_active FROM users WHERE id = %s",
                (user_id,)
            )
            user = cursor.fetchone()

            if not user or not user[3]:
                return jsonify({
                    'error': 'Account inactive',
                    'message': 'Your account has been disabled'
                }), 401

            # Step 4: Set PostgreSQL session context for RLS
            set_session_context(cursor, user_id, user_role)
            conn.commit()

            current_user = {
                'id': user[0],
                'username': user[1],
                'role': user[2]
            }

            cursor.close()

        except jwt.ExpiredSignatureError:
            return jsonify({
                'error': 'Token expired',
                'message': 'Please log in again'
            }), 401
        except jwt.InvalidTokenError:
            return jsonify({
                'error': 'Invalid token',
                'message': 'Authentication failed'
            }), 401
        finally:
            return_connection(conn)

        return f(current_user, *args, **kwargs)
    return decorated
