# ============================================================
# SecretShelf | app/db.py
# Purpose: PostgreSQL connection management
# Uses a connection pool -- instead of opening a new connection
# on every request, we reuse existing ones
# Much faster and safer for a web application
# ============================================================

import psycopg2
from psycopg2 import pool
from dotenv import load_dotenv
import os

load_dotenv()

# ============================================================
# CONNECTION POOL
# min 1 connection always open
# max 10 connections at peak load
# ============================================================

connection_pool = None

def init_pool():
    """Initialize the connection pool. Called once on app startup."""
    global connection_pool
    connection_pool = psycopg2.pool.SimpleConnectionPool(
        minconn=1,
        maxconn=10,
        dsn=os.getenv('DATABASE_URL')
    )
    print("Database connection pool initialized")


def get_connection():
    """Get a connection from the pool."""
    return connection_pool.getconn()


def return_connection(conn):
    """Return a connection back to the pool."""
    connection_pool.putconn(conn)


def close_pool():
    """Close all connections. Called on app shutdown."""
    if connection_pool:
        connection_pool.closeall()


# ============================================================
# SET SESSION CONTEXT
# This is critical for RLS to work
# Before every query Flask must tell PostgreSQL
# which user is making the request
# RLS policies read these session variables
# ============================================================

def set_session_context(cursor, user_id, user_role):
    """
    Set PostgreSQL session variables for RLS policies.
    Must be called before any query that touches
    secrets, vaults, vault_members, or secret_grants.
    """
    cursor.execute(
        "SELECT set_config('app.current_user_id', %s, TRUE)",
        (str(user_id),)
    )
    cursor.execute(
        "SELECT set_config('app.current_user_role', %s, TRUE)",
        (str(user_role),)
    )
    cursor.execute(
        "SELECT set_config('app.enc_key', %s, TRUE)",
        (os.getenv('ENCRYPTION_KEY'),)
    )
