-- ============================================================
-- SecretShelf | 02_roles.sql
-- Purpose: Create PostgreSQL roles and assign permissions
-- These are DATABASE roles -- separate from application users
-- Think of these as the "identity" Flask uses to connect
-- ============================================================


-- ============================================================
-- CREATE APPLICATION ROLES
-- We create 4 roles matching our user_role enum
-- Flask connects to PostgreSQL using these roles
-- not as the superuser postgres
-- This means even if Flask is compromised, the attacker
-- only has the permissions of that role -- not full DB access
-- ============================================================

-- Drop roles if they already exist (useful when re-running)
DROP ROLE IF EXISTS secretshelf_owner;
DROP ROLE IF EXISTS secretshelf_admin;
DROP ROLE IF EXISTS secretshelf_developer;
DROP ROLE IF EXISTS secretshelf_viewer;
DROP ROLE IF EXISTS secretshelf_app;

-- secretshelf_app is the base role Flask always connects as
-- all other roles inherit from this
CREATE ROLE secretshelf_app WITH
    LOGIN
    PASSWORD 'secretshelf_app_password'
    NOSUPERUSER
    NOCREATEDB
    NOCREATEROLE;

-- Owner role -- highest privilege
CREATE ROLE secretshelf_owner WITH
    LOGIN
    PASSWORD 'secretshelf_owner_password'
    NOSUPERUSER
    NOCREATEDB
    NOCREATEROLE;

-- Admin role
CREATE ROLE secretshelf_admin WITH
    LOGIN
    PASSWORD 'secretshelf_admin_password'
    NOSUPERUSER
    NOCREATEDB
    NOCREATEROLE;

-- Developer role
CREATE ROLE secretshelf_developer WITH
    LOGIN
    PASSWORD 'secretshelf_developer_password'
    NOSUPERUSER
    NOCREATEDB
    NOCREATEROLE;

-- Viewer role -- lowest privilege
CREATE ROLE secretshelf_viewer WITH
    LOGIN
    PASSWORD 'secretshelf_viewer_password'
    NOSUPERUSER
    NOCREATEDB
    NOCREATEROLE;


-- ============================================================
-- GRANT SCHEMA ACCESS
-- All roles need to see the public schema
-- Without this they cannot find any tables
-- ============================================================

GRANT USAGE ON SCHEMA public TO
    secretshelf_app,
    secretshelf_owner,
    secretshelf_admin,
    secretshelf_developer,
    secretshelf_viewer;


-- ============================================================
-- GRANT SEQUENCE ACCESS
-- Sequences are what power SERIAL / auto-increment columns
-- Roles need USAGE on sequences to insert rows
-- ============================================================

GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO
    secretshelf_app,
    secretshelf_owner,
    secretshelf_admin,
    secretshelf_developer,
    secretshelf_viewer;


-- ============================================================
-- GRANT TABLE PERMISSIONS
-- Each role gets exactly what it needs -- nothing more
-- Principle of least privilege
-- ============================================================

-- secretshelf_app: used by Flask for auth only
-- can read users table to verify login
-- can insert/update for registration and lockout
GRANT SELECT, INSERT, UPDATE ON users TO secretshelf_app;
GRANT SELECT, INSERT ON jwt_blacklist TO secretshelf_app;
GRANT INSERT ON access_log TO secretshelf_app;


-- secretshelf_owner: full control over everything
GRANT SELECT, INSERT, UPDATE, DELETE ON
    users,
    vaults,
    vault_members,
    secrets,
    secret_grants,
    jwt_blacklist
TO secretshelf_owner;

-- owner can read audit log but NOT delete it
GRANT SELECT ON access_log TO secretshelf_owner;
-- INSERT on access_log is handled by triggers only
GRANT INSERT ON access_log TO secretshelf_owner;


-- secretshelf_admin: manage secrets and members
-- cannot delete users or vaults
GRANT SELECT, INSERT, UPDATE ON
    vaults,
    vault_members,
    secrets,
    secret_grants
TO secretshelf_admin;

GRANT SELECT, UPDATE ON users TO secretshelf_admin;
GRANT SELECT, INSERT ON jwt_blacklist TO secretshelf_admin;
GRANT SELECT, INSERT ON access_log TO secretshelf_admin;


-- secretshelf_developer: read and create secrets
-- cannot manage members or delete anything
GRANT SELECT ON
    vaults,
    vault_members,
    secret_grants
TO secretshelf_developer;

GRANT SELECT, INSERT ON secrets TO secretshelf_developer;
GRANT UPDATE (value_enc, updated_by, updated_at, status)
    ON secrets TO secretshelf_developer;
GRANT SELECT, INSERT ON jwt_blacklist TO secretshelf_developer;
GRANT SELECT, INSERT ON access_log TO secretshelf_developer;


-- secretshelf_viewer: read only
-- cannot see secret values directly -- only names
GRANT SELECT ON
    vaults,
    vault_members,
    secret_grants
TO secretshelf_viewer;

-- viewer can select from secrets table
-- but RLS in 03_rls.sql will restrict which rows they see
GRANT SELECT ON secrets TO secretshelf_viewer;
GRANT SELECT, INSERT ON jwt_blacklist TO secretshelf_viewer;
GRANT INSERT ON access_log TO secretshelf_viewer;


-- ============================================================
-- REVOKE DELETE ON access_log FROM EVERYONE
-- This is the tamper-proof guarantee
-- No application role can delete audit records
-- Even if an attacker gets admin access to the app
-- they cannot erase their tracks
-- ============================================================

REVOKE DELETE ON access_log FROM
    secretshelf_owner,
    secretshelf_admin,
    secretshelf_developer,
    secretshelf_viewer,
    secretshelf_app;

-- Also revoke UPDATE so log entries cannot be modified
REVOKE UPDATE ON access_log FROM
    secretshelf_owner,
    secretshelf_admin,
    secretshelf_developer,
    secretshelf_viewer,
    secretshelf_app;


-- ============================================================
-- VERIFY: Run these after executing the file
-- ============================================================

-- Check roles were created:
-- \du
-- You should see all 5 secretshelf roles listed

-- Check table permissions:
-- \dp secrets
-- You should see different privileges per role
