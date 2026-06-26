-- ============================================================
-- SecretShelf | 01_schema.sql
-- Purpose: Create all tables, enums, and constraints
-- Run this first before any other SQL file
-- ============================================================


-- Enable pgcrypto extension
-- This gives us AES-256 encryption functions built into PostgreSQL
-- pgp_sym_encrypt() and pgp_sym_decrypt() come from this extension
CREATE EXTENSION IF NOT EXISTS pgcrypto;


-- ============================================================
-- ENUM TYPES
-- Enums are enforced at the DATABASE level
-- meaning even a direct psql connection cannot insert
-- a role that does not exist in this list
-- ============================================================

CREATE TYPE user_role AS ENUM (
    'owner',        -- full control, created the vault
    'admin',        -- can manage secrets and users
    'developer',    -- can read and create secrets
    'viewer'        -- read only, must explicitly reveal
);

CREATE TYPE secret_status AS ENUM (
    'active',       -- secret is currently in use
    'rotated',      -- secret was replaced by a newer version
    'expired',      -- secret passed its expiry date
    'deleted'       -- soft deleted, not visible to users
);

CREATE TYPE audit_action AS ENUM (
    'CREATED',      -- new secret was added
    'REVEALED',     -- secret value was decrypted and shown
    'ROTATED',      -- secret value was updated
    'DELETED',      -- secret was soft deleted
    'LOGIN',        -- user logged in
    'LOGOUT',       -- user logged out
    'FAILED_LOGIN'  -- wrong password attempt
);


-- ============================================================
-- TABLE: users
-- Stores all staff accounts across all vaults
-- Passwords are NEVER stored -- only bcrypt hashes
-- ============================================================

CREATE TABLE users (
    id                  SERIAL PRIMARY KEY,

    username            VARCHAR(50) NOT NULL UNIQUE,
    email               VARCHAR(255) NOT NULL UNIQUE,

    -- bcrypt hash of the password
    -- bcrypt output is always 60 characters
    -- we store 255 to be safe for future algorithm changes
    password_hash       VARCHAR(255) NOT NULL,

    -- role is enforced by the enum type above
    -- cannot insert 'superuser' or any unlisted value
    role                user_role NOT NULL DEFAULT 'viewer',

    -- account lockout fields
    -- after 5 failed logins, locked_until is set to NOW() + 15 minutes
    failed_attempts     INT NOT NULL DEFAULT 0,
    locked_until        TIMESTAMP,

    -- soft disable without deleting the user
    -- audit history is preserved even for disabled accounts
    is_active           BOOLEAN NOT NULL DEFAULT TRUE,

    created_at          TIMESTAMP NOT NULL DEFAULT NOW(),
    last_login          TIMESTAMP,

    -- constraint: failed_attempts cannot go negative
    CONSTRAINT chk_failed_attempts CHECK (failed_attempts >= 0)
);


-- ============================================================
-- TABLE: vaults
-- A vault is a named collection of secrets
-- Think of it like a folder or a project namespace
-- One user can own multiple vaults
-- ============================================================

CREATE TABLE vaults (
    id                  SERIAL PRIMARY KEY,

    name                VARCHAR(100) NOT NULL,
    description         TEXT,

    -- the user who created this vault
    -- ON DELETE RESTRICT means you cannot delete a user
    -- who still owns a vault -- must transfer ownership first
    owner_id            INT NOT NULL REFERENCES users(id)
                        ON DELETE RESTRICT,

    is_active           BOOLEAN NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMP NOT NULL DEFAULT NOW(),

    -- vault names must be unique per owner
    -- two different owners can have a vault called 'production'
    -- but one owner cannot have two vaults with the same name
    CONSTRAINT uq_vault_name_per_owner UNIQUE (owner_id, name)
);


-- ============================================================
-- TABLE: vault_members
-- Maps users to vaults with a specific role
-- This is the RBAC assignment table
-- One row = one user has one role on one vault
-- ============================================================

CREATE TABLE vault_members (
    id                  SERIAL PRIMARY KEY,

    vault_id            INT NOT NULL REFERENCES vaults(id)
                        ON DELETE CASCADE,

    user_id             INT NOT NULL REFERENCES users(id)
                        ON DELETE CASCADE,

    -- role on THIS vault specifically
    -- same user can be Admin on vault A and Viewer on vault B
    role                user_role NOT NULL,

    -- who added this person to the vault
    added_by            INT REFERENCES users(id)
                        ON DELETE SET NULL,

    added_at            TIMESTAMP NOT NULL DEFAULT NOW(),

    -- a user can only have one role per vault
    -- to change role, update this row -- do not insert a new one
    CONSTRAINT uq_user_per_vault UNIQUE (vault_id, user_id)
);


-- ============================================================
-- TABLE: secrets
-- The core table -- stores encrypted secret values
-- The plaintext value NEVER exists in this table
-- value_enc is BYTEA -- raw encrypted binary data
-- It looks like gibberish without the encryption key
-- ============================================================

CREATE TABLE secrets (
    id                  SERIAL PRIMARY KEY,

    vault_id            INT NOT NULL REFERENCES vaults(id)
                        ON DELETE CASCADE,

    -- the name of the secret -- stored as plaintext
    -- example: 'STRIPE_SECRET_KEY', 'DB_PASSWORD'
    -- names are not sensitive -- only values are
    name                VARCHAR(255) NOT NULL,

    -- the encrypted value -- this is the important part
    -- stored as BYTEA (binary) -- output of pgp_sym_encrypt()
    -- without the encryption key this is completely unreadable
    value_enc           BYTEA NOT NULL,

    -- optional description -- what is this secret used for
    description         TEXT,

    status              secret_status NOT NULL DEFAULT 'active',

    -- auto expiry -- NULL means never expires
    -- application checks this before revealing
    expires_at          TIMESTAMP,

    created_by          INT REFERENCES users(id)
                        ON DELETE SET NULL,

    updated_by          INT REFERENCES users(id)
                        ON DELETE SET NULL,

    created_at          TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMP NOT NULL DEFAULT NOW(),

    -- secret names must be unique within a vault
    -- same name can exist in different vaults
    CONSTRAINT uq_secret_name_per_vault UNIQUE (vault_id, name),

    -- name cannot be empty or just spaces
    CONSTRAINT chk_secret_name CHECK (LENGTH(TRIM(name)) > 0)
);


-- ============================================================
-- TABLE: secret_grants
-- Fine-grained access control WITHIN a vault
-- Even if a user is Developer on a vault,
-- specific secrets can be further restricted to specific users
-- ============================================================

CREATE TABLE secret_grants (
    id                  SERIAL PRIMARY KEY,

    secret_id           INT NOT NULL REFERENCES secrets(id)
                        ON DELETE CASCADE,

    user_id             INT NOT NULL REFERENCES users(id)
                        ON DELETE CASCADE,

    -- can this user reveal (decrypt) this secret
    can_reveal          BOOLEAN NOT NULL DEFAULT FALSE,

    -- can this user rotate (update) this secret
    can_rotate          BOOLEAN NOT NULL DEFAULT FALSE,

    granted_by          INT REFERENCES users(id)
                        ON DELETE SET NULL,

    granted_at          TIMESTAMP NOT NULL DEFAULT NOW(),

    -- one grant record per user per secret
    CONSTRAINT uq_grant_per_user_secret UNIQUE (secret_id, user_id)
);


-- ============================================================
-- TABLE: jwt_blacklist
-- When a user logs out, their JWT is added here
-- The middleware checks this table on every request
-- If the token hash exists here, access is denied
-- even if the token signature is technically still valid
-- ============================================================

CREATE TABLE jwt_blacklist (
    id                  SERIAL PRIMARY KEY,

    -- we store a hash of the token, not the token itself
    -- storing the full token would be a security risk
    token_hash          VARCHAR(255) NOT NULL UNIQUE,

    user_id             INT REFERENCES users(id)
                        ON DELETE CASCADE,

    invalidated_at      TIMESTAMP NOT NULL DEFAULT NOW(),

    -- when the token would have expired anyway
    -- used for cleanup -- no point keeping blacklist entries
    -- for tokens that are already expired
    expires_at          TIMESTAMP NOT NULL
);


-- ============================================================
-- TABLE: access_log
-- Immutable audit trail
-- Written automatically by triggers -- app does not touch this
-- REVOKE below prevents anyone from deleting rows
-- even the database superuser through the app roles
-- ============================================================

CREATE TABLE access_log (
    id                  BIGSERIAL PRIMARY KEY,

    user_id             INT REFERENCES users(id)
                        ON DELETE SET NULL,

    action              audit_action NOT NULL,

    -- which secret was accessed (NULL for login/logout events)
    secret_id           INT REFERENCES secrets(id)
                        ON DELETE SET NULL,

    -- which vault was involved
    vault_id            INT REFERENCES vaults(id)
                        ON DELETE SET NULL,

    -- IP address of the request
    -- INET is a PostgreSQL type specifically for IP addresses
    ip_address          INET,

    -- extra context stored as JSON
    -- flexible field for any additional information
    -- example: {"username": "priya", "reason": "deployment"}
    metadata            JSONB,

    accessed_at         TIMESTAMP NOT NULL DEFAULT NOW()

    -- NOTE: no updated_at, no soft delete, no status
    -- this table is append-only by design
    -- once written, a log entry cannot be changed
);


-- ============================================================
-- SECURITY: Make access_log tamper-proof
-- Even if an attacker gets Admin access to the database
-- they cannot delete or modify audit records
-- through the application roles we create in 02_roles.sql
-- ============================================================

-- We will apply REVOKE statements in 02_roles.sql
-- after creating the application roles
-- Noted here so the intent is clear at schema level


-- ============================================================
-- VERIFY: Run this after executing the file
-- You should see all 7 tables listed
-- ============================================================

-- \dt
-- Expected output:
--  Schema |     Name      | Type  |  Owner
-- --------+---------------+-------+----------
--  public | access_log    | table | postgres
--  public | jwt_blacklist | table | postgres
--  public | secret_grants | table | postgres
--  public | secrets       | table | postgres
--  public | users         | table | postgres
--  public | vault_members | table | postgres
--  public | vaults        | table | postgres
