-- ============================================================
-- SecretShelf | 07_seed.sql
-- Purpose: Realistic fake data for testing
-- This simulates a real startup team using SecretShelf
-- Run this AFTER all other SQL files
-- ============================================================


-- ============================================================
-- USERS
-- Passwords are bcrypt hashed
-- All test passwords are: Test@1234
-- bcrypt hash below was generated with rounds=12
-- ============================================================

INSERT INTO users (username, email, password_hash, role) VALUES
(
    'arjun_cto',
    'arjun@nimbly.io',
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4tbHMQWWla',
    'owner'
),
(
    'priya_backend',
    'priya@nimbly.io',
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4tbHMQWWla',
    'admin'
),
(
    'ravi_frontend',
    'ravi@nimbly.io',
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4tbHMQWWla',
    'developer'
),
(
    'sara_devops',
    'sara@nimbly.io',
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4tbHMQWWla',
    'developer'
),
(
    'karan_contractor',
    'karan@contractor.dev',
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4tbHMQWWla',
    'viewer'
),
(
    'meera_intern',
    'meera@nimbly.io',
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4tbHMQWWla',
    'viewer'
);


-- ============================================================
-- VAULTS
-- Three vaults matching a real startup setup
-- ============================================================

INSERT INTO vaults (name, description, owner_id) VALUES
(
    'nimbly-production',
    'Live production environment secrets. Handle with care.',
    1  -- arjun_cto is owner
),
(
    'nimbly-staging',
    'Staging environment for testing before production.',
    1
),
(
    'nimbly-development',
    'Development environment. Safe to share with all engineers.',
    1
);


-- ============================================================
-- VAULT MEMBERS
-- Each person gets a role on each vault
-- Notice karan and meera have restricted access
-- ============================================================

INSERT INTO vault_members (vault_id, user_id, role, added_by) VALUES
-- Production vault
(1, 2, 'admin',     1),  -- priya is admin on production
(1, 3, 'developer', 1),  -- ravi is developer on production
(1, 4, 'admin',     1),  -- sara is admin on production
(1, 5, 'viewer',    1),  -- karan is viewer on production only
-- Staging vault
(2, 2, 'admin',     1),
(2, 3, 'developer', 1),
(2, 4, 'admin',     1),
(2, 5, 'developer', 1),  -- karan is developer on staging
(2, 6, 'viewer',    1),  -- meera is viewer on staging only
-- Development vault
(3, 2, 'admin',     1),
(3, 3, 'developer', 1),
(3, 4, 'developer', 1),
(3, 5, 'developer', 1),
(3, 6, 'viewer',    1);


-- ============================================================
-- SECRETS
-- We insert secrets directly here using pgp_sym_encrypt
-- In production Flask calls create_secret procedure instead
-- Encryption key used here: 'test_encryption_key_32_chars!!'
-- Store this same key in your .env as ENCRYPTION_KEY
-- ============================================================

INSERT INTO secrets (vault_id, name, value_enc, description, created_by) VALUES
-- Production secrets
(
    1,
    'STRIPE_SECRET_KEY',
    pgp_sym_encrypt('sk_live_51NxyzABCDEFGHIJKLMN', 'test_encryption_key_32_chars!!'),
    'Stripe live mode secret key for payment processing',
    1
),
(
    1,
    'DATABASE_PASSWORD',
    pgp_sym_encrypt('Xk9#mP2$qLrT5@wN', 'test_encryption_key_32_chars!!'),
    'Production PostgreSQL database password',
    1
),
(
    1,
    'JWT_SIGNING_KEY',
    pgp_sym_encrypt('hs256-prod-super-secret-64-char-signing-key-do-not-share!!', 'test_encryption_key_32_chars!!'),
    'JWT token signing key for production API',
    1
),
(
    1,
    'SENDGRID_API_KEY',
    pgp_sym_encrypt('SG.prod_abc123xyz456def789', 'test_encryption_key_32_chars!!'),
    'SendGrid API key for transactional emails',
    1
),
(
    1,
    'AWS_SECRET_ACCESS_KEY',
    pgp_sym_encrypt('wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', 'test_encryption_key_32_chars!!'),
    'AWS secret key for S3 bucket access',
    1
),
-- Staging secrets
(
    2,
    'STRIPE_SECRET_KEY',
    pgp_sym_encrypt('sk_test_51NxyzTESTKEYABCDEFGHIJ', 'test_encryption_key_32_chars!!'),
    'Stripe test mode secret key',
    1
),
(
    2,
    'DATABASE_PASSWORD',
    pgp_sym_encrypt('staging_db_pass_2024', 'test_encryption_key_32_chars!!'),
    'Staging PostgreSQL database password',
    1
),
(
    2,
    'SENDGRID_API_KEY',
    pgp_sym_encrypt('SG.staging_abc123xyz', 'test_encryption_key_32_chars!!'),
    'SendGrid API key for staging emails',
    2
),
-- Development secrets
(
    3,
    'STRIPE_SECRET_KEY',
    pgp_sym_encrypt('sk_test_devmode_abc123', 'test_encryption_key_32_chars!!'),
    'Stripe test key for local development',
    2
),
(
    3,
    'DATABASE_PASSWORD',
    pgp_sym_encrypt('dev_local_password_123', 'test_encryption_key_32_chars!!'),
    'Local development database password',
    3
),
(
    3,
    'OPENAI_API_KEY',
    pgp_sym_encrypt('sk-proj-devtest-abc123xyz456', 'test_encryption_key_32_chars!!'),
    'OpenAI API key for AI features in development',
    2
);


-- ============================================================
-- SECRET GRANTS
-- Karan (viewer) gets explicit access to only 2 secrets
-- Meera (viewer) gets access to only 1 secret
-- Everyone else gets access through vault_members role
-- ============================================================

INSERT INTO secret_grants (secret_id, user_id, can_reveal, can_rotate, granted_by)
VALUES
(9,  5, TRUE,  FALSE, 1),  -- karan can reveal dev STRIPE key
(10, 5, TRUE,  FALSE, 1),  -- karan can reveal dev DATABASE_PASSWORD
(9,  6, TRUE,  FALSE, 1),  -- meera can reveal dev STRIPE key only
(11, 6, FALSE, FALSE, 1);  -- meera can see OPENAI key exists but cannot reveal


-- ============================================================
-- VERIFY: Run these to confirm seed data
-- ============================================================

-- SELECT id, username, role, is_active FROM users;
-- SELECT id, name, owner_id FROM vaults;
-- SELECT id, name, vault_id, status FROM secrets;
-- SELECT name, encode(value_enc, 'hex') FROM secrets LIMIT 3;
-- The last query shows encrypted values as hex -- unreadable gibberish
