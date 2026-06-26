-- ============================================================
-- SecretShelf | 06_indexes.sql
-- Purpose: Indexes for performance and security
-- Indexes speed up queries that RLS policies run constantly
-- Without indexes, every RLS check does a full table scan
-- With indexes, lookups are near-instant
-- ============================================================


-- ============================================================
-- INDEXES ON: users
-- ============================================================

-- Login query: WHERE username = ? AND is_active = TRUE
-- Partial index -- only indexes active users
-- Inactive users are never queried during login
-- smaller index = faster lookups
CREATE INDEX idx_users_username_active
    ON users (username)
    WHERE is_active = TRUE;

-- Role-based lookups
CREATE INDEX idx_users_role
    ON users (role);

-- Lockout check: WHERE locked_until > NOW()
CREATE INDEX idx_users_locked
    ON users (locked_until)
    WHERE locked_until IS NOT NULL;


-- ============================================================
-- INDEXES ON: vaults
-- ============================================================

-- RLS policy checks owner_id constantly
CREATE INDEX idx_vaults_owner
    ON vaults (owner_id);

-- Only active vaults are ever queried by the app
CREATE INDEX idx_vaults_active
    ON vaults (owner_id)
    WHERE is_active = TRUE;


-- ============================================================
-- INDEXES ON: vault_members
-- ============================================================

-- RLS policies do: WHERE user_id = ? constantly
CREATE INDEX idx_vault_members_user
    ON vault_members (user_id);

-- And also: WHERE vault_id = ?
CREATE INDEX idx_vault_members_vault
    ON vault_members (vault_id);

-- Combined: WHERE user_id = ? AND role = ?
CREATE INDEX idx_vault_members_user_role
    ON vault_members (user_id, role);


-- ============================================================
-- INDEXES ON: secrets
-- ============================================================

-- Most queries filter by vault_id
CREATE INDEX idx_secrets_vault
    ON secrets (vault_id);

-- RLS filters active secrets constantly
-- Partial index -- deleted and rotated secrets not included
CREATE INDEX idx_secrets_vault_active
    ON secrets (vault_id)
    WHERE status = 'active';

-- Expiry check -- finding secrets that need to expire
CREATE INDEX idx_secrets_expiry
    ON secrets (expires_at)
    WHERE expires_at IS NOT NULL;

-- Creator lookups for audit purposes
CREATE INDEX idx_secrets_created_by
    ON secrets (created_by);


-- ============================================================
-- INDEXES ON: secret_grants
-- ============================================================

-- RLS policy: WHERE user_id = ? AND can_reveal = TRUE
CREATE INDEX idx_grants_user
    ON secret_grants (user_id);

-- Lookup grants for a specific secret
CREATE INDEX idx_grants_secret
    ON secret_grants (secret_id);

-- Combined for the viewer RLS policy
-- which checks both user_id and can_reveal together
CREATE INDEX idx_grants_user_reveal
    ON secret_grants (user_id, can_reveal)
    WHERE can_reveal = TRUE;


-- ============================================================
-- INDEXES ON: access_log
-- ============================================================

-- Forensic queries: WHERE accessed_at BETWEEN ? AND ?
-- DESC because most queries want recent events first
CREATE INDEX idx_audit_time
    ON access_log (accessed_at DESC);

-- Per-user audit: WHERE user_id = ? ORDER BY accessed_at DESC
CREATE INDEX idx_audit_user_time
    ON access_log (user_id, accessed_at DESC);

-- Per-secret audit: WHERE secret_id = ?
CREATE INDEX idx_audit_secret
    ON access_log (secret_id);

-- Per-vault audit: WHERE vault_id = ?
CREATE INDEX idx_audit_vault
    ON access_log (vault_id, accessed_at DESC);

-- Action-based queries: WHERE action = 'REVEALED'
CREATE INDEX idx_audit_action
    ON access_log (action);


-- ============================================================
-- INDEXES ON: jwt_blacklist
-- ============================================================

-- Middleware checks this on EVERY request
-- token_hash already has a UNIQUE constraint which creates
-- an index automatically -- but we add expiry index for cleanup
CREATE INDEX idx_jwt_expiry
    ON jwt_blacklist (expires_at);


-- ============================================================
-- VERIFY: Run this after executing the file
-- ============================================================

-- SELECT indexname, tablename
-- FROM pg_indexes
-- WHERE schemaname = 'public'
-- ORDER BY tablename, indexname;
