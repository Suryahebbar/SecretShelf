-- ============================================================
-- SecretShelf | 03_rls.sql
-- Purpose: Row-Level Security policies
-- RLS controls WHICH ROWS a role can see
-- 02_roles.sql controlled WHICH TABLES they can access
-- Together they form the complete access control system
-- ============================================================


-- ============================================================
-- ENABLE RLS ON ALL SENSITIVE TABLES
-- Once RLS is enabled on a table, ALL access goes through
-- the policies defined below
-- If no policy matches, zero rows are returned -- not an error
-- This is the "default deny" principle
-- ============================================================

ALTER TABLE secrets ENABLE ROW LEVEL SECURITY;
ALTER TABLE vaults ENABLE ROW LEVEL SECURITY;
ALTER TABLE vault_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE secret_grants ENABLE ROW LEVEL SECURITY;


-- ============================================================
-- BYPASS RLS FOR POSTGRES SUPERUSER
-- The postgres superuser bypasses RLS by default
-- This is fine -- postgres is only used for setup
-- never for application connections
-- ============================================================


-- ============================================================
-- HOW RLS WORKS IN THIS PROJECT
-- Flask sets a session variable before every query:
--   SET app.current_user_id = 5;
--   SET app.current_user_role = 'developer';
-- RLS policies read these variables to make decisions
-- If these variables are not set, no rows are returned
-- ============================================================


-- ============================================================
-- POLICIES ON: vaults
-- ============================================================

-- Owner can see all their own vaults
CREATE POLICY owner_sees_own_vaults ON vaults
    FOR ALL
    TO secretshelf_owner
    USING (
        owner_id = current_setting('app.current_user_id', TRUE)::INT
    );

-- Admin, Developer, Viewer can see vaults they are members of
CREATE POLICY members_see_their_vaults ON vaults
    FOR SELECT
    TO secretshelf_admin, secretshelf_developer, secretshelf_viewer
    USING (
        id IN (
            SELECT vault_id
            FROM vault_members
            WHERE user_id = current_setting('app.current_user_id', TRUE)::INT
        )
    );

-- Admin can update vault details for vaults they are members of
CREATE POLICY admin_update_vaults ON vaults
    FOR UPDATE
    TO secretshelf_admin
    USING (
        id IN (
            SELECT vault_id
            FROM vault_members
            WHERE user_id = current_setting('app.current_user_id', TRUE)::INT
            AND role = 'admin'
        )
    );


-- ============================================================
-- POLICIES ON: vault_members
-- ============================================================

-- Owner sees all members of their vaults
CREATE POLICY owner_sees_vault_members ON vault_members
    FOR ALL
    TO secretshelf_owner
    USING (
        vault_id IN (
            SELECT id FROM vaults
            WHERE owner_id = current_setting('app.current_user_id', TRUE)::INT
        )
    );

-- Admin sees members of vaults they administer
CREATE POLICY admin_sees_vault_members ON vault_members
    FOR SELECT
    TO secretshelf_admin
    USING (
        vault_id IN (
            SELECT vault_id FROM vault_members
            WHERE user_id = current_setting('app.current_user_id', TRUE)::INT
            AND role = 'admin'
        )
    );

-- Admin can add members to vaults they administer
CREATE POLICY admin_insert_vault_members ON vault_members
    FOR INSERT
    TO secretshelf_admin
    WITH CHECK (
        vault_id IN (
            SELECT vault_id FROM vault_members
            WHERE user_id = current_setting('app.current_user_id', TRUE)::INT
            AND role = 'admin'
        )
    );

-- Developer and Viewer can only see their own membership row
CREATE POLICY dev_viewer_sees_own_membership ON vault_members
    FOR SELECT
    TO secretshelf_developer, secretshelf_viewer
    USING (
        user_id = current_setting('app.current_user_id', TRUE)::INT
    );


-- ============================================================
-- POLICIES ON: secrets
-- This is the most important table
-- ============================================================

-- Owner sees ALL secrets in their vaults
CREATE POLICY owner_sees_all_secrets ON secrets
    FOR ALL
    TO secretshelf_owner
    USING (
        vault_id IN (
            SELECT id FROM vaults
            WHERE owner_id = current_setting('app.current_user_id', TRUE)::INT
        )
    );

-- Admin sees all secrets in vaults they administer
CREATE POLICY admin_sees_secrets ON secrets
    FOR ALL
    TO secretshelf_admin
    USING (
        vault_id IN (
            SELECT vault_id FROM vault_members
            WHERE user_id = current_setting('app.current_user_id', TRUE)::INT
            AND role = 'admin'
        )
    );

-- Developer sees secrets in their vaults
-- BUT only active secrets -- not deleted or expired ones
CREATE POLICY developer_sees_secrets ON secrets
    FOR SELECT
    TO secretshelf_developer
    USING (
        vault_id IN (
            SELECT vault_id FROM vault_members
            WHERE user_id = current_setting('app.current_user_id', TRUE)::INT
            AND role IN ('developer')
        )
        AND status = 'active'
    );

-- Developer can insert new secrets into their vaults
CREATE POLICY developer_insert_secrets ON secrets
    FOR INSERT
    TO secretshelf_developer
    WITH CHECK (
        vault_id IN (
            SELECT vault_id FROM vault_members
            WHERE user_id = current_setting('app.current_user_id', TRUE)::INT
            AND role = 'developer'
        )
    );

-- Viewer sees ONLY secrets they have been explicitly granted
-- Even if they are a member of the vault
-- they cannot see secrets without a secret_grant row
CREATE POLICY viewer_sees_granted_secrets ON secrets
    FOR SELECT
    TO secretshelf_viewer
    USING (
        id IN (
            SELECT secret_id FROM secret_grants
            WHERE user_id = current_setting('app.current_user_id', TRUE)::INT
            AND can_reveal = TRUE
        )
        AND status = 'active'
    );


-- ============================================================
-- POLICIES ON: secret_grants
-- ============================================================

-- Owner manages all grants in their vaults
CREATE POLICY owner_manages_grants ON secret_grants
    FOR ALL
    TO secretshelf_owner
    USING (
        secret_id IN (
            SELECT s.id FROM secrets s
            JOIN vaults v ON v.id = s.vault_id
            WHERE v.owner_id = current_setting('app.current_user_id', TRUE)::INT
        )
    );

-- Admin manages grants for secrets in their vaults
CREATE POLICY admin_manages_grants ON secret_grants
    FOR ALL
    TO secretshelf_admin
    USING (
        secret_id IN (
            SELECT s.id FROM secrets s
            JOIN vault_members vm ON vm.vault_id = s.vault_id
            WHERE vm.user_id = current_setting('app.current_user_id', TRUE)::INT
            AND vm.role = 'admin'
        )
    );

-- Developer and Viewer can only see their own grants
CREATE POLICY dev_viewer_sees_own_grants ON secret_grants
    FOR SELECT
    TO secretshelf_developer, secretshelf_viewer
    USING (
        user_id = current_setting('app.current_user_id', TRUE)::INT
    );


-- ============================================================
-- VERIFY: Run these after executing the file
-- ============================================================

-- Check RLS is enabled on tables:
-- SELECT tablename, rowsecurity FROM pg_tables
-- WHERE schemaname = 'public'
-- AND tablename IN ('secrets', 'vaults', 'vault_members', 'secret_grants');

-- Expected: rowsecurity = true for all 4 tables
