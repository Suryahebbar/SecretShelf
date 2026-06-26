-- ============================================================
-- SecretShelf | 05_triggers.sql
-- Purpose: Automatic audit logging via triggers
-- Triggers fire automatically on table events
-- The application does not need to do anything
-- Even if someone bypasses Flask and queries directly
-- every access is still logged
-- ============================================================


-- ============================================================
-- TRIGGER FUNCTION: log_secret_access
-- Fires after any INSERT, UPDATE, DELETE on secrets table
-- Writes one row to access_log automatically
-- ============================================================

CREATE OR REPLACE FUNCTION log_secret_access()
RETURNS TRIGGER
LANGUAGE plpgsql AS $$
DECLARE
    v_user_id   INT;
    v_action    audit_action;
BEGIN
    -- Read the current user from session variable
    -- Flask sets this before every query
    -- If not set, defaults to NULL
    v_user_id := current_setting('app.current_user_id', TRUE)::INT;

    -- Map the trigger operation to our audit_action enum
    IF TG_OP = 'INSERT' THEN
        v_action := 'CREATED';
    ELSIF TG_OP = 'UPDATE' THEN
        -- Check what kind of update this is
        IF NEW.status = 'deleted' THEN
            v_action := 'DELETED';
        ELSIF NEW.status = 'rotated' THEN
            v_action := 'ROTATED';
        ELSE
            v_action := 'ROTATED';
        END IF;
    ELSIF TG_OP = 'DELETE' THEN
        v_action := 'DELETED';
    END IF;

    -- Write the log entry
    INSERT INTO access_log (
        user_id,
        action,
        secret_id,
        vault_id,
        metadata
    ) VALUES (
        v_user_id,
        v_action,
        -- For DELETE, NEW does not exist so we use OLD
        COALESCE(NEW.id, OLD.id),
        COALESCE(NEW.vault_id, OLD.vault_id),
        jsonb_build_object(
            'secret_name',  COALESCE(NEW.name, OLD.name),
            'operation',    TG_OP,
            'old_status',   OLD.status,
            'new_status',   NEW.status
        )
    );

    RETURN NEW;

EXCEPTION WHEN OTHERS THEN
    -- If logging fails for any reason
    -- we still allow the original operation to complete
    -- Logging should never block actual work
    RAISE WARNING 'Audit log failed: %', SQLERRM;
    RETURN NEW;
END;
$$;


-- ============================================================
-- ATTACH TRIGGER TO secrets TABLE
-- AFTER means the log is written after the operation succeeds
-- We do not want to log failed operations
-- FOR EACH ROW means one log entry per affected row
-- ============================================================

CREATE TRIGGER secrets_audit_trigger
    AFTER INSERT OR UPDATE OR DELETE
    ON secrets
    FOR EACH ROW
    EXECUTE FUNCTION log_secret_access();


-- ============================================================
-- TRIGGER FUNCTION: log_secret_revealed
-- This is separate from the above
-- It fires when a secret is REVEALED (decrypted and shown)
-- Revealing is a SELECT -- triggers do not fire on SELECT
-- So Flask calls this function explicitly after decryption
-- ============================================================

CREATE OR REPLACE FUNCTION log_secret_revealed(
    p_secret_id     INT,
    p_user_id       INT,
    p_vault_id      INT,
    p_secret_name   TEXT,
    p_ip_address    INET DEFAULT NULL
)
RETURNS VOID
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO access_log (
        user_id,
        action,
        secret_id,
        vault_id,
        ip_address,
        metadata
    ) VALUES (
        p_user_id,
        'REVEALED',
        p_secret_id,
        p_vault_id,
        p_ip_address,
        jsonb_build_object(
            'secret_name', p_secret_name,
            'revealed_at', NOW()
        )
    );
END;
$$;


-- ============================================================
-- TRIGGER FUNCTION: update_secrets_timestamp
-- Automatically updates updated_at column on every UPDATE
-- So Flask never needs to manually set this field
-- ============================================================

CREATE OR REPLACE FUNCTION update_secrets_timestamp()
RETURNS TRIGGER
LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at := NOW();
    RETURN NEW;
END;
$$;

CREATE TRIGGER secrets_timestamp_trigger
    BEFORE UPDATE
    ON secrets
    FOR EACH ROW
    EXECUTE FUNCTION update_secrets_timestamp();


-- ============================================================
-- TRIGGER FUNCTION: prevent_audit_log_tampering
-- Extra protection on access_log
-- Raises an error if anyone tries to UPDATE or DELETE
-- a log entry through any means
-- ============================================================

CREATE OR REPLACE FUNCTION prevent_audit_tampering()
RETURNS TRIGGER
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION
        'Audit log is immutable. DELETE and UPDATE are not permitted on access_log.'
        USING ERRCODE = '42501';
    RETURN NULL;
END;
$$;

CREATE TRIGGER audit_log_immutable
    BEFORE UPDATE OR DELETE
    ON access_log
    FOR EACH ROW
    EXECUTE FUNCTION prevent_audit_tampering();


-- ============================================================
-- VERIFY: Run these after executing the file
-- ============================================================

-- Check triggers exist:
-- SELECT trigger_name, event_manipulation, event_object_table
-- FROM information_schema.triggers
-- WHERE trigger_schema = 'public'
-- ORDER BY event_object_table;
