-- ============================================================
-- SecretShelf | 04_procedures.sql
-- Purpose: Stored procedures for core business logic
-- Procedures run INSIDE PostgreSQL
-- They are atomic -- either everything succeeds or nothing does
-- This is important for security operations
-- ============================================================


-- ============================================================
-- PROCEDURE: create_secret
-- Creates a new secret with encryption in one atomic transaction
-- If encryption fails, the insert never happens
-- If the insert fails, nothing is written
-- ============================================================

CREATE OR REPLACE PROCEDURE create_secret(
    p_vault_id      INT,
    p_name          TEXT,
    p_value         TEXT,
    p_description   TEXT,
    p_created_by    INT,
    p_enc_key       TEXT,
    p_expires_at    TIMESTAMP DEFAULT NULL
)
LANGUAGE plpgsql AS $$
DECLARE
    v_secret_id INT;
    v_vault_exists BOOLEAN;
BEGIN
    -- Step 1: Verify vault exists and is active
    SELECT EXISTS(
        SELECT 1 FROM vaults
        WHERE id = p_vault_id
        AND is_active = TRUE
    ) INTO v_vault_exists;

    IF NOT v_vault_exists THEN
        RAISE EXCEPTION 'Vault % does not exist or is inactive', p_vault_id;
    END IF;

    -- Step 2: Check secret name does not already exist in this vault
    IF EXISTS (
        SELECT 1 FROM secrets
        WHERE vault_id = p_vault_id
        AND name = p_name
        AND status = 'active'
    ) THEN
        RAISE EXCEPTION 'Secret named "%" already exists in this vault', p_name;
    END IF;

    -- Step 3: Encrypt and insert the secret
    -- pgp_sym_encrypt encrypts p_value using p_enc_key
    -- the result is BYTEA -- binary data, not readable text
    INSERT INTO secrets (
        vault_id,
        name,
        value_enc,
        description,
        created_by,
        updated_by,
        expires_at
    ) VALUES (
        p_vault_id,
        p_name,
        pgp_sym_encrypt(p_value, p_enc_key),
        p_description,
        p_created_by,
        p_created_by,
        p_expires_at
    )
    RETURNING id INTO v_secret_id;

    -- Step 4: Log the creation
    -- This is the only place besides triggers that writes to access_log
    INSERT INTO access_log (
        user_id,
        action,
        secret_id,
        vault_id,
        metadata
    ) VALUES (
        p_created_by,
        'CREATED',
        v_secret_id,
        p_vault_id,
        jsonb_build_object(
            'secret_name', p_name,
            'has_expiry', p_expires_at IS NOT NULL
        )
    );

    RAISE NOTICE 'Secret "%" created with ID: %', p_name, v_secret_id;
END;
$$;


-- ============================================================
-- PROCEDURE: rotate_secret
-- Updates the encrypted value of an existing secret
-- Old value is gone -- replaced with new ciphertext
-- Rotation is logged automatically
-- ============================================================

CREATE OR REPLACE PROCEDURE rotate_secret(
    p_secret_id     INT,
    p_new_value     TEXT,
    p_rotated_by    INT,
    p_enc_key       TEXT
)
LANGUAGE plpgsql AS $$
DECLARE
    v_vault_id INT;
    v_secret_name TEXT;
BEGIN
    -- Step 1: Get secret details and verify it exists
    SELECT vault_id, name
    INTO v_vault_id, v_secret_name
    FROM secrets
    WHERE id = p_secret_id
    AND status = 'active';

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Secret % not found or already deleted', p_secret_id;
    END IF;

    -- Step 2: Update with new encrypted value
    UPDATE secrets SET
        value_enc   = pgp_sym_encrypt(p_new_value, p_enc_key),
        status      = 'rotated',
        updated_by  = p_rotated_by,
        updated_at  = NOW()
    WHERE id = p_secret_id;

    -- Step 3: Insert new active version
    -- After rotation we insert a fresh active row
    -- so the secret remains accessible with the new value
    INSERT INTO secrets (
        vault_id,
        name,
        value_enc,
        description,
        created_by,
        updated_by,
        status
    )
    SELECT
        vault_id,
        name,
        pgp_sym_encrypt(p_new_value, p_enc_key),
        description,
        p_rotated_by,
        p_rotated_by,
        'active'
    FROM secrets
    WHERE id = p_secret_id;

    -- Step 4: Log the rotation
    INSERT INTO access_log (
        user_id,
        action,
        secret_id,
        vault_id,
        metadata
    ) VALUES (
        p_rotated_by,
        'ROTATED',
        p_secret_id,
        v_vault_id,
        jsonb_build_object('secret_name', v_secret_name)
    );

    RAISE NOTICE 'Secret "%" rotated successfully', v_secret_name;
END;
$$;


-- ============================================================
-- PROCEDURE: soft_delete_secret
-- Never hard deletes a secret
-- Sets status to deleted so it disappears from all views
-- Audit trail is preserved
-- ============================================================

CREATE OR REPLACE PROCEDURE soft_delete_secret(
    p_secret_id     INT,
    p_deleted_by    INT
)
LANGUAGE plpgsql AS $$
DECLARE
    v_vault_id  INT;
    v_name      TEXT;
BEGIN
    SELECT vault_id, name
    INTO v_vault_id, v_name
    FROM secrets
    WHERE id = p_secret_id
    AND status = 'active';

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Secret % not found or already deleted', p_secret_id;
    END IF;

    UPDATE secrets SET
        status      = 'deleted',
        updated_by  = p_deleted_by,
        updated_at  = NOW()
    WHERE id = p_secret_id;

    INSERT INTO access_log (
        user_id,
        action,
        secret_id,
        vault_id,
        metadata
    ) VALUES (
        p_deleted_by,
        'DELETED',
        p_secret_id,
        v_vault_id,
        jsonb_build_object('secret_name', v_name)
    );

    RAISE NOTICE 'Secret "%" soft deleted', v_name;
END;
$$;


-- ============================================================
-- PROCEDURE: record_failed_login
-- Called every time a wrong password is submitted
-- Increments failed_attempts counter
-- Locks account after 5 failures for 15 minutes
-- ============================================================

CREATE OR REPLACE PROCEDURE record_failed_login(
    p_username TEXT
)
LANGUAGE plpgsql AS $$
DECLARE
    v_user_id       INT;
    v_attempts      INT;
BEGIN
    -- Get current attempt count
    SELECT id, failed_attempts
    INTO v_user_id, v_attempts
    FROM users
    WHERE username = p_username;

    IF NOT FOUND THEN
        -- Username does not exist
        -- We still raise notice but do nothing
        -- This prevents username enumeration via timing
        RAISE NOTICE 'Login attempt for unknown user';
        RETURN;
    END IF;

    -- Increment counter
    v_attempts := v_attempts + 1;

    UPDATE users SET
        failed_attempts = v_attempts,
        locked_until = CASE
            -- Lock for 15 minutes after 5 failures
            WHEN v_attempts >= 5
            THEN NOW() + INTERVAL '15 minutes'
            ELSE locked_until
        END
    WHERE id = v_user_id;

    -- Log the failed attempt
    INSERT INTO access_log (
        user_id,
        action,
        metadata
    ) VALUES (
        v_user_id,
        'FAILED_LOGIN',
        jsonb_build_object(
            'attempt_number', v_attempts,
            'locked', v_attempts >= 5
        )
    );

    IF v_attempts >= 5 THEN
        RAISE NOTICE 'Account % locked for 15 minutes', p_username;
    END IF;
END;
$$;


-- ============================================================
-- PROCEDURE: reset_failed_attempts
-- Called after a successful login
-- Clears the lockout counter
-- ============================================================

CREATE OR REPLACE PROCEDURE reset_failed_attempts(
    p_user_id INT
)
LANGUAGE plpgsql AS $$
BEGIN
    UPDATE users SET
        failed_attempts = 0,
        locked_until    = NULL,
        last_login      = NOW()
    WHERE id = p_user_id;
END;
$$;


-- ============================================================
-- VERIFY: Run this after executing the file
-- \df
-- You should see all 5 procedures listed
-- ============================================================
