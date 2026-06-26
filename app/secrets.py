# ============================================================
# SecretShelf | app/secrets.py
# Purpose: Secret CRUD routes
# All routes here are protected by @token_required
# RLS policies enforce what each role can actually see
# ============================================================

import os
from flask import Blueprint, request, jsonify
from .db import get_connection, return_connection, set_session_context
from .middleware import token_required
from dotenv import load_dotenv

load_dotenv()

secrets_bp = Blueprint('secrets', __name__)


# ============================================================
# ROUTE: GET /api/vaults
# Get all vaults the current user has access to
# RLS automatically filters -- user only sees their vaults
# ============================================================

@secrets_bp.route('/api/vaults', methods=['GET'])
@token_required
def get_vaults(current_user):
    conn = get_connection()
    try:
        cursor = conn.cursor()

        # Set session context for RLS
        set_session_context(
            cursor,
            current_user['id'],
            current_user['role']
        )

        cursor.execute(
            """
            SELECT
                v.id,
                v.name,
                v.description,
                v.created_at,
                vm.role as my_role,
                COUNT(s.id) as secret_count
            FROM vaults v
            LEFT JOIN vault_members vm
                ON vm.vault_id = v.id
                AND vm.user_id = %s
            LEFT JOIN secrets s
                ON s.vault_id = v.id
                AND s.status = 'active'
            WHERE v.is_active = TRUE
            GROUP BY v.id, v.name, v.description, v.created_at, vm.role
            ORDER BY v.created_at DESC
            """,
            (current_user['id'],)
        )

        vaults = cursor.fetchall()
        cursor.close()

        return jsonify({
            'vaults': [
                {
                    'id':           row[0],
                    'name':         row[1],
                    'description':  row[2],
                    'created_at':   row[3].isoformat(),
                    'my_role':      row[4],
                    'secret_count': row[5]
                }
                for row in vaults
            ]
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        return_connection(conn)


# ============================================================
# ROUTE: POST /api/vaults
# Create a new vault
# Only owners and admins can create vaults
# ============================================================

@secrets_bp.route('/api/vaults', methods=['POST'])
@token_required
def create_vault(current_user):
    if current_user['role'] not in ('owner', 'admin'):
        return jsonify({
            'error': 'Permission denied',
            'message': 'Only owners and admins can create vaults'
        }), 403

    data = request.get_json()
    if not data.get('name'):
        return jsonify({'error': 'Vault name is required'}), 400

    conn = get_connection()
    try:
        cursor = conn.cursor()

        set_session_context(
            cursor,
            current_user['id'],
            current_user['role']
        )

        cursor.execute(
            """
            INSERT INTO vaults (name, description, owner_id)
            VALUES (%s, %s, %s)
            RETURNING id, name, created_at
            """,
            (
                data['name'].strip(),
                data.get('description', ''),
                current_user['id']
            )
        )
        vault = cursor.fetchone()

        # Automatically add creator as owner in vault_members
        cursor.execute(
            """
            INSERT INTO vault_members (vault_id, user_id, role, added_by)
            VALUES (%s, %s, 'owner', %s)
            """,
            (vault[0], current_user['id'], current_user['id'])
        )

        conn.commit()
        cursor.close()

        return jsonify({
            'message': 'Vault created successfully',
            'vault': {
                'id':         vault[0],
                'name':       vault[1],
                'created_at': vault[2].isoformat()
            }
        }), 201

    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        return_connection(conn)


# ============================================================
# ROUTE: GET /api/vaults/<vault_id>/secrets
# List all secrets in a vault
# Values are NOT returned here -- only names and metadata
# User must explicitly call reveal to get the value
# ============================================================

@secrets_bp.route('/api/vaults/<int:vault_id>/secrets', methods=['GET'])
@token_required
def get_secrets(current_user, vault_id):
    conn = get_connection()
    try:
        cursor = conn.cursor()

        set_session_context(
            cursor,
            current_user['id'],
            current_user['role']
        )

        # RLS automatically filters rows here
        # A viewer only sees secrets they have grants for
        # A developer sees all active secrets in their vaults
        cursor.execute(
            """
            SELECT
                id,
                name,
                description,
                status,
                expires_at,
                created_at,
                updated_at
            FROM secrets
            WHERE vault_id = %s
            AND status = 'active'
            ORDER BY name ASC
            """,
            (vault_id,)
        )

        secrets = cursor.fetchall()
        cursor.close()

        return jsonify({
            'secrets': [
                {
                    'id':          row[0],
                    'name':        row[1],
                    'description': row[2],
                    'status':      row[3],
                    'expires_at':  row[4].isoformat() if row[4] else None,
                    'created_at':  row[5].isoformat(),
                    'updated_at':  row[6].isoformat(),
                    'value':       '••••••••'  # never return value in list
                }
                for row in secrets
            ]
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        return_connection(conn)


# ============================================================
# ROUTE: POST /api/vaults/<vault_id>/secrets
# Create a new secret in a vault
# Value is encrypted via stored procedure
# ============================================================

@secrets_bp.route('/api/vaults/<int:vault_id>/secrets', methods=['POST'])
@token_required
def create_secret(current_user, vault_id):
    if current_user['role'] not in ('owner', 'admin', 'developer'):
        return jsonify({
            'error': 'Permission denied',
            'message': 'Viewers cannot create secrets'
        }), 403

    data = request.get_json()

    if not data.get('name') or not data.get('value'):
        return jsonify({'error': 'Name and value are required'}), 400

    conn = get_connection()
    try:
        cursor = conn.cursor()

        set_session_context(
            cursor,
            current_user['id'],
            current_user['role']
        )

        # Call stored procedure -- handles encryption + audit log
        cursor.execute(
            "CALL create_secret(%s, %s, %s, %s, %s, %s)",
            (
                vault_id,
                data['name'].strip().upper(),
                data['value'],
                data.get('description', ''),
                current_user['id'],
                os.getenv('ENCRYPTION_KEY')
            )
        )

        conn.commit()
        cursor.close()

        return jsonify({
            'message': f'Secret {data["name"].upper()} created successfully'
        }), 201

    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        return_connection(conn)


# ============================================================
# ROUTE: GET /api/secrets/<secret_id>/reveal
# Decrypt and return the secret value
# This is the most sensitive operation
# Every reveal is logged by log_secret_revealed function
# ============================================================

@secrets_bp.route('/api/secrets/<int:secret_id>/reveal', methods=['GET'])
@token_required
def reveal_secret(current_user, secret_id):
    conn = get_connection()
    try:
        cursor = conn.cursor()

        set_session_context(
            cursor,
            current_user['id'],
            current_user['role']
        )

        # Decrypt the value using pgp_sym_decrypt
        # RLS ensures user can only reach rows they are allowed to
        cursor.execute(
            """
            SELECT
                s.id,
                s.name,
                s.vault_id,
                pgp_sym_decrypt(s.value_enc, %s) as value,
                s.expires_at
            FROM secrets s
            WHERE s.id = %s
            AND s.status = 'active'
            """,
            (os.getenv('ENCRYPTION_KEY'), secret_id)
        )

        secret = cursor.fetchone()

        if not secret:
            return jsonify({
                'error': 'Secret not found or access denied'
            }), 404

        # Check expiry
        if secret[4] and secret[4] < __import__('datetime').datetime.utcnow():
            return jsonify({
                'error': 'Secret has expired',
                'message': 'This secret needs to be rotated'
            }), 410

        # Log the reveal via function
        # Triggers do not fire on SELECT so we call this manually
        ip_address = request.remote_addr
        cursor.execute(
            "SELECT log_secret_revealed(%s, %s, %s, %s, %s::INET)",
            (
                secret[0],
                current_user['id'],
                secret[2],
                secret[1],
                ip_address
            )
        )

        conn.commit()
        cursor.close()

        return jsonify({
            'id':    secret[0],
            'name':  secret[1],
            'value': secret[3]  # decrypted plaintext
        }), 200

    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        return_connection(conn)


# ============================================================
# ROUTE: PUT /api/secrets/<secret_id>/rotate
# Update the encrypted value of a secret
# Old value is replaced -- rotation is logged
# ============================================================

@secrets_bp.route('/api/secrets/<int:secret_id>/rotate', methods=['PUT'])
@token_required
def rotate_secret(current_user, secret_id):
    if current_user['role'] not in ('owner', 'admin'):
        return jsonify({
            'error': 'Permission denied',
            'message': 'Only owners and admins can rotate secrets'
        }), 403

    data = request.get_json()
    if not data.get('new_value'):
        return jsonify({'error': 'new_value is required'}), 400

    conn = get_connection()
    try:
        cursor = conn.cursor()

        set_session_context(
            cursor,
            current_user['id'],
            current_user['role']
        )

        cursor.execute(
            "CALL rotate_secret(%s, %s, %s, %s)",
            (
                secret_id,
                data['new_value'],
                current_user['id'],
                os.getenv('ENCRYPTION_KEY')
            )
        )

        conn.commit()
        cursor.close()

        return jsonify({
            'message': 'Secret rotated successfully'
        }), 200

    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        return_connection(conn)


# ============================================================
# ROUTE: DELETE /api/secrets/<secret_id>
# Soft delete -- sets status to deleted
# Secret disappears from all views but audit trail remains
# ============================================================

@secrets_bp.route('/api/secrets/<int:secret_id>', methods=['DELETE'])
@token_required
def delete_secret(current_user, secret_id):
    if current_user['role'] not in ('owner', 'admin'):
        return jsonify({
            'error': 'Permission denied',
            'message': 'Only owners and admins can delete secrets'
        }), 403

    conn = get_connection()
    try:
        cursor = conn.cursor()

        set_session_context(
            cursor,
            current_user['id'],
            current_user['role']
        )

        cursor.execute(
            "CALL soft_delete_secret(%s, %s)",
            (secret_id, current_user['id'])
        )

        conn.commit()
        cursor.close()

        return jsonify({
            'message': 'Secret deleted successfully'
        }), 200

    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        return_connection(conn)


# ============================================================
# ROUTE: GET /api/audit
# View audit log for admin and owner only
# Uses CTE for forensic querying
# ============================================================

@secrets_bp.route('/api/audit', methods=['GET'])
@token_required
def get_audit_log(current_user):
    if current_user['role'] not in ('owner', 'admin'):
        return jsonify({
            'error': 'Permission denied',
            'message': 'Only owners and admins can view audit logs'
        }), 403

    conn = get_connection()
    try:
        cursor = conn.cursor()

        set_session_context(
            cursor,
            current_user['id'],
            current_user['role']
        )

        # CTE for readable audit query
        cursor.execute(
            """
            WITH audit_details AS (
                SELECT
                    al.id,
                    al.action,
                    al.accessed_at,
                    al.ip_address,
                    al.metadata,
                    u.username,
                    s.name as secret_name,
                    v.name as vault_name
                FROM access_log al
                LEFT JOIN users u ON u.id = al.user_id
                LEFT JOIN secrets s ON s.id = al.secret_id
                LEFT JOIN vaults v ON v.id = al.vault_id
            )
            SELECT *
            FROM audit_details
            ORDER BY accessed_at DESC
            LIMIT 100
            """
        )

        logs = cursor.fetchall()
        cursor.close()

        return jsonify({
            'audit_log': [
                {
                    'id':          row[0],
                    'action':      row[1],
                    'accessed_at': row[2].isoformat(),
                    'ip_address':  str(row[3]) if row[3] else None,
                    'metadata':    row[4],
                    'username':    row[5],
                    'secret_name': row[6],
                    'vault_name':  row[7]
                }
                for row in logs
            ]
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        return_connection(conn)
