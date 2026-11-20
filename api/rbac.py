"""Role-Based Access Control decorators and helpers for VaultAuth SSO."""

from functools import wraps
from flask import g, jsonify
from api.db import execute_query
from api.utils import safe_print

ROLES = {
    "user": 1,
    "admin": 2,
}

VALID_ROLES = set(ROLES.keys())


def get_user_role(uid):
    """Fetch the role of a user from the database."""
    try:
        rows = execute_query("SELECT role FROM users WHERE uid = %s", (uid,))
        if rows and len(rows) > 0:
            return (rows[0].get("role") or "user").lower()
    except Exception as e:
        safe_print(f"[RBAC] get_user_role error: {e}")
    return "user"


def require_role(*allowed_roles):
    """Decorator: require that the authenticated user has one of the allowed roles.
    Must be applied AFTER @require_auth so g.user is populated.
    Example:
        @app.route("/api/admin/users")
        @require_auth
        @require_role("admin")
        def admin_users(): ...
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            uid = getattr(g, "user", {}).get("uid") if hasattr(g, "user") and g.user else None
            if not uid:
                return jsonify({"success": False, "message": "Authentication required."}), 401
            role = get_user_role(uid)
            if role not in allowed_roles:
                # Log unauthorized access attempt
                safe_print(f"[RBAC] UNAUTHORIZED: uid={uid} role={role} attempted access to restricted endpoint (requires {allowed_roles})")
                return jsonify({
                    "success": False,
                    "message": "Access denied. Insufficient permissions.",
                    "required_role": list(allowed_roles)
                }), 403
            g.role = role
            return f(*args, **kwargs)
        return decorated
    return decorator


def require_admin(f):
    """Shortcut decorator: require admin role."""
    return require_role("admin")(f)


def is_admin(uid):
    """Check if a given user uid has admin role."""
    return get_user_role(uid) == "admin"
