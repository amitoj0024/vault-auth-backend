"""Service layer for VaultAuth Admin Dashboard."""

import json
import os
from datetime import datetime, timedelta, timezone
from api.db import execute_query
from api.utils import safe_print
from api.rbac import get_user_role, ROLES
from api.dashboard import _to_local_datetime, cleanup_expired_sessions, format_relative_timestamp, format_live_relative


def _fmt_dt_local(dt, include_seconds=False):
    """Format DB timestamps (UTC naive) into local readable datetime strings."""
    if not dt:
        return "—"
    local_dt = _to_local_datetime(dt) or dt
    if hasattr(local_dt, "strftime"):
        fmt = "%b %d, %Y %I:%M:%S %p" if include_seconds else "%b %d, %Y %I:%M %p"
        return local_dt.strftime(fmt)
    return str(local_dt)


def record_audit_log(event_type, actor_uid=None, actor_username=None, target_uid=None,
                     target_username=None, ip_address="127.0.0.1", status="Success", details=None):
    """Insert an audit log entry."""
    try:
        execute_query(
            """INSERT INTO audit_logs (event_type, actor_uid, actor_username, target_uid,
               target_username, ip_address, status, details, created_at)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW())""",
            (event_type, actor_uid, actor_username, target_uid, target_username,
             ip_address, status, details)
        )
    except Exception as e:
        safe_print(f"Audit log error: {e}")


def get_admin_dashboard_stats():
    """Aggregate all live statistics for Admin Overview cards directly from Postgres."""
    try:
        cleanup_expired_sessions()

        # Total users
        r = execute_query("SELECT COUNT(*) as cnt FROM users")
        total_users = r[0]["cnt"] if isinstance(r, list) and r else 0

        # New users today
        r = execute_query("SELECT COUNT(*) as cnt FROM users WHERE c_date = CURRENT_DATE")
        new_users_today = r[0]["cnt"] if isinstance(r, list) and r else 0

        # Active users (is_active = TRUE)
        r = execute_query("SELECT COUNT(*) as cnt FROM users WHERE is_active = TRUE")
        active_users = r[0]["cnt"] if isinstance(r, list) and r else 0

        # Administrators
        r = execute_query("SELECT COUNT(*) as cnt FROM users WHERE role = 'admin'")
        admins = r[0]["cnt"] if isinstance(r, list) and r else 0

        # Active sessions (strictly valid: non-revoked, non-expired against DB clock)
        r = execute_query(
            """
            SELECT COUNT(*) as cnt, COUNT(DISTINCT uid) as unique_users
            FROM active_sessions
            WHERE is_active = TRUE
              AND (revoked_at IS NULL)
              AND (expires_at IS NULL OR expires_at > NOW()::timestamp)
            """
        )
        active_sessions = r[0]["cnt"] if isinstance(r, list) and r else 0
        active_session_users = r[0].get("unique_users", 0) if isinstance(r, list) and r else 0

        # Failed login attempts (last 24h aligned with Postgres UTC NOW())
        r = execute_query(
            "SELECT COUNT(*) as cnt FROM login_activity WHERE status = 'Failed' AND created_at >= NOW() - INTERVAL '24 hours'"
        )
        failed_logins = r[0]["cnt"] if isinstance(r, list) and r else 0

        # Suspicious activities in last 24h
        try:
            r = execute_query(
                "SELECT COUNT(*) as cnt FROM audit_logs WHERE (status = 'Failed' OR event_type LIKE '%UNAUTHORIZED%' OR event_type LIKE '%SUSPICIOUS%') AND created_at >= NOW() - INTERVAL '24 hours'"
            )
            suspicious = r[0]["cnt"] if isinstance(r, list) and r else 0
        except Exception:
            suspicious = 0

        # Live workspace connected applications summary
        apps_summary = get_admin_connected_apps().get("summary", {})
        sec_cfg = get_runtime_security_settings()
        mfa_req = bool(sec_cfg.get("mfa_required"))
        min_pwd = int(sec_cfg.get("password_min_length", 8) or 8)
        security_score = min(
            100,
            max(
                45,
                70
                + (15 if mfa_req else 5)
                + (10 if min_pwd >= 8 else 0)
                + (5 if suspicious == 0 else -min(15, suspicious * 2))
                - (min(15, failed_logins) if failed_logins > 5 else 0),
            ),
        )

        return {
            "total_users": total_users,
            "new_users_today": new_users_today,
            "active_users": active_users,
            "administrators": admins,
            "active_sessions": active_sessions,
            "active_session_users": active_session_users,
            "failed_logins_24h": failed_logins,
            "suspicious_activities_24h": suspicious,
            "connected_apps_total": apps_summary.get("total_apps", 0),
            "connected_apps_active": apps_summary.get("active_apps", 0),
            "connected_apps_inactive": apps_summary.get("inactive_apps", 0),
            "connected_grants_active": apps_summary.get("total_active_grants", 0),
            "connected_grants_inactive": apps_summary.get("total_inactive_grants", 0),
            "security_score": security_score,
        }
    except Exception as e:
        safe_print(f"Admin stats error: {e}")
        return {
            "total_users": 0, "new_users_today": 0, "active_users": 0, "administrators": 0,
            "active_sessions": 0, "active_session_users": 0,
            "failed_logins_24h": 0, "suspicious_activities_24h": 0,
            "connected_apps_total": 0, "connected_apps_active": 0, "connected_apps_inactive": 0,
            "connected_grants_active": 0, "connected_grants_inactive": 0, "security_score": 85,
        }


def get_all_users_admin(search=None, role_filter=None, status_filter=None, page=1, per_page=20):
    """Retrieve all users with optional filters, with role lookup."""
    try:
        conditions = []
        params = []

        if search:
            conditions.append("(LOWER(username) LIKE %s OR LOWER(email) LIKE %s OR CAST(uid AS TEXT) LIKE %s)")
            term = f"%{search.lower()}%"
            params.extend([term, term, term])

        if role_filter and role_filter != "all":
            conditions.append("role = %s")
            params.append(role_filter.lower())

        if status_filter and status_filter != "all":
            if status_filter.lower() == "active":
                conditions.append("is_active = TRUE")
            elif status_filter.lower() == "inactive":
                conditions.append("is_active = FALSE")

        where = "WHERE " + " AND ".join(conditions) if conditions else ""
        offset = (page - 1) * per_page

        count_res = execute_query(f"SELECT COUNT(*) as cnt FROM users {where}", tuple(params) if params else None)
        total = count_res[0]["cnt"] if isinstance(count_res, list) and count_res else 0

        query = f"""
        SELECT uid, username, email, full_name, phone, is_active, c_date, role
        FROM users {where}
        ORDER BY uid DESC
        LIMIT %s OFFSET %s
        """
        p = list(params) + [per_page, offset]
        rows = execute_query(query, tuple(p))

        users = []
        if isinstance(rows, list):
            for u in rows:
                role_key = (u.get("role") or "user").lower()
                users.append({
                    "uid": u["uid"],
                    "username": u["username"],
                    "email": u["email"],
                    "full_name": u.get("full_name") or u["username"],
                    "phone": u.get("phone") or "",
                    "is_active": u.get("is_active", True),
                    "role": role_key,
                    "role_title": ROLES.get(role_key, "End User"),
                    "c_date": u["c_date"].isoformat() if hasattr(u["c_date"], "isoformat") else str(u.get("c_date", "")),
                })

        return {"users": users, "total": total, "page": page, "per_page": per_page, "pages": max(1, -(-total // per_page))}
    except Exception as e:
        safe_print(f"Admin get users error: {e}")
        return {"users": [], "total": 0, "page": 1, "per_page": per_page, "pages": 1}


def admin_create_user(username, email, password, full_name=None, phone=None, role="user"):
    """Create a new user (admin action)."""
    from werkzeug.security import generate_password_hash
    from api.security import validate_email, validate_username, validate_password_strength, sanitize_string
    try:
        email = validate_email(email)
        username = validate_username(username)
        sec_cfg = get_runtime_security_settings()
        ok, _, errs = validate_password_strength(password, min_length=sec_cfg["password_min_length"])
        if not ok:
            return False, f"Weak password: {'; '.join(errs)}"

        if full_name:
            full_name = sanitize_string(full_name, 100)

        hashed = generate_password_hash(password)
        c_date = datetime.now().strftime("%Y-%m-%d")
        role = role.lower() if role.lower() in ("admin", "user") else "user"

        res = execute_query(
            "INSERT INTO users (username, password, email, c_date, full_name, phone, is_active, role) VALUES (%s, %s, %s, %s, %s, %s, TRUE, %s) RETURNING uid",
            (username, hashed, email, c_date, full_name, phone, role)
        )
        if isinstance(res, str) and res.startswith("Error"):
            return False, res
        new_uid = res[0]["uid"] if isinstance(res, list) and res else None
        # Seed security settings
        if new_uid:
            execute_query(
                "INSERT INTO user_security_settings (uid, mfa_enabled, recovery_email, recovery_email_verified, password_strength, password_last_changed, department, role, joined_date) VALUES (%s, TRUE, %s, FALSE, 'Strong', NOW(), 'General', %s, CURRENT_DATE) ON CONFLICT (uid) DO NOTHING",
                (new_uid, email, ROLES.get(role, "End User"))
            )
        return True, {"uid": new_uid, "username": username, "email": email}
    except ValueError as ve:
        return False, str(ve)
    except Exception as e:
        safe_print(f"Admin create user error: {e}")
        return False, str(e)


def admin_update_user(target_uid, data, actor_uid):
    """Update user fields (admin)."""
    from api.security import sanitize_string, validate_email
    allowed_fields = {}
    if "full_name" in data:
        try:
            allowed_fields["full_name"] = sanitize_string(data["full_name"], 100)
        except ValueError as ve:
            return False, str(ve)
    if "email" in data:
        try:
            allowed_fields["email"] = validate_email(data["email"])
        except ValueError as ve:
            return False, str(ve)
    if "phone" in data:
        allowed_fields["phone"] = sanitize_string(str(data["phone"])[:20], 20) if data["phone"] else None
    if "is_active" in data:
        allowed_fields["is_active"] = bool(data["is_active"])

    if not allowed_fields:
        return True, "No changes"

    sets = ", ".join(f"{k} = %s" for k in allowed_fields)
    vals = list(allowed_fields.values()) + [target_uid]
    res = execute_query(f"UPDATE users SET {sets} WHERE uid = %s", tuple(vals))
    if isinstance(res, str) and res.startswith("Error"):
        return False, res
    return True, "User updated"


def admin_toggle_user_status(target_uid, is_active, actor_uid):
    """Activate or deactivate a user account."""
    res = execute_query("UPDATE users SET is_active = %s WHERE uid = %s RETURNING uid", (is_active, target_uid))
    if isinstance(res, list) and res:
        if not is_active:
            # Revoke all sessions on deactivation
            execute_query("UPDATE active_sessions SET is_active = FALSE, revoked_at = NOW() WHERE uid = %s AND is_active = TRUE", (target_uid,))
        return True, "Account status updated"
    return False, "User not found"


def admin_delete_user(target_uid, actor_uid):
    """Permanently delete a user and all their data (cascade)."""
    # Confirm user exists first
    check = execute_query("SELECT uid, username FROM users WHERE uid = %s", (target_uid,))
    if not isinstance(check, list) or not check:
        return False, "User not found"
    username = check[0]["username"]
    res = execute_query("DELETE FROM users WHERE uid = %s RETURNING uid", (target_uid,))
    if isinstance(res, list) and res:
        return True, f"User '{username}' permanently deleted"
    return False, "Delete failed"


def get_admin_all_sessions(search=None, status_filter=None, page=1, per_page=20, current_token=None):
    """Get sessions across all users for admin view with accurate active/expired/revoked state."""
    try:
        cleanup_expired_sessions()
        conditions = []
        params = []

        if search:
            conditions.append("(LOWER(u.username) LIKE %s OR LOWER(u.email) LIKE %s OR LOWER(s.device_name) LIKE %s)")
            term = f"%{search.lower()}%"
            params.extend([term, term, term])

        if status_filter == "active":
            conditions.append("s.is_active = TRUE AND (s.revoked_at IS NULL) AND (s.expires_at IS NULL OR s.expires_at > NOW()::timestamp)")
        elif status_filter == "revoked":
            conditions.append("(s.is_active = FALSE OR s.revoked_at IS NOT NULL OR (s.expires_at IS NOT NULL AND s.expires_at <= NOW()::timestamp))")

        where = "WHERE " + " AND ".join(conditions) if conditions else ""
        offset = (page - 1) * per_page

        count_res = execute_query(
            f"SELECT COUNT(*) as cnt FROM active_sessions s JOIN users u ON s.uid = u.uid {where}",
            tuple(params) if params else None
        )
        total = count_res[0]["cnt"] if isinstance(count_res, list) and count_res else 0

        query = f"""
        SELECT s.id, s.session_id, s.session_token, s.uid, u.username, u.email, u.full_name,
               s.device_name, s.device_type, s.browser, s.os, s.ip_address, s.location,
               s.created_at, s.last_activity, s.is_active, s.expires_at, s.revoked_at
        FROM active_sessions s
        JOIN users u ON s.uid = u.uid
        {where}
        ORDER BY s.last_activity DESC
        LIMIT %s OFFSET %s
        """
        p = list(params) + [per_page, offset]
        rows = execute_query(query, tuple(p))

        sessions = []
        utc_now = datetime.now(timezone.utc).replace(tzinfo=None)
        if isinstance(rows, list):
            for r in rows:
                expires_at = r.get("expires_at")
                is_expired = expires_at and expires_at < utc_now if isinstance(expires_at, datetime) else False
                is_revoked = bool(r.get("revoked_at"))
                is_active = bool(r.get("is_active", False)) and not is_expired and not is_revoked
                is_current = bool(current_token and r.get("session_token") == current_token)

                sessions.append({
                    "id": r["id"],
                    "session_id": r.get("session_id"),
                    "uid": r["uid"],
                    "username": r["username"],
                    "full_name": r.get("full_name") or r["username"],
                    "email": r["email"],
                    "device_name": r.get("device_name", "Unknown"),
                    "device_type": r.get("device_type", "desktop"),
                    "browser": r.get("browser", "—"),
                    "os": r.get("os", "—"),
                    "ip_address": r.get("ip_address", "—"),
                    "location": r.get("location", "—"),
                    "created_at": _fmt_dt_local(r.get("created_at")),
                    "last_activity": _fmt_dt_local(r.get("last_activity")),
                    "last_activity_relative": format_live_relative(r.get("last_activity")) if is_active else _fmt_dt_local(r.get("last_activity")),
                    "is_current": is_current,
                    "is_active": is_active,
                    "status": "Current" if (is_active and is_current) else ("Active" if is_active else ("Revoked" if is_revoked else "Expired")),
                })

        return {"sessions": sessions, "total": total, "page": page, "per_page": per_page, "pages": max(1, -(-total // per_page))}
    except Exception as e:
        safe_print(f"Admin sessions error: {e}")
        return {"sessions": [], "total": 0, "page": 1, "per_page": per_page, "pages": 1}


def admin_revoke_session(session_id, actor_uid):
    """Revoke a session by session_id (admin)."""
    res = execute_query(
        "UPDATE active_sessions SET is_active = FALSE, revoked_at = NOW() WHERE session_id = %s AND is_active = TRUE RETURNING id",
        (session_id,)
    )
    if isinstance(res, list) and res:
        return True, "Session revoked"
    return False, "Session not found or already revoked"


def admin_revoke_all_user_sessions(target_uid, actor_uid):
    """Revoke all active sessions for a specific user (admin)."""
    res = execute_query(
        "UPDATE active_sessions SET is_active = FALSE, revoked_at = NOW() WHERE uid = %s AND is_active = TRUE RETURNING id",
        (target_uid,)
    )
    count = len(res) if isinstance(res, list) else 0
    return True, f"Revoked {count} session(s)"


def _minute_bucket(dt, explicit_bucket=None):
    """Return local minute-truncated datetime (or raw fallback) for grouping same-minute events."""
    raw = explicit_bucket or dt
    local_dt = _to_local_datetime(raw) or raw
    if hasattr(local_dt, "replace"):
        return local_dt.replace(second=0, microsecond=0)
    return raw


def _tally_statuses(items, default="Unknown"):
    counts = {}
    for item in items:
        st = item.get("status") or default
        counts[st] = counts.get(st, 0) + 1
    has_failure = any(str(k).lower() != "success" for k in counts)
    return counts, has_failure


def _extract_group_counts(count_res):
    if isinstance(count_res, list) and count_res:
        total = int(count_res[0].get("cnt") or 0)
        raw_total = int(count_res[0].get("raw_cnt") if count_res[0].get("raw_cnt") is not None else total)
        return total, raw_total
    return 0, 0


def get_admin_login_activity(search=None, status_filter=None, date_from=None, date_to=None, page=1, per_page=25):
    """Get login activity for admin monitoring, grouped by user UID and minute timestamp."""
    try:
        conditions = []
        params = []

        if search:
            conditions.append("(LOWER(u.username) LIKE %s OR LOWER(u.email) LIKE %s OR LOWER(COALESCE(u.full_name, '')) LIKE %s)")
            term = f"%{search.lower()}%"
            params.extend([term, term, term])

        if status_filter and status_filter != "all":
            conditions.append("LOWER(la.status) = %s")
            params.append(status_filter.lower())

        if date_from:
            try:
                conditions.append("la.created_at >= %s")
                params.append(datetime.fromisoformat(date_from))
            except Exception:
                pass

        if date_to:
            try:
                dt_to = datetime.fromisoformat(date_to) + timedelta(days=1)
                conditions.append("la.created_at < %s")
                params.append(dt_to)
            except Exception:
                pass

        where = "WHERE " + " AND ".join(conditions) if conditions else ""
        offset = (page - 1) * per_page

        count_res = execute_query(
            f"""
            SELECT COUNT(*) AS cnt, COALESCE(SUM(group_size), 0) AS raw_cnt
            FROM (
                SELECT COUNT(*) AS group_size
                FROM login_activity la
                JOIN users u ON la.uid = u.uid
                {where}
                GROUP BY la.uid, DATE_TRUNC('minute', la.created_at)
            ) grouped
            """,
            tuple(params) if params else None,
        )
        total, raw_total = _extract_group_counts(count_res)

        query = f"""
        WITH filtered AS (
            SELECT la.id, la.uid, u.username, u.full_name, u.email,
                   la.device_name, la.device_type, la.browser, la.os,
                   la.location, la.ip_address, la.status, la.created_at,
                   DATE_TRUNC('minute', la.created_at) AS time_bucket
            FROM login_activity la
            JOIN users u ON la.uid = u.uid
            {where}
        ),
        page_groups AS (
            SELECT uid, time_bucket, MAX(created_at) AS latest_at
            FROM filtered
            GROUP BY uid, time_bucket
            ORDER BY MAX(created_at) DESC
            LIMIT %s OFFSET %s
        )
        SELECT f.*
        FROM filtered f
        JOIN page_groups pg
          ON f.uid = pg.uid
         AND f.time_bucket = pg.time_bucket
        ORDER BY pg.latest_at DESC, f.created_at DESC, f.id DESC
        """
        p = list(params) + [per_page, offset]
        rows = execute_query(query, tuple(p))

        buckets = {}
        if isinstance(rows, list):
            for r in rows:
                created = r.get("created_at")
                created_local = _to_local_datetime(created) or created
                bucket = _minute_bucket(created, r.get("time_bucket"))
                bucket_key = bucket.isoformat() if hasattr(bucket, "isoformat") else str(bucket or "")
                group_key = f"{r['uid']}:{bucket_key}"
                event_entry = {
                    "id": r["id"],
                    "uid": r["uid"],
                    "username": r["username"],
                    "full_name": r.get("full_name") or r["username"],
                    "email": r["email"],
                    "device_name": r.get("device_name", "—"),
                    "device_type": r.get("device_type", "desktop"),
                    "browser": r.get("browser", "—"),
                    "os": r.get("os", "—"),
                    "location": r.get("location", "—"),
                    "ip_address": r.get("ip_address", "—"),
                    "status": r.get("status", "Unknown"),
                    "created_at": _fmt_dt_local(created),
                    "created_at_exact": _fmt_dt_local(created, include_seconds=True),
                    "created_at_iso": created_local.isoformat() if hasattr(created_local, "isoformat") else str(created_local or ""),
                }
                if group_key not in buckets:
                    buckets[group_key] = {
                        "group_key": group_key,
                        "time_bucket": _fmt_dt_local(bucket),
                        "lead": event_entry,
                        "events": [],
                    }
                buckets[group_key]["events"].append(event_entry)

        activities = []
        for g in buckets.values():
            lead = g["lead"]
            events = g["events"]
            status_counts, has_failure = _tally_statuses(events, default="Unknown")
            activities.append({
                **lead,
                "group_key": g["group_key"],
                "time_bucket": g["time_bucket"],
                "created_at": g["time_bucket"] if g["time_bucket"] != "—" else lead["created_at"],
                "created_at_exact": lead["created_at_exact"],
                "event_count": len(events),
                "status_counts": status_counts,
                "has_failure": has_failure,
                "events": events,
            })

        return {
            "activities": activities,
            "total": total,
            "raw_total": raw_total,
            "page": page,
            "per_page": per_page,
            "pages": max(1, -(-total // per_page)),
        }
    except Exception as e:
        safe_print(f"Admin login activity error: {e}")
        return {"activities": [], "total": 0, "raw_total": 0, "page": 1, "per_page": per_page, "pages": 1}


def get_audit_logs(search=None, event_filter=None, page=1, per_page=25):
    """Retrieve audit log entries grouped by user UID and minute timestamp."""
    try:
        conditions = []
        params = []

        if search:
            conditions.append(
                "(LOWER(COALESCE(al.actor_username, '')) LIKE %s "
                "OR LOWER(COALESCE(al.target_username, '')) LIKE %s "
                "OR LOWER(COALESCE(al.event_type, '')) LIKE %s "
                "OR LOWER(COALESCE(al.details, '')) LIKE %s)"
            )
            term = f"%{search.lower()}%"
            params.extend([term, term, term, term])

        if event_filter and event_filter != "all":
            conditions.append("LOWER(al.event_type) LIKE %s")
            params.append(f"%{event_filter.lower()}%")

        where = "WHERE " + " AND ".join(conditions) if conditions else ""
        offset = (page - 1) * per_page

        count_res = execute_query(
            f"""
            SELECT COUNT(*) AS cnt, COALESCE(SUM(group_size), 0) AS raw_cnt
            FROM (
                SELECT COUNT(*) AS group_size
                FROM audit_logs al
                {where}
                GROUP BY COALESCE(al.actor_uid, al.target_uid, -1), DATE_TRUNC('minute', al.created_at)
            ) grouped
            """,
            tuple(params) if params else None,
        )
        total, raw_total = _extract_group_counts(count_res)

        query = f"""
        WITH filtered AS (
            SELECT al.id, al.event_type, al.actor_uid, al.actor_username,
                   al.target_uid, al.target_username, al.ip_address, al.status,
                   al.details, al.created_at,
                   COALESCE(al.actor_uid, al.target_uid, -1) AS group_uid,
                   DATE_TRUNC('minute', al.created_at) AS time_bucket
            FROM audit_logs al
            {where}
        ),
        page_groups AS (
            SELECT group_uid, time_bucket, MAX(created_at) AS latest_at
            FROM filtered
            GROUP BY group_uid, time_bucket
            ORDER BY MAX(created_at) DESC
            LIMIT %s OFFSET %s
        )
        SELECT f.*, u.full_name, u.username AS user_username
        FROM filtered f
        JOIN page_groups pg
          ON f.group_uid = pg.group_uid
         AND f.time_bucket = pg.time_bucket
        LEFT JOIN users u
          ON u.uid = COALESCE(f.actor_uid, f.target_uid)
        ORDER BY pg.latest_at DESC, f.created_at DESC, f.id DESC
        """
        p = list(params) + [per_page, offset]
        rows = execute_query(query, tuple(p))

        buckets = {}
        if isinstance(rows, list):
            for r in rows:
                created = r.get("created_at")
                bucket = _minute_bucket(created, r.get("time_bucket"))
                bucket_key = bucket.isoformat() if hasattr(bucket, "isoformat") else str(bucket or "")
                eff_uid = r.get("actor_uid") if r.get("actor_uid") is not None else r.get("target_uid")
                group_uid = r.get("group_uid") if r.get("group_uid") is not None else (eff_uid if eff_uid is not None else -1)
                group_key = f"{group_uid}:{bucket_key}"
                log_entry = {
                    "id": r["id"],
                    "uid": eff_uid,
                    "event_type": r["event_type"],
                    "actor_uid": r.get("actor_uid"),
                    "actor_username": r.get("actor_username") or r.get("user_username") or "System",
                    "full_name": r.get("full_name") or r.get("actor_username") or r.get("user_username") or "System",
                    "target_uid": r.get("target_uid"),
                    "target_username": r.get("target_username") or "—",
                    "ip_address": r.get("ip_address", "—"),
                    "status": r.get("status", "Success"),
                    "details": r.get("details") or "",
                    "created_at": _fmt_dt_local(created),
                    "created_at_exact": _fmt_dt_local(created, include_seconds=True),
                }
                if group_key not in buckets:
                    buckets[group_key] = {
                        "group_key": group_key,
                        "uid": eff_uid,
                        "time_bucket": _fmt_dt_local(bucket),
                        "lead": log_entry,
                        "events": [],
                    }
                buckets[group_key]["events"].append(log_entry)

        logs = []
        for g in buckets.values():
            lead = g["lead"]
            events = g["events"]
            ev_counts = {}
            for ev in events:
                et = ev["event_type"]
                ev_counts[et] = ev_counts.get(et, 0) + 1
            event_types = [
                {"event_type": et, "count": cnt}
                for et, cnt in sorted(ev_counts.items(), key=lambda x: -x[1])
            ]
            status_counts, has_failure = _tally_statuses(events, default="Success")
            actor_name = next((e["actor_username"] for e in events if e["actor_username"] and e["actor_username"] != "System"), lead["actor_username"])
            logs.append({
                **lead,
                "actor_username": actor_name,
                "uid": g["uid"],
                "group_key": g["group_key"],
                "time_bucket": g["time_bucket"],
                "created_at": g["time_bucket"] if g["time_bucket"] != "—" else lead["created_at"],
                "created_at_exact": lead["created_at_exact"],
                "event_count": len(events),
                "event_types": event_types,
                "status_counts": status_counts,
                "has_failure": has_failure,
                "events": events,
            })

        return {
            "logs": logs,
            "total": total,
            "raw_total": raw_total,
            "page": page,
            "per_page": per_page,
            "pages": max(1, -(-total // per_page)),
        }
    except Exception as e:
        safe_print(f"Audit logs error: {e}")
        return {"logs": [], "total": 0, "raw_total": 0, "page": 1, "per_page": per_page, "pages": 1}


def get_runtime_security_settings():
    """Fetch enforced runtime security settings with safe defaults if DB is unavailable."""
    defaults = {
        "session_timeout": int(os.getenv("TOKEN_EXPIRATION", "3600") or 3600),
        "max_failed_attempts": 5,
        "otp_expiry_seconds": 300,
        "password_min_length": 8,
        "mfa_required": False,
    }
    try:
        rows = execute_query("SELECT setting_key, setting_value FROM admin_settings")
        if isinstance(rows, list):
            mapping = {r["setting_key"]: r["setting_value"] for r in rows if isinstance(r, dict)}
            if str(mapping.get("session_timeout", "")).isdigit():
                defaults["session_timeout"] = max(60, min(86400, int(mapping["session_timeout"])))
            if str(mapping.get("max_failed_attempts", "")).isdigit():
                defaults["max_failed_attempts"] = max(3, min(20, int(mapping["max_failed_attempts"])))
            if str(mapping.get("otp_expiry_seconds", "")).isdigit():
                defaults["otp_expiry_seconds"] = max(60, min(900, int(mapping["otp_expiry_seconds"])))
            if str(mapping.get("password_min_length", "")).isdigit():
                defaults["password_min_length"] = max(8, min(32, int(mapping["password_min_length"])))
            if "mfa_required" in mapping:
                defaults["mfa_required"] = str(mapping["mfa_required"]).strip().lower() in ("true", "1", "yes")
    except Exception:
        pass
    return defaults


def get_admin_settings():
    """Retrieve all admin settings (non-secret)."""
    from api.mailer import is_smtp_configured, is_plunk_configured, is_email_configured
    try:
        rows = execute_query("SELECT setting_key, setting_value FROM admin_settings ORDER BY id")
        settings = {}
        if isinstance(rows, list):
            for r in rows:
                settings[r["setting_key"]] = r["setting_value"]
        # Augment with read-only env-derived values (never expose secrets)
        smtp_ready = is_smtp_configured()
        plunk_ready = is_plunk_configured()
        settings["smtp_configured"] = smtp_ready
        settings["plunk_configured"] = plunk_ready
        settings["otp_configured"] = is_email_configured()
        settings["mail_provider"] = "SMTP" if smtp_ready else ("Plunk" if plunk_ready else "Unconfigured")
        settings["cors_origins"] = os.getenv("CORS_ORIGINS", "http://localhost:3000,http://localhost:5500")
        return settings
    except Exception as e:
        safe_print(f"Admin settings error: {e}")
        return {}


def update_admin_settings(updates, actor_uid):
    """Update admin settings (safe keys only with validation)."""
    if not isinstance(updates, dict):
        return False, "Invalid settings payload"

    ALLOWED_KEYS = {
        "session_timeout", "max_failed_attempts", "otp_expiry_seconds",
        "password_min_length", "mfa_required", "app_name"
    }
    updated = []
    for key, val in updates.items():
        if key not in ALLOWED_KEYS:
            continue
        if key == "session_timeout":
            try:
                num = int(val)
                if num < 60 or num > 86400:
                    return False, "session_timeout must be between 60 and 86400 seconds"
                clean_val = str(num)
            except (TypeError, ValueError):
                return False, "session_timeout must be a valid integer"
        elif key == "otp_expiry_seconds":
            try:
                num = int(val)
                if num < 60 or num > 900:
                    return False, "otp_expiry_seconds must be between 60 and 900 seconds"
                clean_val = str(num)
            except (TypeError, ValueError):
                return False, "otp_expiry_seconds must be a valid integer"
        elif key == "max_failed_attempts":
            try:
                num = int(val)
                if num < 3 or num > 20:
                    return False, "max_failed_attempts must be between 3 and 20"
                clean_val = str(num)
            except (TypeError, ValueError):
                return False, "max_failed_attempts must be a valid integer"
        elif key == "password_min_length":
            try:
                num = int(val)
                if num < 8 or num > 32:
                    return False, "password_min_length must be between 8 and 32"
                clean_val = str(num)
            except (TypeError, ValueError):
                return False, "password_min_length must be a valid integer"
        elif key == "mfa_required":
            clean_val = "true" if str(val).strip().lower() in ("true", "1", "yes") else "false"
        else:
            clean_val = str(val).strip()[:100]

        res = execute_query(
            """
            INSERT INTO admin_settings (setting_key, setting_value, updated_at)
            VALUES (%s, %s, NOW())
            ON CONFLICT (setting_key) DO UPDATE SET setting_value = EXCLUDED.setting_value, updated_at = NOW()
            """,
            (key, clean_val)
        )
        if isinstance(res, str) and res.startswith("Error"):
            return False, res
        updated.append(key)
    return bool(updated), f"Updated: {', '.join(updated)}" if updated else "No valid settings updated"


def get_roles_overview():
    """Get role distribution and permission mapping."""
    try:
        rows = execute_query(
            "SELECT role, COUNT(*) as count FROM users GROUP BY role ORDER BY count DESC"
        )
        role_counts = {}
        if isinstance(rows, list):
            for r in rows:
                role_counts[r["role"] or "user"] = r["count"]

        PERMISSIONS_MAP = {
            "admin": [
                "users.view", "users.create", "users.edit", "users.delete",
                "roles.view", "roles.manage", "sessions.view", "sessions.revoke",
                "audit.view", "settings.manage"
            ],
            "user": ["users.view"]
        }

        return {
            "roles": [
                {
                    "key": "admin",
                    "title": "Enterprise Admin",
                    "description": "Full system access with all administrative privileges",
                    "count": role_counts.get("admin", 0),
                    "permissions": PERMISSIONS_MAP["admin"],
                    "color": "#7047eb"
                },
                {
                    "key": "user",
                    "title": "End User",
                    "description": "Standard user with limited read access",
                    "count": role_counts.get("user", 0),
                    "permissions": PERMISSIONS_MAP["user"],
                    "color": "#1d4ed8"
                }
            ],
            "permissions": [
                {"key": "users.view", "label": "View Users", "category": "Users"},
                {"key": "users.create", "label": "Create Users", "category": "Users"},
                {"key": "users.edit", "label": "Edit Users", "category": "Users"},
                {"key": "users.delete", "label": "Delete Users", "category": "Users"},
                {"key": "roles.view", "label": "View Roles", "category": "RBAC"},
                {"key": "roles.manage", "label": "Manage Roles", "category": "RBAC"},
                {"key": "sessions.view", "label": "View Sessions", "category": "Sessions"},
                {"key": "sessions.revoke", "label": "Revoke Sessions", "category": "Sessions"},
                {"key": "audit.view", "label": "View Audit Logs", "category": "Security"},
                {"key": "settings.manage", "label": "Manage Settings", "category": "System"},
            ]
        }
    except Exception as e:
        safe_print(f"Roles overview error: {e}")
        return {"roles": [], "permissions": []}


def get_admin_connected_apps():
    """Aggregate live workspace connected applications and real user accounts from Postgres."""
    try:
        test_filter = (
            "WHERE u.email !~* '@(vaultauth\\.test|test\\.vault\\.io|example\\.com|vault\\.io)$' "
            "AND u.email !~* '^(employee_|reg_)[0-9]+@'"
        )
        query = f"""
        SELECT ca.id, ca.uid, u.email, u.username, u.full_name, ca.app_key, ca.app_name, ca.app_desc,
               ca.logo_char, ca.logo_bg, ca.permissions, ca.connected_at,
               COALESCE(ca.last_used_at, ca.connected_at) AS last_used,
               COALESCE(ca.login_count, 1) AS login_count,
               ca.is_active
        FROM connected_apps ca
        JOIN users u ON ca.uid = u.uid
        {test_filter}
        ORDER BY COALESCE(ca.last_used_at, ca.connected_at) DESC, ca.id DESC
        """
        rows = execute_query(query)
        if isinstance(rows, str) and rows.startswith("Error:"):
            fallback_query = f"""
            SELECT ca.id, ca.uid, u.email, u.username, u.full_name, ca.app_key, ca.app_name, ca.app_desc,
                   ca.logo_char, ca.logo_bg, ca.permissions, ca.connected_at,
                   ca.connected_at AS last_used, 1 AS login_count, ca.is_active
            FROM connected_apps ca
            JOIN users u ON ca.uid = u.uid
            {test_filter}
            ORDER BY ca.connected_at DESC, ca.id DESC
            """
            rows = execute_query(fallback_query)

        grouped = {}
        total_active_grants = 0
        total_inactive_grants = 0

        if isinstance(rows, list):
            for r in rows:
                app_key = (r.get("app_key") or r.get("app_name") or f"app_{r['id']}").lower()
                raw_perms = r.get("permissions")
                try:
                    perms = json.loads(raw_perms) if isinstance(raw_perms, str) else raw_perms
                except Exception:
                    perms = [raw_perms] if raw_perms else []

                is_act = bool(r.get("is_active", True))
                if is_act:
                    total_active_grants += 1
                else:
                    total_inactive_grants += 1

                if app_key not in grouped:
                    grouped[app_key] = {
                        "id": app_key,
                        "row_id": r["id"],
                        "app_key": app_key,
                        "name": r.get("app_name") or app_key,
                        "app_name": r.get("app_name") or app_key,
                        "desc": r.get("app_desc") or "Enterprise SSO Client",
                        "app_desc": r.get("app_desc") or "Enterprise SSO Client",
                        "logo": r.get("logo_char") or (r.get("app_name") or "A")[:1].upper(),
                        "logo_char": r.get("logo_char") or (r.get("app_name") or "A")[:1].upper(),
                        "logo_bg": r.get("logo_bg") or "#2563eb",
                        "permissions": perms if isinstance(perms, list) else [],
                        "active_users_count": 0,
                        "inactive_users_count": 0,
                        "total_logins": 0,
                        "connected_users": [],
                        "seen_uids": set(),
                        "latest_dt": r.get("last_used") or r.get("connected_at"),
                    }

                entry = grouped[app_key]
                entry["total_logins"] += int(r.get("login_count") or 1)
                if is_act:
                    entry["active_users_count"] += 1
                else:
                    entry["inactive_users_count"] += 1

                uid = r["uid"]
                if uid not in entry["seen_uids"]:
                    entry["seen_uids"].add(uid)
                    entry["connected_users"].append({
                        "uid": uid,
                        "email": r.get("email"),
                        "username": r.get("username"),
                        "full_name": r.get("full_name") or r.get("username"),
                        "is_active": is_act,
                        "login_count": int(r.get("login_count") or 1),
                        "last_used_at": format_relative_timestamp(r.get("last_used") or r.get("connected_at")),
                    })

        apps_list = []
        active_apps = 0
        inactive_apps = 0
        for entry in grouped.values():
            entry.pop("seen_uids", None)
            latest_dt = entry.pop("latest_dt", None)
            is_enabled = entry["active_users_count"] > 0
            if is_enabled:
                active_apps += 1
            else:
                inactive_apps += 1

            formatted_recent = format_relative_timestamp(latest_dt)
            entry["is_active"] = is_enabled
            entry["status"] = "Active" if is_enabled else "Inactive"
            entry["connectedDate"] = formatted_recent
            entry["connected_date"] = formatted_recent
            entry["last_used_at"] = formatted_recent
            entry["connected_emails"] = [u["email"] for u in entry["connected_users"] if u.get("email") and u.get("is_active")]
            apps_list.append(entry)

        return {
            "apps": apps_list,
            "summary": {
                "total_apps": len(apps_list),
                "active_apps": active_apps,
                "inactive_apps": inactive_apps,
                "total_active_grants": total_active_grants,
                "total_inactive_grants": total_inactive_grants,
            },
        }
    except Exception as e:
        safe_print(f"Admin connected apps error: {e}")
        return {
            "apps": [],
            "summary": {
                "total_apps": 0,
                "active_apps": 0,
                "inactive_apps": 0,
                "total_active_grants": 0,
                "total_inactive_grants": 0,
            },
        }


def admin_toggle_connected_app(app_key, is_active=None, target_uid=None):
    """Enable or disable a connected SSO application across the workspace (or for a specific user)."""
    clean_key = str(app_key or "").strip().lower()
    if not clean_key:
        return False, "Application key is required", None

    try:
        where_clause = "WHERE LOWER(app_key) = %s"
        params = [clean_key]
        if target_uid is not None:
            where_clause += " AND uid = %s"
            params.append(int(target_uid))

        existing = execute_query(
            f"SELECT id, is_active FROM connected_apps {where_clause}",
            tuple(params),
        )
        if not isinstance(existing, list) or len(existing) == 0:
            return False, "Connected application not found", None

        if is_active is None:
            any_active = any(bool(row.get("is_active")) for row in existing)
            new_state = not any_active
        else:
            new_state = bool(is_active)

        update_params = [new_state] + params
        execute_query(
            f"UPDATE connected_apps SET is_active = %s WHERE id IN (SELECT id FROM connected_apps {where_clause})",
            tuple(update_params),
        )
        return True, f"Application '{clean_key}' {'enabled' if new_state else 'disabled'}", new_state
    except Exception as e:
        safe_print(f"Toggle connected app error: {e}")
        return False, str(e), None


def admin_disconnect_connected_app(app_key):
    """Disable/revoke all grants for an application across the workspace."""
    return admin_toggle_connected_app(app_key, is_active=False)
