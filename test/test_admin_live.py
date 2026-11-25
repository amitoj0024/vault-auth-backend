"""Unit tests for live admin metrics, active sessions, and connected applications tracking."""

from datetime import datetime, timezone
import pytest
from main import app
from api import admin, dashboard
from api.token import generate_token, session_token


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


@pytest.fixture
def admin_headers(monkeypatch):
    mock_admin = {
        "uid": 24,
        "username": "amy",
        "email": "amy492998@gmail.com",
        "full_name": "Amy Admin",
        "is_active": True,
        "role": "admin",
    }
    raw_token, _ = generate_token({"username": "amy", "uid": 24, "role": "admin"})
    token = session_token(raw_token)
    from api import auth_middleware

    monkeypatch.setattr(auth_middleware, "resolve_user_from_token", lambda tok: mock_admin if tok == token else None)
    monkeypatch.setattr("api.rbac.get_user_role", lambda uid: "admin")
    return {"Authorization": f"Bearer {token}"}, token


def test_admin_connected_apps_aggregation_live(client, admin_headers, monkeypatch):
    headers, _ = admin_headers
    sample_rows = [
        {
            "id": 10,
            "uid": 24,
            "email": "amy492998@gmail.com",
            "username": "amy",
            "app_key": "vaultauth",
            "app_name": "VaultAuth SSO",
            "app_desc": "Primary workspace",
            "logo_char": "V",
            "logo_bg": "#2563eb",
            "permissions": '["Single Sign-On"]',
            "connected_at": datetime.now(timezone.utc).replace(tzinfo=None),
            "last_used": datetime.now(timezone.utc).replace(tzinfo=None),
            "login_count": 4,
            "is_active": True,
        },
        {
            "id": 11,
            "uid": 5,
            "email": "amitoj0024@gmail.com",
            "username": "amitoj",
            "app_key": "slack",
            "app_name": "Slack",
            "app_desc": "Team messaging",
            "logo_char": "S",
            "logo_bg": "#5865F2",
            "permissions": '["Send messages"]',
            "connected_at": datetime.now(timezone.utc).replace(tzinfo=None),
            "last_used": datetime.now(timezone.utc).replace(tzinfo=None),
            "login_count": 1,
            "is_active": False,
        },
    ]
    queries_seen = []

    def fake_apps_query(q, p=None):
        queries_seen.append(q)
        return sample_rows

    monkeypatch.setattr(admin, "execute_query", fake_apps_query)

    res = client.get("/api/admin/connected-apps", headers=headers)
    assert res.status_code == 200
    data = res.get_json()
    assert data["summary"]["total_apps"] == 2
    assert data["summary"]["active_apps"] == 1
    assert data["summary"]["inactive_apps"] == 1
    assert data["summary"]["total_active_grants"] == 1
    assert data["summary"]["total_inactive_grants"] == 1
    vault_app = data["apps"][0]
    assert vault_app["app_key"] == "vaultauth"
    assert vault_app["total_logins"] == 4
    assert vault_app["connected_emails"] == ["amy492998@gmail.com"]
    assert vault_app["connected_users"][0]["full_name"] == "amy"
    assert any("vaultauth\\.test" in q for q in queries_seen)


def test_admin_toggle_connected_app_endpoint(client, admin_headers, monkeypatch):
    headers, _ = admin_headers
    monkeypatch.setattr(
        admin,
        "execute_query",
        lambda q, p=None: [{"id": 11, "is_active": True}] if "SELECT" in q else [],
    )
    monkeypatch.setattr("main.record_audit_log", lambda *a, **kw: None)

    res = client.post("/api/admin/connected-apps/slack/toggle", headers=headers, json={"is_active": False})
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["is_active"] is False


def test_record_connected_app_signin_updates_same_email_usage(monkeypatch):
    queries = []

    def fake_query(q, p=None):
        queries.append((q, p))
        if "SELECT id, is_active FROM connected_apps" in q:
            return [{"id": 56, "is_active": True}]
        return ()

    monkeypatch.setattr(dashboard, "execute_query", fake_query)
    dashboard.record_connected_app_signin(24, {"uid": 24, "email": "amy492998@gmail.com"})

    assert any("UPDATE connected_apps" in q and "login_count" in q for q, _ in queries)


def test_admin_sessions_active_filter_excludes_expired(monkeypatch):
    queries = []

    def fake_query(q, p=None):
        queries.append(q)
        if "COUNT(*)" in q:
            return [{"cnt": 1}]
        if "FROM active_sessions" in q:
            return [{
                "id": 91,
                "session_id": "sess_1",
                "session_token": "tok_current",
                "uid": 24,
                "username": "amy",
                "full_name": "Amy Admin",
                "email": "amy492998@gmail.com",
                "device_name": "MacBook Pro",
                "device_type": "laptop",
                "browser": "Chrome",
                "os": "macOS",
                "ip_address": "127.0.0.1",
                "location": "Bengaluru, India",
                "created_at": datetime.now(timezone.utc).replace(tzinfo=None),
                "last_activity": datetime.now(timezone.utc).replace(tzinfo=None),
                "is_active": True,
                "expires_at": None,
                "revoked_at": None,
            }]
        return ()

    monkeypatch.setattr(admin, "cleanup_expired_sessions", lambda: None)
    monkeypatch.setattr(admin, "execute_query", fake_query)

    res = admin.get_admin_all_sessions(status_filter="active", current_token="tok_current")
    assert res["total"] == 1
    assert len(res["sessions"]) == 1
    assert res["sessions"][0]["status"] == "Current"
    assert res["sessions"][0]["is_current"] is True
    assert any("expires_at > NOW()::timestamp" in q for q in queries)


def test_session_expiration_and_cleanup_align_on_utc(monkeypatch):
    inserted_exp = []
    cleanup_cutoffs = []

    def fake_exec(q, p=None):
        norm = " ".join(str(q).split())
        if "INSERT INTO active_sessions" in norm and p and len(p) >= 10:
            inserted_exp.append(p[9])
        elif "UPDATE active_sessions SET is_active = FALSE" in norm and p and len(p) >= 2:
            cleanup_cutoffs.append(p[1])
        return ()

    class FakeHeaders(dict):
        pass

    class FakeReq:
        headers = FakeHeaders({"User-Agent": "Chrome/158"})
        remote_addr = "127.0.0.1"

    monkeypatch.setattr(dashboard, "execute_query", fake_exec)
    raw_token, _ = generate_token({"username": "amy", "uid": 24, "role": "admin"})
    s_token = session_token(raw_token, expiration_seconds=3600)

    dashboard.create_user_session(24, s_token, FakeReq())
    dashboard.cleanup_expired_sessions(24)

    assert len(inserted_exp) == 1
    assert len(cleanup_cutoffs) == 1
    assert inserted_exp[0] > cleanup_cutoffs[0]


def test_security_activity_groups_same_uid_and_minute(monkeypatch):
    import api.admin as admin
    from datetime import datetime

    queries = []
    t_same_1 = datetime(2026, 11, 25, 17, 40, 41)
    t_same_2 = datetime(2026, 11, 25, 17, 40, 12)
    t_other_min = datetime(2026, 11, 25, 17, 39, 55)
    bucket_40 = datetime(2026, 11, 25, 17, 40, 0)
    bucket_39 = datetime(2026, 11, 25, 17, 39, 0)

    def fake_login_query(q, p=None):
        norm = " ".join(str(q).split())
        queries.append(norm)
        if "SELECT COUNT(*) AS cnt" in norm:
            return [{"cnt": 3, "raw_cnt": 4}]
        if "FROM filtered f" in norm:
            return [
                {
                    "id": 121, "uid": 24, "username": "amy", "full_name": "Amy Admin",
                    "email": "amy492998@gmail.com", "device_name": "MacBook Pro",
                    "device_type": "laptop", "browser": "Chrome", "os": "macOS",
                    "location": "Local", "ip_address": "127.0.0.1", "status": "Success",
                    "created_at": t_same_1, "time_bucket": bucket_40,
                },
                {
                    "id": 120, "uid": 24, "username": "amy", "full_name": "Amy Admin",
                    "email": "amy492998@gmail.com", "device_name": "MacBook Pro",
                    "device_type": "laptop", "browser": "Chrome", "os": "macOS",
                    "location": "Local", "ip_address": "127.0.0.1", "status": "Failed",
                    "created_at": t_same_2, "time_bucket": bucket_40,
                },
                {
                    "id": 119, "uid": 5, "username": "amitoj", "full_name": "Amitoj",
                    "email": "amitoj0024@gmail.com", "device_name": "MacBook Pro",
                    "device_type": "laptop", "browser": "Chrome", "os": "macOS",
                    "location": "Local", "ip_address": "127.0.0.1", "status": "Success",
                    "created_at": t_same_2, "time_bucket": bucket_40,
                },
                {
                    "id": 118, "uid": 24, "username": "amy", "full_name": "Amy Admin",
                    "email": "amy492998@gmail.com", "device_name": "MacBook Pro",
                    "device_type": "laptop", "browser": "Chrome", "os": "macOS",
                    "location": "Local", "ip_address": "127.0.0.1", "status": "Success",
                    "created_at": t_other_min, "time_bucket": bucket_39,
                },
            ]
        return ()

    monkeypatch.setattr(admin, "execute_query", fake_login_query)
    res = admin.get_admin_login_activity(page=1, per_page=25)
    assert res["total"] == 3
    assert res["raw_total"] == 4
    assert len(res["activities"]) == 3
    first = res["activities"][0]
    assert first["uid"] == 24
    assert first["event_count"] == 2
    assert first["has_failure"] is True
    assert first["status_counts"] == {"Success": 1, "Failed": 1}
    assert [e["id"] for e in first["events"]] == [121, 120]
    assert res["activities"][1]["uid"] == 5 and res["activities"][1]["event_count"] == 1
    assert res["activities"][2]["uid"] == 24 and res["activities"][2]["event_count"] == 1
    assert any("DATE_TRUNC('minute', la.created_at)" in q for q in queries)

    audit_queries = []

    def fake_audit_query(q, p=None):
        norm = " ".join(str(q).split())
        audit_queries.append(norm)
        if "SELECT COUNT(*) AS cnt" in norm:
            return [{"cnt": 1, "raw_cnt": 3}]
        if "FROM filtered f" in norm:
            return [
                {
                    "id": 462, "event_type": "ADMIN_STATS_VIEW", "actor_uid": 24,
                    "actor_username": "amy", "full_name": "Amy Admin", "user_username": "amy",
                    "target_uid": None, "target_username": None, "ip_address": "127.0.0.1",
                    "status": "Success", "details": None, "created_at": t_same_1,
                    "group_uid": 24, "time_bucket": bucket_40,
                },
                {
                    "id": 461, "event_type": "ADMIN_APP_ENABLED", "actor_uid": 24,
                    "actor_username": "amy", "full_name": "Amy Admin", "user_username": "amy",
                    "target_uid": None, "target_username": None, "ip_address": "127.0.0.1",
                    "status": "Success", "details": "app_key=github", "created_at": t_same_2,
                    "group_uid": 24, "time_bucket": bucket_40,
                },
                {
                    "id": 460, "event_type": "ADMIN_STATS_VIEW", "actor_uid": 24,
                    "actor_username": "amy", "full_name": "Amy Admin", "user_username": "amy",
                    "target_uid": None, "target_username": None, "ip_address": "127.0.0.1",
                    "status": "Success", "details": None, "created_at": t_same_2,
                    "group_uid": 24, "time_bucket": bucket_40,
                },
            ]
        return ()

    monkeypatch.setattr(admin, "execute_query", fake_audit_query)
    ares = admin.get_audit_logs(page=1, per_page=25)
    assert ares["total"] == 1
    assert ares["raw_total"] == 3
    assert len(ares["logs"]) == 1
    grp = ares["logs"][0]
    assert grp["uid"] == 24
    assert grp["event_count"] == 3
    assert grp["event_types"] == [
        {"event_type": "ADMIN_STATS_VIEW", "count": 2},
        {"event_type": "ADMIN_APP_ENABLED", "count": 1},
    ]
    assert any("DATE_TRUNC('minute', al.created_at)" in q for q in audit_queries)


def test_admin_user_counts_and_directory_exclude_test_users(monkeypatch):
    import api.admin as admin

    stats_queries = []
    users_queries = []
    roles_queries = []

    def fake_exec(q, p=None):
        norm = " ".join(str(q).split())
        if "COUNT(*) AS total_users" in norm:
            stats_queries.append(norm)
            return [{"total_users": 4, "new_users_today": 1, "active_users": 4, "administrators": 1}]
        if "SELECT COUNT(*) as cnt FROM users" in norm:
            users_queries.append(norm)
            return [{"cnt": 4}]
        if "SELECT uid, username, email, full_name" in norm:
            users_queries.append(norm)
            return [
                {"uid": 24, "username": "amy", "email": "amy492998@gmail.com", "full_name": "Amy Admin", "phone": "", "is_active": True, "c_date": "2026-11-25", "role": "admin"},
            ]
        if "GROUP BY role ORDER BY count DESC" in norm:
            roles_queries.append(norm)
            return [{"role": "user", "count": 3}, {"role": "admin", "count": 1}]
        return [{"cnt": 0, "unique_users": 0}]

    monkeypatch.setattr(admin, "cleanup_expired_sessions", lambda: None)
    monkeypatch.setattr(admin, "get_admin_connected_apps", lambda: {"summary": {}})
    monkeypatch.setattr(admin, "get_runtime_security_settings", lambda: {"mfa_required": False, "password_min_length": 8})
    monkeypatch.setattr(admin, "execute_query", fake_exec)

    stats = admin.get_admin_dashboard_stats()
    assert stats["total_users"] == 4
    assert stats["active_users"] == 4
    assert any("vaultauth\\.test" in q and "employee_" in q for q in stats_queries)

    users_res = admin.get_all_users_admin(page=1, per_page=20)
    assert users_res["total"] == 4
    assert all("vaultauth\\.test" in q for q in users_queries)

    roles_res = admin.get_roles_overview()
    assert roles_res["roles"][0]["count"] == 1
    assert any("vaultauth\\.test" in q for q in roles_queries)


def test_ensure_default_dashboard_data_does_not_seed_dummy_apps(monkeypatch):
    queries = []

    def fake_exec(q, p=None):
        norm = " ".join(str(q).split())
        queries.append(norm)
        if "SELECT id FROM user_security_settings" in norm:
            return []
        return ()

    monkeypatch.setattr(dashboard, "execute_query", fake_exec)
    dashboard.ensure_default_user_dashboard_data(99, {"uid": 99, "email": "realuser@gmail.com"})

    assert any("INSERT INTO user_security_settings" in q for q in queries)
    assert not any("INSERT INTO connected_apps" in q for q in queries)
