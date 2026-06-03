# access_control.py — Attribute-Based Access Control (ABAC) engine
# Enforces: role check, clearance level, department restriction, time window

from datetime import datetime
from db import execute_query


# ─────────────────────────────────────────────
#  Core ABAC evaluation
# ─────────────────────────────────────────────

def evaluate_access(user_id: int, file_id: int) -> dict:
    """
    Evaluate whether user_id may access file_id.

    Returns:
        {
          "status":  "GRANTED" | "DENIED" | "TIME_LOCKED",
          "reason":  str,
          "checks":  list[dict]   # detailed per-policy result
        }
    """
    user = _get_user(user_id)
    if not user:
        return _deny("User not found", [])

    file = _get_file(file_id)
    if not file:
        return _deny("File not found", [])

    checks = []

    # 1. Role check
    allowed_roles = _get_allowed_roles(file_id)
    role_ok = user["role"] in allowed_roles
    checks.append({
        "policy":  "Role",
        "passed":  role_ok,
        "detail":  f"User role '{user['role']}' — allowed: {allowed_roles}",
    })

    # 2. Clearance level
    clearance_ok = user["clearance_level"] >= file["min_clearance"]
    checks.append({
        "policy":  "Clearance",
        "passed":  clearance_ok,
        "detail":  f"User CL {user['clearance_level']} — required CL {file['min_clearance']}+",
    })

    # 3. Department restriction
    dept_required = file["dept_required"]
    dept_ok = dept_required is None or dept_required == user["department"]
    checks.append({
        "policy":  "Department",
        "passed":  dept_ok,
        "detail":  f"Required: {dept_required or 'any'} — User: {user['department']}",
    })

    # 4. Time window
    now = datetime.now().time()
    time_ok = file["access_start"] <= now <= file["access_end"]
    checks.append({
        "policy":  "Time Window",
        "passed":  time_ok,
        "detail":  f"Window: {file['access_start']}–{file['access_end']} | Now: {now.strftime('%H:%M')}",
    })

    # ── Determine result ──────────────────────────────────────
    if not role_ok:
        status, reason = "DENIED",      "Insufficient role"
    elif not clearance_ok:
        status, reason = "DENIED",      "Insufficient clearance level"
    elif not dept_ok:
        status, reason = "DENIED",      f"Restricted to {dept_required} department"
    elif not time_ok:
        status, reason = "TIME_LOCKED", f"Access only between {file['access_start']} and {file['access_end']}"
    else:
        status, reason = "GRANTED",     "All policies satisfied"

    return {"status": status, "reason": reason, "checks": checks,
            "user": user, "file": file}


# ─────────────────────────────────────────────
#  Audit logging
# ─────────────────────────────────────────────

def log_access(user_id: int, file_id: int, result: dict,
               ip_address: str = None, user_agent: str = None) -> int:
    """
    Insert an audit record for every access attempt, regardless of outcome.
    Uses parameterized query — no string interpolation of user data.
    """
    query = """
        INSERT INTO audit_log
            (user_id, file_id, action, ip_address, user_agent, access_result, denial_reason)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    """
    params = (
        user_id,
        file_id,
        "READ",
        ip_address,
        user_agent,
        result["status"],
        result["reason"] if result["status"] != "GRANTED" else None,
    )
    return execute_query(query, params, fetch=False)


# ─────────────────────────────────────────────
#  Helpers (all parameterized)
# ─────────────────────────────────────────────

def _get_user(user_id: int):
    rows = execute_query(
        "SELECT id, name, email, role, department, clearance_level "
        "FROM users WHERE id = %s AND is_active = TRUE",
        (user_id,)
    )
    return rows[0] if rows else None


def _get_file(file_id: int):
    rows = execute_query(
        "SELECT id, filename, department, min_clearance, dept_required, "
        "       access_start, access_end, storage_path "
        "FROM files WHERE id = %s",
        (file_id,)
    )
    return rows[0] if rows else None


def _get_allowed_roles(file_id: int) -> list:
    rows = execute_query(
        "SELECT role FROM file_role_permissions WHERE file_id = %s",
        (file_id,)
    )
    return [r["role"] for r in rows]


def _deny(reason: str, checks: list) -> dict:
    return {"status": "DENIED", "reason": reason, "checks": checks}
