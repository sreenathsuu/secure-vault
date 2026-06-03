# app.py — SecureVault Flask API
# Routes: auth, file listing, access request, file upload, audit log, user management

import os
from flask import Flask, request, jsonify, g, send_file
from flask_cors import CORS
from werkzeug.utils import secure_filename

from config import UPLOAD_FOLDER, MAX_CONTENT_MB
from db import execute_query
from auth import require_auth, login, hash_password
from access_control import evaluate_access, log_access

app = Flask(__name__)
CORS(app)
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_MB * 1024 * 1024
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route("/")
def home():
    return jsonify({
        "status": "online",
        "service": "SecureVault API"
    })

@app.route("/health")
def health():
    return jsonify({
        "status": "healthy"
    })


# ══════════════════════════════════════════════════
#  AUTH
# ══════════════════════════════════════════════════

@app.route("/api/login", methods=["POST"])
def api_login():
    """POST { email, password } → { token, user }"""
    data = request.get_json(force=True)
    try:
        token, user = login(data.get("email", ""), data.get("password", ""))
        return jsonify({"token": token, "user": user})
    except ValueError as e:
        return jsonify({"error": str(e)}), 401


@app.route("/api/me", methods=["GET"])
@require_auth
def api_me():
    return jsonify(g.current_user)


# ══════════════════════════════════════════════════
#  FILES
# ══════════════════════════════════════════════════

@app.route("/api/files", methods=["GET"])
@require_auth
def api_files():
    """List all files with their policies (no content delivery)."""
    rows = execute_query("""
        SELECT f.id, f.filename, f.department, f.description,
               f.file_size, f.min_clearance, f.dept_required,
               f.access_start, f.access_end,
               GROUP_CONCAT(frp.role) AS allowed_roles
        FROM files f
        LEFT JOIN file_role_permissions frp ON frp.file_id = f.id
        GROUP BY f.id
        ORDER BY f.created_at DESC
    """)
    for r in rows:
        r["allowed_roles"] = r["allowed_roles"].split(",") if r["allowed_roles"] else []
        r["access_start"]  = str(r["access_start"])
        r["access_end"]    = str(r["access_end"])
    return jsonify(rows)


@app.route("/api/files/<int:file_id>/request", methods=["POST"])
@require_auth
def api_request_access(file_id):
    """
    POST → evaluate ABAC + time policies for the calling user.
    Logs the attempt to audit_log regardless of outcome.
    """
    user_id    = g.current_user["id"]
    ip_address = request.remote_addr
    user_agent = request.headers.get("User-Agent")

    result = evaluate_access(user_id, file_id)
    log_id = log_access(user_id, file_id, result, ip_address, user_agent)

    response = {
        "audit_log_id": log_id,
        "status":       result["status"],
        "reason":       result["reason"],
        "checks":       result["checks"],
    }

    if result["status"] == "GRANTED":
        return jsonify(response), 200
    elif result["status"] == "TIME_LOCKED":
        return jsonify(response), 403
    else:
        return jsonify(response), 403


@app.route("/api/files/<int:file_id>/download", methods=["GET"])
@require_auth
def api_download(file_id):
    """
    Download only if access is GRANTED at this moment.
    Every download attempt is re-evaluated and re-logged.
    """
    user_id = g.current_user["id"]
    result  = evaluate_access(user_id, file_id)
    log_access(user_id, file_id, result, request.remote_addr, request.headers.get("User-Agent"))

    if result["status"] != "GRANTED":
        return jsonify({"error": result["reason"], "status": result["status"]}), 403

    file_path = result["file"]["storage_path"]
    if not os.path.exists(file_path):
        return jsonify({"error": "File not found on server"}), 404

    return send_file(file_path, as_attachment=True,
                     download_name=result["file"]["filename"])


@app.route("/api/files/upload", methods=["POST"])
@require_auth
def api_upload():
    """Upload a file and register its ABAC policy. Admin only."""
    if g.current_user["role"] != "admin":
        return jsonify({"error": "Admin access required"}), 403

    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    f    = request.files["file"]
    name = secure_filename(f.filename)
    dest = os.path.join(UPLOAD_FOLDER, name)
    f.save(dest)

    form = request.form
    file_id = execute_query("""
        INSERT INTO files
            (filename, department, description, file_size, storage_path,
             min_clearance, dept_required, access_start, access_end, uploaded_by)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """, (
        name,
        form.get("department", "General"),
        form.get("description", ""),
        f"{os.path.getsize(dest) // 1024} KB",
        dest,
        int(form.get("min_clearance", 1)),
        form.get("dept_required") or None,
        form.get("access_start", "00:00:00"),
        form.get("access_end",   "23:59:59"),
        g.current_user["id"],
    ), fetch=False)

    roles = form.getlist("roles") or ["admin"]
    for role in roles:
        execute_query(
            "INSERT IGNORE INTO file_role_permissions (file_id, role) VALUES (%s, %s)",
            (file_id, role), fetch=False
        )

    return jsonify({"file_id": file_id, "message": "Uploaded successfully"}), 201


# ══════════════════════════════════════════════════
#  USERS  (admin only)
# ══════════════════════════════════════════════════

@app.route("/api/users", methods=["GET"])
@require_auth
def api_users():
    if g.current_user["role"] != "admin":
        return jsonify({"error": "Forbidden"}), 403
    rows = execute_query(
        "SELECT id, name, email, role, department, clearance_level, is_active, created_at "
        "FROM users ORDER BY id"
    )
    return jsonify(rows)


@app.route("/api/users", methods=["POST"])
@require_auth
def api_create_user():
    if g.current_user["role"] != "admin":
        return jsonify({"error": "Forbidden"}), 403
    data = request.get_json(force=True)
    uid = execute_query("""
        INSERT INTO users (name, email, password_hash, role, department, clearance_level)
        VALUES (%s, %s, %s, %s, %s, %s)
    """, (
        data["name"],
        data["email"],
        hash_password(data["password"]),
        data.get("role", "viewer"),
        data.get("department", "General"),
        int(data.get("clearance_level", 1)),
    ), fetch=False)
    return jsonify({"user_id": uid, "message": "User created"}), 201


@app.route("/api/users/<int:uid>", methods=["DELETE"])
@require_auth
def api_delete_user(uid):
    if g.current_user["role"] != "admin":
        return jsonify({"error": "Forbidden"}), 403
    execute_query(
        "UPDATE users SET is_active = FALSE WHERE id = %s",
        (uid,), fetch=False
    )
    return jsonify({"message": "User deactivated"})


# ══════════════════════════════════════════════════
#  AUDIT LOG
# ══════════════════════════════════════════════════

@app.route("/api/audit", methods=["GET"])
@require_auth
def api_audit():
    """
    Admins see all logs.
    Other users see only their own logs.
    """
    user = g.current_user
    limit = min(int(request.args.get("limit", 100)), 500)

    if user["role"] == "admin":
        rows = execute_query("""
            SELECT al.id, al.attempted_at, u.name AS user_name, u.role,
                   f.filename, al.action, al.ip_address,
                   al.access_result, al.denial_reason
            FROM audit_log al
            JOIN users u ON u.id = al.user_id
            JOIN files f ON f.id = al.file_id
            ORDER BY al.attempted_at DESC
            LIMIT %s
        """, (limit,))
    else:
        rows = execute_query("""
            SELECT al.id, al.attempted_at, u.name AS user_name, u.role,
                   f.filename, al.action, al.ip_address,
                   al.access_result, al.denial_reason
            FROM audit_log al
            JOIN users u ON u.id = al.user_id
            JOIN files f ON f.id = al.file_id
            WHERE al.user_id = %s
            ORDER BY al.attempted_at DESC
            LIMIT %s
        """, (user["id"], limit))

    for r in rows:
        r["attempted_at"] = str(r["attempted_at"])
    return jsonify(rows)


# ══════════════════════════════════════════════════
#  RUN
# ══════════════════════════════════════════════════

@app.route("/")
def home():
    return jsonify({
        "status": "online",
        "service": "SecureVault API"
    })
    
    if __name__ == "__main__":
         app.run(
             debug=False,
             host="0.0.0.0",
             port=int(os.environ.get("PORT", 5000)) 
         )
    
