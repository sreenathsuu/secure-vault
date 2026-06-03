# auth.py — Login, JWT token creation and verification
import jwt
import bcrypt
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify, g
from config import SECRET_KEY, TOKEN_EXPIRE_H
from db import execute_query


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())


def create_token(user_id: int) -> str:
    payload = {
        "sub": user_id,
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(hours=TOKEN_EXPIRE_H),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def decode_token(token: str) -> dict:
    return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])


def login(email: str, password: str):
    """
    Authenticate user. Returns (token, user_dict) or raises ValueError.
    Parameterized query prevents SQL injection on the email field.
    """
    rows = execute_query(
        "SELECT id, name, email, password_hash, role, department, clearance_level "
        "FROM users WHERE email = %s AND is_active = TRUE",
        (email,)
    )
    if not rows:
        raise ValueError("Invalid credentials")

    user = rows[0]
    if not verify_password(password, user["password_hash"]):
        raise ValueError("Invalid credentials")

    token = create_token(user["id"])
    user.pop("password_hash", None)
    return token, user


# ── Decorator ─────────────────────────────────────────────────

def require_auth(f):
    """JWT guard for Flask routes."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing token"}), 401
        try:
            payload = decode_token(auth_header.split(" ", 1)[1])
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

        rows = execute_query(
            "SELECT id, name, email, role, department, clearance_level "
            "FROM users WHERE id = %s AND is_active = TRUE",
            (payload["sub"],)
        )
        if not rows:
            return jsonify({"error": "User not found"}), 401

        g.current_user = rows[0]
        return f(*args, **kwargs)
    return wrapper
