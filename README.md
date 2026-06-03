# SecureVault — Secure Data Sharing System
### Attribute-Based Access Control (ABAC) + Time-Based Policies
**By Sreenath Mallepalli** | MCA, Yogi Vemana University

---

## Project Overview

A secure file-sharing backend that enforces who can access which files based on:
- **Role** (admin / manager / analyst / viewer)
- **Clearance level** (1, 2, or 3)
- **Department restriction** (e.g. Finance-only files)
- **Time window** (e.g. accessible only 09:00–18:00)

Every access attempt — granted or denied — is logged to an audit table.
All SQL queries are **parameterized** to prevent SQL injection.

---

## Project Structure

```
securevault/
├── database/
│   └── schema.sql          # Full MySQL schema + seed data
├── backend/
│   ├── app.py              # Flask REST API (all routes)
│   ├── access_control.py   # ABAC + time-policy engine
│   ├── auth.py             # JWT login + route guard
│   ├── db.py               # MySQL connection pool
│   ├── config.py           # Environment config
│   └── requirements.txt    # Python dependencies
└── frontend/
    └── index.html          # Single-file UI (no build step)
```

---

## Setup

### 1. MySQL Database

```bash
mysql -u root -p < database/schema.sql
```

This creates the `securevault` database with all tables and demo users.

### 2. Backend

```bash
cd backend
pip install -r requirements.txt

# Set environment variables (or create a .env file)
export DB_HOST=localhost
export DB_USER=root
export DB_PASSWORD=yourpassword
export SECRET_KEY=change-this-in-prod

python app.py
# API running at http://localhost:5000
```

### 3. Frontend

Open `frontend/index.html` directly in a browser — no build step needed.

---

## Demo Credentials (from seed data)

| Email | Password | Role | Dept | Clearance |
|---|---|---|---|---|
| arjun@company.com | admin123 | admin | IT | 3 |
| priya@company.com | analyst123 | analyst | Finance | 2 |
| kiran@company.com | viewer123 | viewer | HR | 1 |
| sneha@company.com | manager123 | manager | Finance | 2 |
| dev@company.com | analyst123 | analyst | IT | 2 |

---

## API Endpoints

| Method | Route | Auth | Description |
|---|---|---|---|
| POST | /api/login | None | Login → JWT token |
| GET | /api/me | JWT | Current user profile |
| GET | /api/files | JWT | List all files + policies |
| POST | /api/files/:id/request | JWT | Evaluate ABAC access + log |
| GET | /api/files/:id/download | JWT | Download if access granted |
| POST | /api/files/upload | Admin JWT | Upload file + set policy |
| GET | /api/users | Admin JWT | List all users |
| POST | /api/users | Admin JWT | Create user |
| DELETE | /api/users/:id | Admin JWT | Deactivate user |
| GET | /api/audit | JWT | Audit log (admin=all, others=own) |

---

## Core ABAC Query

```sql
SELECT f.id, f.filename, f.storage_path
FROM files f
JOIN file_role_permissions frp ON f.id = frp.file_id
JOIN users u ON u.id = %s          -- parameterized: user_id
WHERE f.id = %s                    -- parameterized: file_id
  AND frp.role = u.role
  AND u.clearance_level >= f.min_clearance
  AND (f.dept_required IS NULL OR f.dept_required = u.department)
  AND (CURTIME() BETWEEN f.access_start AND f.access_end);
```

All inputs are parameterized — no string interpolation of user data anywhere.

---

## Technologies

- **MySQL** — relational database, schema design, ACID transactions
- **Python + Flask** — REST API, JWT auth
- **mysql-connector-python** — parameterized queries
- **bcrypt** — password hashing
- **Vanilla JS** — frontend (zero dependencies, no build step)
