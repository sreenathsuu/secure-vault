# 🔐 SecureVault — Secure Data Sharing System

![MySQL](https://img.shields.io/badge/MySQL-8.0-4479A1?style=flat&logo=mysql&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-REST%20API-000000?style=flat&logo=flask)
![JWT](https://img.shields.io/badge/Auth-JWT-purple?style=flat)
![bcrypt](https://img.shields.io/badge/Passwords-bcrypt-green?style=flat)
![License](https://img.shields.io/badge/License-MIT-blue?style=flat)

> A file-sharing backend that enforces **who can access which file, when** — using Attribute-Based Access Control (ABAC) backed by a relational MySQL database.

---

## 📌 What This Project Does

Most systems check only **"is this user logged in?"**. SecureVault checks **four conditions** on every file request:

| Policy | Example |
|--------|---------|
| **Role** | Only `analyst` and `manager` can see Finance files |
| **Clearance Level** | Salary data needs CL3 — a CL1 viewer is denied |
| **Department** | HR files restricted to HR department only |
| **Time Window** | Server configs accessible only 09:00–18:00 |

Every access attempt — **granted or denied** — is recorded in `audit_log`. No attempt goes unlogged.

---

## 🗂️ Project Structure

```
securevault/
├── database/
│   └── schema.sql          # Full MySQL schema, seed data, views, procedure, trigger
├── backend/
│   ├── app.py              # Flask REST API (all routes)
│   ├── access_control.py   # ABAC + time-policy engine
│   ├── auth.py             # JWT login + route guard
│   ├── db.py               # MySQL connection pool
│   ├── config.py           # Environment config
│   └── requirements.txt    # Python dependencies
└── frontend/
    └── index.html          # Single-file UI (no build step needed)
```

---

## 🗄️ Database Schema

Four tables, each with a clear purpose:

```
┌─────────────────────────────────────────────────────────┐
│                        users                            │
│  id | name | email | password_hash | role | department  │
│       clearance_level | is_active | created_at          │
└──────────────────────────┬──────────────────────────────┘
                           │ user_id FK
                           ▼
┌─────────────────────────────────────────────────────────┐
│                      audit_log                          │
│  id | user_id | file_id | action | ip_address           │
│       access_result | denial_reason | attempted_at      │
└──────────────────────────┬──────────────────────────────┘
                           │ file_id FK
                           ▼
┌─────────────────────────────────────────────────────────┐
│                        files                            │
│  id | filename | department | min_clearance             │
│       dept_required | access_start | access_end         │
│       storage_path | uploaded_by | created_at           │
└──────────────────────────┬──────────────────────────────┘
                           │ file_id FK
                           ▼
┌─────────────────────────────────────────────────────────┐
│               file_role_permissions                     │
│  file_id (FK) | role                                    │
│  PRIMARY KEY (file_id, role)                            │
└─────────────────────────────────────────────────────────┘
```

### Extra database objects included:
| Object | Name | Purpose |
|--------|------|---------|
| **View** | `v_audit_log` | Human-readable audit log with user + file names joined |
| **View** | `v_user_access_summary` | Per-user grant/deny statistics with grant rate % |
| **Stored Procedure** | `get_accessible_files(user_id)` | Returns all files accessible to a user right now |
| **Trigger** | `trg_deactivate_audit` | Auto-logs to audit_log when a user account is deactivated |

---

## ⚙️ Core ABAC Query

This single query decides access — fully parameterized, no string interpolation:

```sql
SELECT f.id, f.filename, f.storage_path
FROM files f
JOIN file_role_permissions frp ON f.id = frp.file_id
JOIN users u ON u.id = %s              -- :user_id (parameterized)
WHERE f.id = %s                        -- :file_id (parameterized)
  AND frp.role = u.role                -- role check
  AND u.clearance_level >= f.min_clearance   -- clearance check
  AND (f.dept_required IS NULL OR f.dept_required = u.department)  -- dept check
  AND (CURTIME() BETWEEN f.access_start AND f.access_end);         -- time check
```

---

## 🚀 Setup

### 1. MySQL Database
```bash
mysql -u root -p < database/schema.sql
```
This creates the `securevault` database with all tables, views, procedures, triggers, and demo data.

### 2. Backend
```bash
cd backend
pip install -r requirements.txt

# Create a .env file:
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=yourpassword
SECRET_KEY=change-this-in-production

python app.py
# API running at http://localhost:5000
```

### 3. Frontend
```bash
# Open directly in browser — no build step needed
open frontend/index.html
```

---

## 👥 Demo Credentials

| Email | Password | Role | Department | Clearance |
|-------|----------|------|------------|-----------|
| arjun@company.com | admin123 | admin | Management | 3 |
| priya@company.com | analyst123 | analyst | Finance | 2 |
| kiran@company.com | viewer123 | viewer | HR | 1 |
| sneha@company.com | manager123 | manager | Finance | 2 |

> Passwords are stored as **bcrypt hashes** in the database. Plain-text passwords above are for demo login only.

---

## 🔌 API Endpoints

| Method | Route | Auth | Description |
|--------|-------|------|-------------|
| POST | `/api/login` | None | Login → JWT token |
| GET | `/api/me` | JWT | Current user profile |
| GET | `/api/files` | JWT | List all files with policies |
| POST | `/api/files/:id/request` | JWT | Evaluate ABAC + log result |
| GET | `/api/files/:id/download` | JWT | Download if access granted |
| POST | `/api/files/upload` | Admin | Upload file + set policy |
| GET | `/api/users` | Admin | List all users |
| POST | `/api/users` | Admin | Create user |
| DELETE | `/api/users/:id` | Admin | Deactivate user |
| GET | `/api/audit` | JWT | Audit log (admin=all, others=own) |

---

## 🛠️ Technologies

| Layer | Technology |
|-------|-----------|
| Database | MySQL 8.0 — RDBMS, schema design, Views, Stored Procedure, Trigger |
| Backend | Python 3.10 + Flask — REST API |
| Auth | JWT (JSON Web Tokens) — stateless authentication |
| DB Driver | mysql-connector-python — parameterized queries |
| Security | bcrypt — password hashing |
| Frontend | Vanilla JS + HTML/CSS — zero dependencies |

---

## 🔒 Security Notes

- All SQL inputs use **parameterized queries** — no string interpolation of user data anywhere
- Passwords stored as **bcrypt hashes** — never plain text
- JWT tokens expire and must be sent in `Authorization: Bearer <token>` header
- Every access attempt is logged — including denied ones — for full traceability

---

## 👤 Author

**Mallepalli Sreenath**  
MCA — Yogi Vemana University, Kadapa  
[GitHub](https://github.com/sreenathsuu)
