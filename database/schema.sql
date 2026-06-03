-- ============================================================
--  SecureVault — Secure Data Sharing System
--  Author: Sreenath Mallepalli
--  Database: MySQL
-- ============================================================

CREATE DATABASE IF NOT EXISTS securevault;
USE securevault;

-- ------------------------------------------------------------
-- USERS
-- ------------------------------------------------------------
CREATE TABLE users (
    id               INT             NOT NULL AUTO_INCREMENT,
    name             VARCHAR(100)    NOT NULL,
    email            VARCHAR(150)    NOT NULL UNIQUE,
    password_hash    VARCHAR(255)    NOT NULL,
    role             ENUM('admin','manager','analyst','viewer') NOT NULL DEFAULT 'viewer',
    department       VARCHAR(50)     NOT NULL,
    clearance_level  TINYINT         NOT NULL DEFAULT 1
                         CHECK (clearance_level BETWEEN 1 AND 3),
    is_active        BOOLEAN         NOT NULL DEFAULT TRUE,
    created_at       TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id)
);

-- ------------------------------------------------------------
-- FILES
-- ------------------------------------------------------------
CREATE TABLE files (
    id               INT             NOT NULL AUTO_INCREMENT,
    filename         VARCHAR(255)    NOT NULL,
    department       VARCHAR(50)     NOT NULL,
    description      TEXT,
    file_size        VARCHAR(20),
    storage_path     TEXT            NOT NULL,
    min_clearance    TINYINT         NOT NULL DEFAULT 1
                         CHECK (min_clearance BETWEEN 1 AND 3),
    dept_required    VARCHAR(50)     DEFAULT NULL,   -- NULL = open to all depts
    access_start     TIME            NOT NULL DEFAULT '00:00:00',
    access_end       TIME            NOT NULL DEFAULT '23:59:59',
    uploaded_by      INT             NOT NULL,
    created_at       TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    FOREIGN KEY (uploaded_by) REFERENCES users(id)
);

-- ------------------------------------------------------------
-- ROLE-LEVEL PERMISSIONS PER FILE
-- ------------------------------------------------------------
CREATE TABLE file_role_permissions (
    file_id  INT  NOT NULL,
    role     ENUM('admin','manager','analyst','viewer') NOT NULL,
    PRIMARY KEY (file_id, role),
    FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE
);

-- ------------------------------------------------------------
-- AUDIT LOG
-- ------------------------------------------------------------
CREATE TABLE audit_log (
    id             BIGINT       NOT NULL AUTO_INCREMENT,
    user_id        INT          NOT NULL,
    file_id        INT          NOT NULL,
    action         VARCHAR(20)  NOT NULL DEFAULT 'READ',
    ip_address     VARCHAR(45),
    user_agent     TEXT,
    access_result  ENUM('GRANTED','DENIED','TIME_LOCKED') NOT NULL,
    denial_reason  VARCHAR(255),
    attempted_at   TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (file_id)  REFERENCES files(id)
);

-- ------------------------------------------------------------
-- SEED DATA
-- ------------------------------------------------------------
INSERT INTO users (name, email, password_hash, role, department, clearance_level) VALUES
('Arjun Mehta',  'arjun@company.com',  '$2b$12$hash1', 'admin',   'IT',      3),
('Priya Rao',    'priya@company.com',  '$2b$12$hash2', 'analyst', 'Finance', 2),
('Kiran Reddy',  'kiran@company.com',  '$2b$12$hash3', 'viewer',  'HR',      1),
('Sneha Patel',  'sneha@company.com',  '$2b$12$hash4', 'manager', 'Finance', 2),
('Dev Kumar',    'dev@company.com',    '$2b$12$hash5', 'analyst', 'IT',      2);

INSERT INTO files (filename, department, description, file_size, storage_path, min_clearance, dept_required, access_start, access_end, uploaded_by) VALUES
('Q4_Financial_Report.pdf',   'Finance', 'Quarterly financial statements',  '2.4 MB', '/vault/finance/q4_report.pdf',    2, 'Finance', '09:00:00', '18:00:00', 1),
('Employee_Payroll_Data.xlsx', 'HR',      'Monthly payroll records',         '1.1 MB', '/vault/hr/payroll.xlsx',           2, NULL,      '08:00:00', '20:00:00', 1),
('System_Architecture.docx',  'IT',      'Internal system design docs',     '890 KB', '/vault/it/architecture.docx',      1, 'IT',      '00:00:00', '23:59:59', 1),
('Budget_Forecast_2025.xlsx', 'Finance', 'Annual budget — classified',      '3.2 MB', '/vault/finance/budget2025.xlsx',  3, 'Finance', '09:00:00', '17:00:00', 1),
('Security_Audit_Log.txt',    'IT',      'Complete system audit trail',     '560 KB', '/vault/it/audit.txt',              3, 'IT',      '00:00:00', '23:59:59', 1),
('HR_Policy_Manual.pdf',      'HR',      'Company HR policies — all staff', '1.8 MB', '/vault/hr/policy_manual.pdf',      1, NULL,      '00:00:00', '23:59:59', 1);

INSERT INTO file_role_permissions (file_id, role) VALUES
(1,'admin'),(1,'manager'),(1,'analyst'),
(2,'admin'),(2,'manager'),
(3,'admin'),(3,'analyst'),(3,'manager'),
(4,'admin'),(4,'manager'),
(5,'admin'),
(6,'admin'),(6,'manager'),(6,'analyst'),(6,'viewer');
