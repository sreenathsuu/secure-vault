-- ============================================================
--  SecureVault — Secure Data Sharing System
--  Author: Sreenath Mallepalli
--  Database: MySQL
--  Description: ABAC + Time-based access control schema
-- ============================================================

CREATE DATABASE IF NOT EXISTS securevault;
USE securevault;

-- ─────────────────────────────────────────────
--  TABLE: users
--  Stores all user accounts with ABAC attributes
-- ─────────────────────────────────────────────
CREATE TABLE users (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    name            VARCHAR(100)  NOT NULL,
    email           VARCHAR(150)  NOT NULL UNIQUE,
    password_hash   VARCHAR(255)  NOT NULL,
    role            ENUM('admin','manager','analyst','viewer') NOT NULL,
    department      VARCHAR(50)   NOT NULL,
    clearance_level TINYINT       NOT NULL DEFAULT 1,
    is_active       BOOLEAN       NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_email (email),
    INDEX idx_role  (role)
);

-- ─────────────────────────────────────────────
--  TABLE: files
--  Stores file metadata + access policy attributes
-- ─────────────────────────────────────────────
CREATE TABLE files (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    filename        VARCHAR(255)  NOT NULL,
    department      VARCHAR(50)   NOT NULL,
    description     TEXT,
    min_clearance   TINYINT       NOT NULL DEFAULT 1,
    dept_required   VARCHAR(50)   DEFAULT NULL,       -- NULL = any department can access
    access_start    TIME          NOT NULL DEFAULT '00:00:00',
    access_end      TIME          NOT NULL DEFAULT '23:59:59',
    storage_path    TEXT          DEFAULT NULL,
    file_size       VARCHAR(20)   DEFAULT 'N/A',
    uploaded_by     INT           DEFAULT NULL,
    created_at      TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (uploaded_by) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_dept (department)
);

-- ─────────────────────────────────────────────
--  TABLE: file_role_permissions
--  Maps which roles are allowed to request each file
-- ─────────────────────────────────────────────
CREATE TABLE file_role_permissions (
    file_id INT  NOT NULL,
    role    ENUM('admin','manager','analyst','viewer') NOT NULL,

    PRIMARY KEY (file_id, role),
    FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE
);

-- ─────────────────────────────────────────────
--  TABLE: audit_log
--  Records every access attempt — granted or denied
--  Never deleted; acts as immutable access history
-- ─────────────────────────────────────────────
CREATE TABLE audit_log (
    id              BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id         INT           DEFAULT NULL,
    file_id         INT           DEFAULT NULL,
    action          VARCHAR(20)   NOT NULL DEFAULT 'READ',
    ip_address      VARCHAR(45)   DEFAULT NULL,
    user_agent      VARCHAR(255)  DEFAULT NULL,
    access_result   ENUM('GRANTED','DENIED','TIME_LOCKED') NOT NULL,
    denial_reason   VARCHAR(255)  DEFAULT NULL,
    attempted_at    TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE SET NULL,
    INDEX idx_user_id (user_id),
    INDEX idx_file_id (file_id),
    INDEX idx_result  (access_result),
    INDEX idx_time    (attempted_at)
);

-- ============================================================
--  SEED DATA
-- ============================================================

-- ─────────────────────────────────────────────
--  Users — passwords are bcrypt hashed
--  Plain passwords (for reference):
--    admin123 | analyst123 | viewer123 | manager123
-- ─────────────────────────────────────────────
INSERT INTO users (name, email, password_hash, role, department, clearance_level) VALUES
('Arjun',   'arjun@company.com',   '$2b$12$hff6jaqCvulfyg46m.h3secqYqVnzxrdEhFZ2P1OebRcnkqp8sH9K', 'admin',   'Management', 3),
('Priya',   'priya@company.com',   '$2b$12$9l9Fhq.OEmJRVAhcx1f6BOsy65QFVkm0nPEcl8zxHU3.DklkFVWsW', 'analyst', 'Finance',    2),
('Kiran',   'kiran@company.com',   '$2b$12$WPyFH0TQeoXyzhveCq3LOewMw3PEOKqE2g7aYpMeqKIH0kUD/pQWi', 'viewer',  'HR',         1),
('Rahul',   'rahul@company.com',   '$2b$12$C9SBIWPJ4dLetGcW91ZyzOLvg8XGS2xScsi1SDZarwmBX9GXG4ira', 'manager', 'IT',         2),
('Sneha',   'sneha@company.com',   '$2b$12$C9SBIWPJ4dLetGcW91ZyzOLvg8XGS2xScsi1SDZarwmBX9GXG4ira', 'manager', 'Finance',    2),
('Amit',    'amit@company.com',    '$2b$12$9l9Fhq.OEmJRVAhcx1f6BOsy65QFVkm0nPEcl8zxHU3.DklkFVWsW', 'analyst', 'IT',         2),
('Neha',    'neha@company.com',    '$2b$12$WPyFH0TQeoXyzhveCq3LOewMw3PEOKqE2g7aYpMeqKIH0kUD/pQWi', 'viewer',  'HR',         1),
('Rohit',   'rohit@company.com',   '$2b$12$WPyFH0TQeoXyzhveCq3LOewMw3PEOKqE2g7aYpMeqKIH0kUD/pQWi', 'viewer',  'Operations', 1),
('Divya',   'divya@company.com',   '$2b$12$9l9Fhq.OEmJRVAhcx1f6BOsy65QFVkm0nPEcl8zxHU3.DklkFVWsW', 'analyst', 'Finance',    2),
('Vikram',  'vikram@company.com',  '$2b$12$WPyFH0TQeoXyzhveCq3LOewMw3PEOKqE2g7aYpMeqKIH0kUD/pQWi', 'viewer',  'IT',         1),
('Anjali',  'anjali@company.com',  '$2b$12$9l9Fhq.OEmJRVAhcx1f6BOsy65QFVkm0nPEcl8zxHU3.DklkFVWsW', 'analyst', 'HR',         2),
('Suresh',  'suresh@company.com',  '$2b$12$C9SBIWPJ4dLetGcW91ZyzOLvg8XGS2xScsi1SDZarwmBX9GXG4ira', 'manager', 'Operations', 2),
('Meera',   'meera@company.com',   '$2b$12$9l9Fhq.OEmJRVAhcx1f6BOsy65QFVkm0nPEcl8zxHU3.DklkFVWsW', 'analyst', 'Finance',    2),
('Karthik', 'karthik@company.com', '$2b$12$WPyFH0TQeoXyzhveCq3LOewMw3PEOKqE2g7aYpMeqKIH0kUD/pQWi', 'viewer',  'IT',         1),
('Isha',    'isha@company.com',    '$2b$12$9l9Fhq.OEmJRVAhcx1f6BOsy65QFVkm0nPEcl8zxHU3.DklkFVWsW', 'analyst', 'Finance',    2),
('Varun',   'varun@company.com',   '$2b$12$WPyFH0TQeoXyzhveCq3LOewMw3PEOKqE2g7aYpMeqKIH0kUD/pQWi', 'viewer',  'HR',         1),
('Pooja',   'pooja@company.com',   '$2b$12$C9SBIWPJ4dLetGcW91ZyzOLvg8XGS2xScsi1SDZarwmBX9GXG4ira', 'manager', 'Operations', 2),
('Manoj',   'manoj@company.com',   '$2b$12$9l9Fhq.OEmJRVAhcx1f6BOsy65QFVkm0nPEcl8zxHU3.DklkFVWsW', 'analyst', 'IT',         2),
('Rekha',   'rekha@company.com',   '$2b$12$WPyFH0TQeoXyzhveCq3LOewMw3PEOKqE2g7aYpMeqKIH0kUD/pQWi', 'viewer',  'Finance',    1),
('Admin2',  'admin2@company.com',  '$2b$12$hff6jaqCvulfyg46m.h3secqYqVnzxrdEhFZ2P1OebRcnkqp8sH9K', 'admin',   'Management', 3);

-- ─────────────────────────────────────────────
--  Files — with dept_required + time windows
-- ─────────────────────────────────────────────
INSERT INTO files (filename, department, description, min_clearance, dept_required, access_start, access_end, file_size) VALUES
('Budget.xlsx',        'Finance',    'Annual budget report',          2, 'Finance',    '09:00:00', '18:00:00', '1.2 MB'),
('Salary.xlsx',        'Finance',    'Employee salary data',          3, 'Finance',    '09:00:00', '17:00:00', '980 KB'),
('Tax.pdf',            'Finance',    'Tax filing documents',          3, 'Finance',    '09:00:00', '18:00:00', '2.1 MB'),
('HR_Policies.pdf',    'HR',         'Company HR policies',           1,  NULL,        '00:00:00', '23:59:59', '340 KB'),
('Recruitment.xlsx',   'HR',         'Open positions & hiring data',  1,  NULL,        '08:00:00', '20:00:00', '750 KB'),
('Employee_Data.xlsx', 'HR',         'Full employee records',         2, 'HR',         '09:00:00', '18:00:00', '1.8 MB'),
('Server_Config.docx', 'IT',         'Production server config',      3, 'IT',         '09:00:00', '18:00:00', '210 KB'),
('Security_Report.pdf','IT',         'Quarterly security audit',      3, 'IT',         '09:00:00', '17:30:00', '3.4 MB'),
('Network.png',        'IT',         'Network topology diagram',      2, 'IT',         '08:00:00', '20:00:00', '560 KB'),
('Logs.txt',           'IT',         'System access logs',            3, 'IT',         '00:00:00', '23:59:59', '4.7 MB'),
('Ops_Report.pdf',     'Operations', 'Monthly operations report',     2, 'Operations', '09:00:00', '18:00:00', '1.1 MB'),
('Supply.xlsx',        'Operations', 'Supply chain tracker',          2, 'Operations', '08:00:00', '19:00:00', '900 KB'),
('Vendor.xlsx',        'Operations', 'Approved vendor list',          1,  NULL,        '08:00:00', '20:00:00', '430 KB'),
('Strategy.pdf',       'Management', 'Company growth strategy',       3,  NULL,        '09:00:00', '18:00:00', '5.2 MB'),
('Roadmap.pdf',        'Management', 'Product roadmap 2025',          2,  NULL,        '08:00:00', '20:00:00', '2.8 MB'),
('Risk.pdf',           'Management', 'Risk analysis report',          3,  NULL,        '09:00:00', '17:00:00', '1.9 MB'),
('Audit.pdf',          'Finance',    'External audit report',         3, 'Finance',    '09:00:00', '18:00:00', '3.1 MB'),
('Training.pdf',       'HR',         'Onboarding training material',  1,  NULL,        '00:00:00', '23:59:59', '780 KB'),
('Assets.xlsx',        'IT',         'IT asset inventory',            2, 'IT',         '08:00:00', '18:00:00', '1.3 MB'),
('Expenses.xlsx',      'Finance',    'Department expense report',     2, 'Finance',    '09:00:00', '18:00:00', '650 KB'),
('Feedback.xlsx',      'HR',         'Employee satisfaction data',    1, 'HR',         '08:00:00', '20:00:00', '420 KB'),
('Plan.pdf',           'Management', 'Business continuity plan',      3,  NULL,        '09:00:00', '18:00:00', '4.0 MB'),
('Security.txt',       'IT',         'Security rules & procedures',   3, 'IT',         '09:00:00', '17:00:00', '180 KB'),
('Performance.xlsx',   'Operations', 'Team performance metrics',      2, 'Operations', '08:00:00', '18:00:00', '870 KB'),
('Overview.pdf',       'Management', 'Company overview deck',         2,  NULL,        '00:00:00', '23:59:59', '6.1 MB');

-- ─────────────────────────────────────────────
--  File Role Permissions
-- ─────────────────────────────────────────────
INSERT INTO file_role_permissions (file_id, role) VALUES
(1,'admin'),(1,'manager'),(1,'analyst'),
(2,'admin'),
(3,'admin'),
(4,'viewer'),(4,'analyst'),(4,'manager'),(4,'admin'),
(5,'viewer'),(5,'analyst'),(5,'admin'),
(6,'analyst'),(6,'manager'),(6,'admin'),
(7,'admin'),
(8,'admin'),
(9,'manager'),(9,'analyst'),(9,'admin'),
(10,'admin'),
(11,'manager'),(11,'admin'),
(12,'analyst'),(12,'admin'),
(13,'viewer'),(13,'analyst'),(13,'manager'),(13,'admin'),
(14,'admin'),
(15,'manager'),(15,'admin'),
(16,'admin'),
(17,'admin'),
(18,'viewer'),(18,'analyst'),(18,'manager'),(18,'admin'),
(19,'admin'),
(20,'manager'),(20,'analyst'),(20,'admin'),
(21,'viewer'),(21,'analyst'),(21,'admin'),
(22,'admin'),
(23,'admin'),
(24,'manager'),(24,'admin'),
(25,'admin'),(25,'manager'),(25,'analyst'),(25,'viewer');

-- ============================================================
--  VIEWS (for reporting & simplified queries)
-- ============================================================

-- View: human-readable audit log (joins user + file names)
CREATE OR REPLACE VIEW v_audit_log AS
SELECT
    al.id,
    al.attempted_at,
    u.name          AS user_name,
    u.email,
    u.role,
    u.department,
    f.filename,
    f.department    AS file_dept,
    al.action,
    al.ip_address,
    al.access_result,
    al.denial_reason
FROM audit_log al
LEFT JOIN users u ON al.user_id = u.id
LEFT JOIN files f ON al.file_id = f.id
ORDER BY al.attempted_at DESC;

-- View: access summary per user
CREATE OR REPLACE VIEW v_user_access_summary AS
SELECT
    u.id,
    u.name,
    u.role,
    u.department,
    u.clearance_level,
    COUNT(al.id)                                          AS total_attempts,
    SUM(al.access_result = 'GRANTED')                     AS granted_count,
    SUM(al.access_result = 'DENIED')                      AS denied_count,
    SUM(al.access_result = 'TIME_LOCKED')                 AS time_locked_count,
    ROUND(SUM(al.access_result = 'GRANTED') * 100.0
          / NULLIF(COUNT(al.id), 0), 1)                   AS grant_rate_pct
FROM users u
LEFT JOIN audit_log al ON u.id = al.user_id
GROUP BY u.id, u.name, u.role, u.department, u.clearance_level;

-- ============================================================
--  STORED PROCEDURE: get_accessible_files
--  Returns all files a given user CAN access right now
-- ============================================================
DELIMITER $$

CREATE PROCEDURE get_accessible_files(IN p_user_id INT)
BEGIN
    SELECT
        f.id,
        f.filename,
        f.department,
        f.description,
        f.min_clearance,
        f.dept_required,
        f.access_start,
        f.access_end,
        f.file_size
    FROM files f
    JOIN file_role_permissions frp ON f.id = frp.file_id
    JOIN users u ON u.id = p_user_id
    WHERE frp.role = u.role
      AND u.clearance_level >= f.min_clearance
      AND (f.dept_required IS NULL OR f.dept_required = u.department)
      AND (CURTIME() BETWEEN f.access_start AND f.access_end)
      AND u.is_active = TRUE;
END$$

DELIMITER ;

-- ============================================================
--  TRIGGER: trg_deactivate_audit
--  Automatically logs when a user account is deactivated
-- ============================================================
DELIMITER $$

CREATE TRIGGER trg_deactivate_audit
AFTER UPDATE ON users
FOR EACH ROW
BEGIN
    IF OLD.is_active = TRUE AND NEW.is_active = FALSE THEN
        INSERT INTO audit_log (user_id, file_id, action, access_result, denial_reason)
        VALUES (NEW.id, NULL, 'DEACTIVATE', 'DENIED', 'User account deactivated');
    END IF;
END$$

DELIMITER ;
