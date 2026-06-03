-- ============================================================
--  SecureVault — Secure Data Sharing System
--  Author: Sreenath Mallepalli
--  Database: MySQL
-- ============================================================

CREATE DATABASE IF NOT EXISTS securevault;
USE securevault;


CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100),
    email VARCHAR(150) UNIQUE,
    password_hash VARCHAR(255),
    role ENUM('admin','manager','analyst','viewer'),
    department VARCHAR(50),
    clearance_level TINYINT
);

INSERT INTO users (name,email,password_hash,role,department,clearance_level) VALUES
('Arjun','arjun@company.com','admin123','admin','Management',3),
('Priya','priya@company.com','analyst123','analyst','Finance',2),
('Kiran','kiran@company.com','viewer123','viewer','HR',1),
('Rahul','rahul@company.com','manager123','manager','IT',2),
('Sneha','sneha@company.com','manager123','manager','Finance',2),
('Amit','amit@company.com','analyst123','analyst','IT',2),
('Neha','neha@company.com','viewer123','viewer','HR',1),
('Rohit','rohit@company.com','viewer123','viewer','Operations',1),
('Divya','divya@company.com','analyst123','analyst','Finance',2),
('Vikram','vikram@company.com','viewer123','viewer','IT',1),
('Anjali','anjali@company.com','analyst123','analyst','HR',2),
('Suresh','suresh@company.com','manager123','manager','Operations',2),
('Meera','meera@company.com','analyst123','analyst','Finance',2),
('Karthik','karthik@company.com','viewer123','viewer','IT',1),
('Isha','isha@company.com','analyst123','analyst','Finance',2),
('Varun','varun@company.com','viewer123','viewer','HR',1),
('Pooja','pooja@company.com','manager123','manager','Operations',2),
('Manoj','manoj@company.com','analyst123','analyst','IT',2),
('Rekha','rekha@company.com','viewer123','viewer','Finance',1),
('Admin2','admin2@company.com','admin123','admin','Management',3);


CREATE TABLE files (
    id INT AUTO_INCREMENT PRIMARY KEY,
    filename VARCHAR(255),
    department VARCHAR(50),
    description TEXT,
    min_clearance TINYINT
);

INSERT INTO files (filename,department,description,min_clearance) VALUES
('Budget.xlsx','Finance','Budget report',2),
('Salary.xlsx','Finance','Salary data',3),
('Tax.pdf','Finance','Tax docs',3),
('HR_Policies.pdf','HR','Policies',1),
('Recruitment.xlsx','HR','Hiring data',1),
('Employee_Data.xlsx','HR','Employee records',2),
('Server_Config.docx','IT','System config',3),
('Security_Report.pdf','IT','Security audit',3),
('Network.png','IT','Network diagram',2),
('Logs.txt','IT','System logs',3),
('Ops_Report.pdf','Operations','Operations report',2),
('Supply.xlsx','Operations','Supply chain',2),
('Vendor.xlsx','Operations','Vendor list',1),
('Strategy.pdf','Management','Strategy doc',3),
('Roadmap.pdf','Management','Roadmap',2),
('Risk.pdf','Management','Risk analysis',3),
('Audit.pdf','Finance','Audit report',3),
('Training.pdf','HR','Training material',1),
('Assets.xlsx','IT','IT assets',2),
('Expenses.xlsx','Finance','Expense report',2),
('Feedback.xlsx','HR','Employee feedback',1),
('Plan.pdf','Management','Business plan',3),
('Security.txt','IT','Security rules',3),
('Performance.xlsx','Operations','Performance data',2),
('Overview.pdf','Management','Company overview',2);

CREATE TABLE file_role_permissions (
    file_id INT,
    role VARCHAR(20)
);

INSERT INTO file_role_permissions VALUES
(1,'admin'),(1,'manager'),(1,'analyst'),
(2,'admin'),
(3,'admin'),
(4,'viewer'),(4,'analyst'),(4,'manager'),
(5,'viewer'),(5,'analyst'),
(6,'analyst'),(6,'manager'),
(7,'admin'),
(8,'admin'),
(9,'manager'),(9,'analyst'),
(10,'admin'),
(11,'manager'),
(12,'analyst'),
(13,'viewer'),
(14,'admin'),
(15,'manager'),
(16,'admin'),
(17,'admin'),
(18,'viewer'),
(19,'admin'),
(20,'manager'),
(21,'viewer'),
(22,'admin'),
(23,'admin'),
(24,'manager'),
(25,'admin');