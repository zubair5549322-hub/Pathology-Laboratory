// db.js - Database layer using Node.js built-in node:sqlite (Node 22+)
'use strict';
const { DatabaseSync } = require('node:sqlite');
const path = require('path');
const fs = require('fs');

const DB_PATH = path.join(__dirname, 'data', 'lims.db');
fs.mkdirSync(path.join(__dirname, 'data'), { recursive: true });

const db = new DatabaseSync(DB_PATH);
db.exec('PRAGMA foreign_keys = ON;');
db.exec('PRAGMA journal_mode = WAL;');

const SCHEMA = `
CREATE TABLE IF NOT EXISTS roles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT UNIQUE NOT NULL,
  permissions TEXT NOT NULL DEFAULT '[]' -- JSON array of permission strings
);

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  full_name TEXT NOT NULL,
  email TEXT,
  role_id INTEGER NOT NULL REFERENCES roles(id),
  password_hash TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active', -- active/disabled/locked
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  last_login TEXT
);

CREATE TABLE IF NOT EXISTS doctors (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  code TEXT UNIQUE,
  name TEXT NOT NULL,
  specialty TEXT,
  mobile TEXT,
  email TEXT,
  hospital_clinic TEXT,
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS employees (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  employee_code TEXT UNIQUE NOT NULL,
  full_name TEXT NOT NULL,
  employee_type TEXT NOT NULL DEFAULT 'Employee',
  designation TEXT,
  department_id INTEGER REFERENCES departments(id),
  qualification TEXT,
  cnic TEXT,
  mobile TEXT,
  email TEXT,
  joining_date TEXT,
  status TEXT NOT NULL DEFAULT 'active',
  notes TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS patients (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  patient_code TEXT UNIQUE NOT NULL, -- e.g. LAB-2026-000001
  name TEXT NOT NULL,
  guardian_name TEXT,
  gender TEXT,
  dob TEXT,
  age_years INTEGER,
  cnic TEXT,
  mobile TEXT,
  email TEXT,
  address TEXT,
  blood_group TEXT,
  category TEXT DEFAULT 'General', -- General/Corporate/Insurance
  notes TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS departments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT UNIQUE NOT NULL,
  status TEXT NOT NULL DEFAULT 'active'
);

CREATE TABLE IF NOT EXISTS tests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  code TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  department_id INTEGER REFERENCES departments(id),
  sample_type TEXT,
  unit TEXT,
  method TEXT,
  ref_low REAL,
  ref_high REAL,
  ref_text TEXT, -- for non-numeric ranges / notes
  critical_low REAL,
  critical_high REAL,
  result_type TEXT NOT NULL DEFAULT 'numeric', -- numeric/text/select
  price REAL NOT NULL DEFAULT 0,
  tat_hours REAL DEFAULT 24,
  active INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_code TEXT UNIQUE NOT NULL,
  patient_id INTEGER NOT NULL REFERENCES patients(id),
  doctor_id INTEGER REFERENCES doctors(id),
  patient_type TEXT NOT NULL DEFAULT 'OPD', -- OPD/IPD/Emergency
  priority TEXT NOT NULL DEFAULT 'Routine', -- Routine/STAT/Emergency
  status TEXT NOT NULL DEFAULT 'Ordered',
  created_by INTEGER REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS order_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_id INTEGER NOT NULL REFERENCES orders(id),
  test_id INTEGER NOT NULL REFERENCES tests(id),
  price REAL NOT NULL,
  discount REAL NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'Ordered' -- Ordered/Collected/Received/Rejected/Resulted/Verified/Authorized/Reported
);

CREATE TABLE IF NOT EXISTS invoices (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  invoice_code TEXT UNIQUE NOT NULL,
  order_id INTEGER NOT NULL REFERENCES orders(id),
  patient_id INTEGER NOT NULL REFERENCES patients(id),
  subtotal REAL NOT NULL,
  discount REAL NOT NULL DEFAULT 0,
  tax REAL NOT NULL DEFAULT 0,
  net_amount REAL NOT NULL,
  paid_amount REAL NOT NULL DEFAULT 0,
  balance REAL NOT NULL,
  status TEXT NOT NULL DEFAULT 'Unpaid', -- Unpaid/Partial/Paid/Cancelled
  created_by INTEGER REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS payments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  invoice_id INTEGER NOT NULL REFERENCES invoices(id),
  amount REAL NOT NULL,
  method TEXT NOT NULL DEFAULT 'Cash',
  received_by INTEGER REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS expenses (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  expense_code TEXT UNIQUE NOT NULL,
  expense_date TEXT NOT NULL DEFAULT (date('now')),
  category TEXT NOT NULL,
  description TEXT,
  vendor TEXT,
  payment_method TEXT NOT NULL DEFAULT 'Cash',
  amount REAL NOT NULL CHECK(amount >= 0),
  notes TEXT,
  created_by INTEGER REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS samples (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sample_code TEXT UNIQUE NOT NULL,
  order_id INTEGER NOT NULL REFERENCES orders(id),
  order_item_id INTEGER REFERENCES order_items(id),
  sample_type TEXT,
  status TEXT NOT NULL DEFAULT 'Pending Collection',
  collected_by INTEGER REFERENCES users(id),
  collected_at TEXT,
  received_at TEXT,
  rejection_reason TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS results (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_item_id INTEGER NOT NULL REFERENCES order_items(id),
  sample_id INTEGER REFERENCES samples(id),
  value TEXT,
  flag TEXT, -- Normal/High/Low/Critical-High/Critical-Low
  ref_low REAL,
  ref_high REAL,
  entered_by INTEGER REFERENCES users(id),
  entered_at TEXT NOT NULL DEFAULT (datetime('now')),
  verified_by INTEGER REFERENCES users(id),
  verified_at TEXT,
  authorized_by INTEGER REFERENCES users(id),
  authorized_at TEXT,
  status TEXT NOT NULL DEFAULT 'Entered' -- Entered/Verified/Authorized/Corrected
);

CREATE TABLE IF NOT EXISTS result_authorizers (
  result_id INTEGER PRIMARY KEY REFERENCES results(id) ON DELETE CASCADE,
  employee_id INTEGER NOT NULL REFERENCES employees(id),
  assigned_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS result_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  result_id INTEGER NOT NULL REFERENCES results(id),
  old_value TEXT,
  new_value TEXT,
  reason TEXT,
  changed_by INTEGER REFERENCES users(id),
  changed_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS critical_results (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  result_id INTEGER NOT NULL REFERENCES results(id),
  order_item_id INTEGER NOT NULL REFERENCES order_items(id),
  patient_id INTEGER NOT NULL REFERENCES patients(id),
  test_id INTEGER NOT NULL REFERENCES tests(id),
  value TEXT,
  threshold TEXT,
  direction TEXT, -- High/Low
  status TEXT NOT NULL DEFAULT 'Detected', -- Detected/Notified/Acknowledged/Closed
  detected_at TEXT NOT NULL DEFAULT (datetime('now')),
  notified_person TEXT,
  notified_by INTEGER REFERENCES users(id),
  notified_at TEXT,
  acknowledged_at TEXT,
  closed_at TEXT,
  remarks TEXT
);

CREATE TABLE IF NOT EXISTS reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  report_code TEXT UNIQUE NOT NULL,
  order_id INTEGER NOT NULL REFERENCES orders(id),
  version INTEGER NOT NULL DEFAULT 1,
  status TEXT NOT NULL DEFAULT 'Released', -- Released/Corrected/Superseded
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  authorized_by INTEGER REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS inventory_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  code TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  category TEXT,
  unit TEXT,
  reorder_level REAL DEFAULT 0,
  stock_qty REAL NOT NULL DEFAULT 0,
  active INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS inventory_transactions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  item_id INTEGER NOT NULL REFERENCES inventory_items(id),
  type TEXT NOT NULL, -- Receipt/Issue/Adjustment/Waste
  quantity REAL NOT NULL,
  batch TEXT,
  expiry TEXT,
  reason TEXT,
  created_by INTEGER REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  username TEXT,
  action TEXT NOT NULL,
  module TEXT,
  record_ref TEXT,
  details TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS counters (
  name TEXT PRIMARY KEY,
  value INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS app_settings (
  key TEXT PRIMARY KEY,
  value TEXT
);
`;

db.exec(SCHEMA);
// Backward-compatible migrations for existing installations.
try { db.exec('ALTER TABLE results ADD COLUMN remarks TEXT'); } catch (e) { if (!String(e.message||e).includes('duplicate column name')) throw e; }

function nextNumber(name, prefix) {
  const year = new Date().getFullYear();
  const key = `${name}-${year}`;
  db.exec(`INSERT INTO counters (name, value) VALUES ('${key}', 0) ON CONFLICT(name) DO NOTHING;`);
  db.prepare(`UPDATE counters SET value = value + 1 WHERE name = ?`).run(key);
  const row = db.prepare(`SELECT value FROM counters WHERE name = ?`).get(key);
  const num = String(row.value).padStart(6, '0');
  return `${prefix}-${year}-${num}`;
}

// ---- Seed data (only if empty) ----
function seed() {
  const roleCount = db.prepare('SELECT COUNT(*) c FROM roles').get().c;
  if (roleCount === 0) {
    const insRole = db.prepare('INSERT INTO roles (name, permissions) VALUES (?, ?)');
    const ALL = JSON.stringify(['*']);
    insRole.run('Administrator', ALL);
    insRole.run('Receptionist', JSON.stringify(['patient.create','patient.view','order.create','invoice.create','payment.create']));
    insRole.run('Phlebotomist', JSON.stringify(['sample.collect','sample.view']));
    insRole.run('Technician', JSON.stringify(['result.enter','sample.receive','result.view']));
    insRole.run('Pathologist', JSON.stringify(['result.verify','result.authorize','report.release','critical.manage']));
    insRole.run('Cashier', JSON.stringify(['payment.create','invoice.view']));
  }
  const userCount = db.prepare('SELECT COUNT(*) c FROM users').get().c;
  if (userCount === 0) {
    const { hashPassword } = require('./auth');
    const adminRole = db.prepare("SELECT id FROM roles WHERE name = 'Administrator'").get();
    db.prepare('INSERT INTO users (username, full_name, email, role_id, password_hash) VALUES (?,?,?,?,?)')
      .run('admin', 'System Administrator', 'admin@lab.local', adminRole.id, hashPassword('admin123'));
  }
  const deptCount = db.prepare('SELECT COUNT(*) c FROM departments').get().c;
  if (deptCount === 0) {
    const ins = db.prepare('INSERT INTO departments (name) VALUES (?)');
    ['Hematology','Clinical Chemistry','Microbiology','Serology','Histopathology'].forEach(d => ins.run(d));
  }
  const testCount = db.prepare('SELECT COUNT(*) c FROM tests').get().c;
  if (testCount === 0) {
    const heme = db.prepare("SELECT id FROM departments WHERE name='Hematology'").get().id;
    const chem = db.prepare("SELECT id FROM departments WHERE name='Clinical Chemistry'").get().id;
    const ins = db.prepare(`INSERT INTO tests (code,name,department_id,sample_type,unit,ref_low,ref_high,critical_low,critical_high,result_type,price)
      VALUES (?,?,?,?,?,?,?,?,?,?,?)`);
    ins.run('HB','Hemoglobin',heme,'Blood','g/dL',13,17,6,20,'numeric',300);
    ins.run('WBC','White Blood Cell Count',heme,'Blood','x10^9/L',4,11,1.5,30,'numeric',350);
    ins.run('PLT','Platelet Count',heme,'Blood','x10^9/L',150,450,20,1000,'numeric',350);
    ins.run('GLU','Glucose (Fasting)',chem,'Serum','mg/dL',70,100,40,500,'numeric',250);
    ins.run('K','Potassium',chem,'Serum','mmol/L',3.5,5.1,2.5,6.5,'numeric',400);
    ins.run('CREAT','Creatinine',chem,'Serum','mg/dL',0.6,1.3,null,4,'numeric',400);
  }
  const doctorCount = db.prepare('SELECT COUNT(*) c FROM doctors').get().c;
  if (doctorCount === 0) {
    db.prepare('INSERT INTO doctors (code,name,specialty,mobile) VALUES (?,?,?,?)')
      .run('DOC-0001','Dr. Ayesha Khan','Internal Medicine','03000000000');
  }
  const settingDefaults = {
    mode: 'demo',
    lab_name: 'IQRA GROUP OF LABORATORY',
    lab_address: 'Main Bazar Taty Pur, Qadir Pur Rawan Road, Multan',
    lab_phone: '0301-5549322, 0302-7326325',
    lab_email: 'hafizsaleem2959@gmail.com'
  };
  for (const [k, v] of Object.entries(settingDefaults)) {
    db.prepare('INSERT INTO app_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO NOTHING').run(k, v);
  }
  const invItemCount = db.prepare('SELECT COUNT(*) c FROM inventory_items').get().c;
  if (invItemCount === 0) {
    const ins = db.prepare('INSERT INTO inventory_items (code,name,category,unit,reorder_level,stock_qty) VALUES (?,?,?,?,?,?)');
    ins.run('ITM-0001','Glucose Reagent Kit','Reagents','kit',5,20);
    ins.run('ITM-0002','EDTA Tubes','Consumables','box',10,50);
    ins.run('ITM-0003','Disposable Syringes 5ml','Consumables','box',10,30);
  }
}
seed();

// Keep built-in role permissions up to date for existing databases as well as new installs.
(function migrateRolePermissions(){
  const rolePerms = {
    'Administrator': ['*'],
    'Receptionist': ['patient.create','patient.view','order.create','invoice.create','invoice.view','payment.create','payment.view','report.view','report.print'],
    'Phlebotomist': ['sample.collect','sample.view','sample.receive'],
    'Technician': ['sample.view','sample.receive','result.enter','result.view','inventory.view','inventory.transaction'],
    'Pathologist': ['result.view','result.verify','result.authorize','report.view','report.print','report.release','critical.manage'],
    'Cashier': ['invoice.view','payment.create','payment.view','report.view','report.print']
  };
  for (const [name, perms] of Object.entries(rolePerms)) {
    const row = db.prepare('SELECT permissions FROM roles WHERE name=?').get(name);
    if (!row) continue;
    let old=[]; try { old=JSON.parse(row.permissions||'[]'); } catch(e) {}
    const merged = name === 'Administrator' ? ['*'] : [...new Set([...old, ...perms])];
    db.prepare('UPDATE roles SET permissions=? WHERE name=?').run(JSON.stringify(merged), name);
  }
})();

function audit(userCtx, action, module, recordRef, details) {
  db.prepare('INSERT INTO audit_logs (user_id, username, action, module, record_ref, details) VALUES (?,?,?,?,?,?)')
    .run(userCtx ? userCtx.id : null, userCtx ? userCtx.username : 'system', action, module, recordRef || null,
      details ? JSON.stringify(details) : null);
}

function getSetting(key, fallback) {
  const row = db.prepare('SELECT value FROM app_settings WHERE key = ?').get(key);
  return row ? row.value : fallback;
}
function setSetting(key, value) {
  db.prepare('INSERT INTO app_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').run(key, String(value));
}
function getAllSettings() {
  const rows = db.prepare('SELECT key, value FROM app_settings').all();
  return Object.fromEntries(rows.map(r => [r.key, r.value]));
}

module.exports = { db, nextNumber, audit, getSetting, setSetting, getAllSettings };
