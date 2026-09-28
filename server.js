// server.js - Mini LIMS core API + static file server (pure Node.js, no external deps)
'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');
const { URL } = require('url');
const { db, nextNumber, audit, getSetting, setSetting, getAllSettings } = require('./db');
const { hashPassword, verifyPassword, signToken, verifyToken } = require('./auth');

const PORT = Number(process.env.LIMS_PORT || process.env.PORT || 5150);
const HOST = process.env.LIMS_HOST || process.env.HOST || '0.0.0.0';
const PUBLIC_DIR = path.join(__dirname, 'public');

// ---------- helpers ----------
function sendJSON(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(body) });
  res.end(body);
}
function sendHTML(res, status, html) {
  res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(html);
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', chunk => { data += chunk; if (data.length > 5e6) req.destroy(); });
    req.on('end', () => {
      if (!data) return resolve({});
      try { resolve(JSON.parse(data)); } catch (e) { resolve({}); }
    });
    req.on('error', reject);
  });
}
function getUser(req) {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  const payload = verifyToken(token);
  if (!payload || !payload.id) return null;
  // Always reload the user/role from SQLite. This makes role changes and
  // disabling a user effective immediately on every workstation, even when
  // the user still has an older token in the browser.
  const row = db.prepare(`SELECT u.id,u.username,u.full_name,u.email,u.status,u.role_id,
    r.name AS role_name,r.permissions FROM users u JOIN roles r ON r.id=u.role_id WHERE u.id=?`).get(payload.id);
  if (!row || row.status !== 'active') return null;
  let permissions = [];
  try { permissions = JSON.parse(row.permissions || '[]'); } catch (_) { permissions = []; }
  return { id: row.id, username: row.username, full_name: row.full_name, email: row.email,
    role_id: row.role_id, role: row.role_name, permissions };
}
function requireAuth(req, res) {
  const user = getUser(req);
  if (!user) { sendJSON(res, 401, { error: 'Not authenticated' }); return null; }
  return user;
}
function hasPerm(user, perm) {
  if (!user) return false;
  if (user.permissions.includes('*')) return true;
  return user.permissions.includes(perm);
}
function requirePerm(req, res, perm) {
  const user = requireAuth(req, res);
  if (!user) return null;
  if (!hasPerm(user, perm)) { sendJSON(res, 403, { error: `Missing permission: ${perm}` }); return null; }
  return user;
}
function calcAge(dob) {
  if (!dob) return null;
  const d = new Date(dob);
  if (isNaN(d)) return null;
  const diff = Date.now() - d.getTime();
  return Math.floor(diff / (365.25 * 24 * 3600 * 1000));
}
function flagResult(value, refLow, refHigh, critLow, critHigh) {
  const raw = value == null ? '' : String(value).trim();
  if (!raw || /^undefined|null$/i.test(raw)) return '';
  const v = Number(raw.replace(/,/g,''));
  if (!Number.isFinite(v)) return 'Normal';
  // Critical limits take priority over ordinary reference limits.
  if (critHigh != null && Number.isFinite(Number(critHigh)) && v >= Number(critHigh)) return 'Critical-High';
  if (critLow != null && Number.isFinite(Number(critLow)) && v <= Number(critLow)) return 'Critical-Low';
  if (refHigh != null && Number.isFinite(Number(refHigh)) && v > Number(refHigh)) return 'High';
  if (refLow != null && Number.isFinite(Number(refLow)) && v < Number(refLow)) return 'Low';
  return 'Normal';
}
function esc(s) { return (s === null || s === undefined) ? '' : String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c])); }

// ---------- static file serving ----------
const MIME = { '.html': 'text/html', '.js': 'application/javascript', '.css': 'text/css', '.json': 'application/json', '.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.webp': 'image/webp' };
function serveStatic(req, res, pathname) {
  let filePath = path.join(PUBLIC_DIR, pathname === '/' ? 'index.html' : pathname);
  if (!filePath.startsWith(PUBLIC_DIR)) { res.writeHead(403); return res.end('Forbidden'); }
  fs.readFile(filePath, (err, data) => {
    if (err) {
      // SPA fallback
      fs.readFile(path.join(PUBLIC_DIR, 'index.html'), (err2, data2) => {
        if (err2) { res.writeHead(404); return res.end('Not found'); }
        sendHTML(res, 200, data2.toString());
      });
      return;
    }
    const ext = path.extname(filePath);
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
    res.end(data);
  });
}

// ---------- route table ----------
const routes = []; // {method, regex, keys, handler}
function route(method, pattern, handler) {
  const keys = [];
  const regex = new RegExp('^' + pattern.replace(/:[^/]+/g, (m) => { keys.push(m.slice(1)); return '([^/]+)'; }) + '$');
  routes.push({ method, regex, keys, handler });
}

// ===================== AUTH =====================
route('POST', '/api/auth/login', async (req, res, params, body) => {
  const { username, password } = body;
  const user = db.prepare('SELECT u.*, r.name as role_name, r.permissions FROM users u JOIN roles r ON r.id = u.role_id WHERE u.username = ?').get(username);
  if (!user || user.status !== 'active' || !verifyPassword(password || '', user.password_hash)) {
    audit(null, 'login_failed', 'auth', username, {});
    return sendJSON(res, 401, { error: 'Invalid username or password' });
  }
  db.prepare('UPDATE users SET last_login = datetime(\'now\') WHERE id = ?').run(user.id);
  const permissions = JSON.parse(user.permissions);
  const token = signToken({ id: user.id, username: user.username, role: user.role_name, permissions });
  audit(user, 'login', 'auth', user.username, {});
  sendJSON(res, 200, { token, user: { id: user.id, username: user.username, full_name: user.full_name, role: user.role_name, permissions } });
});

route('GET', '/api/auth/me', async (req, res) => {
  const user = requireAuth(req, res); if (!user) return;
  sendJSON(res, 200, { user });
});

// ===================== HR / EMPLOYEES =====================
function hrAllowed(user){ return hasPerm(user,'*') || hasPerm(user,'hr.manage'); }
route('GET','/api/hr/employees',async(req,res)=>{
  const user=requireAuth(req,res); if(!user)return;
  if(!hrAllowed(user)) return sendJSON(res,403,{error:'HR access denied'});
  const u=new URL(req.url,'http://x');
  const q=String(u.searchParams.get('q')||'').trim();
  const type=String(u.searchParams.get('type')||'').trim();
  const status=String(u.searchParams.get('status')||'').trim();
  let sql=`SELECT e.*, d.name AS department_name FROM employees e LEFT JOIN departments d ON d.id=e.department_id WHERE 1=1`;
  const args=[];
  if(q){sql+=` AND (e.employee_code LIKE ? OR e.full_name LIKE ? OR COALESCE(e.designation,'') LIKE ? OR COALESCE(e.mobile,'') LIKE ? OR COALESCE(e.email,'') LIKE ?)`;const l='%'+q+'%';args.push(l,l,l,l,l);}
  if(type && ['Employee','Consultant','Technologist','Pathologist','Phlebotomist','Receptionist','Cashier','Other'].includes(type)){sql+=' AND e.employee_type=?';args.push(type);}
  if(status && ['active','inactive','on_leave'].includes(status)){sql+=' AND e.status=?';args.push(status);}
  sql+=' ORDER BY CASE e.status WHEN \'active\' THEN 0 WHEN \'on_leave\' THEN 1 ELSE 2 END,e.full_name COLLATE NOCASE';
  sendJSON(res,200,db.prepare(sql).all(...args));
});
route('POST','/api/hr/employees',async(req,res,params,body)=>{
  const user=requireAuth(req,res); if(!user)return;
  if(!hrAllowed(user)) return sendJSON(res,403,{error:'HR access denied'});
  const fullName=String(body.full_name||'').trim();
  const type=String(body.employee_type||'Employee').trim();
  const designation=String(body.designation||'').trim();
  const departmentId=body.department_id?Number(body.department_id):null;
  const allowed=['Employee','Consultant','Technologist','Pathologist','Phlebotomist','Receptionist','Cashier','Other'];
  if(!fullName) return sendJSON(res,400,{error:'Employee name is required'});
  if(!allowed.includes(type)) return sendJSON(res,400,{error:'Invalid employee type'});
  if(departmentId && !db.prepare('SELECT id FROM departments WHERE id=?').get(departmentId)) return sendJSON(res,400,{error:'Department not found'});
  const code=String(body.employee_code||'').trim() || nextNumber('EMPLOYEE','EMP');
  try{
    const info=db.prepare(`INSERT INTO employees(employee_code,full_name,employee_type,designation,department_id,qualification,cnic,mobile,email,joining_date,status,notes)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`).run(code,fullName,type,designation||null,departmentId,body.qualification||null,body.cnic||null,body.mobile||null,body.email||null,body.joining_date||null,body.status||'active',body.notes||null);
    const employeeId=Number(info.lastInsertRowid);
    if(['Consultant','Pathologist'].includes(type)){
      const specialty=designation||type;
      db.prepare('INSERT INTO doctors (code,name,specialty,mobile,email,hospital_clinic) VALUES (?,?,?,?,?,?)').run('EMP-'+code,fullName,specialty,body.mobile||null,body.email||null,'IQRA GROUP OF LABORATORY');
    }
    audit(user,'create','hr_employees',code,{full_name:fullName,employee_type:type,designation});
    sendJSON(res,201,{id:employeeId,employee_code:code});
  }catch(e){sendJSON(res,400,{error:'Employee code already exists or invalid data'});}
});
route('PATCH','/api/hr/employees/:id',async(req,res,params,body)=>{
  const user=requireAuth(req,res); if(!user)return;
  if(!hrAllowed(user)) return sendJSON(res,403,{error:'HR access denied'});
  const e=db.prepare('SELECT * FROM employees WHERE id=?').get(params.id); if(!e)return sendJSON(res,404,{error:'Employee not found'});
  const fullName=String(body.full_name==null?e.full_name:body.full_name).trim();
  const type=String(body.employee_type==null?e.employee_type:body.employee_type);
  const designation=String(body.designation==null?e.designation||'':body.designation).trim();
  const departmentId=body.department_id==null?e.department_id:(body.department_id?Number(body.department_id):null);
  const status=String(body.status==null?e.status:body.status);
  const allowed=['Employee','Consultant','Technologist','Pathologist','Phlebotomist','Receptionist','Cashier','Other'];
  if(!fullName||!allowed.includes(type)||!['active','inactive','on_leave'].includes(status))return sendJSON(res,400,{error:'Invalid employee data'});
  if(departmentId && !db.prepare('SELECT id FROM departments WHERE id=?').get(departmentId))return sendJSON(res,400,{error:'Department not found'});
  db.prepare(`UPDATE employees SET full_name=?,employee_type=?,designation=?,department_id=?,qualification=?,cnic=?,mobile=?,email=?,joining_date=?,status=?,notes=?,updated_at=datetime('now') WHERE id=?`)
    .run(fullName,type,designation||null,departmentId,body.qualification==null?e.qualification:body.qualification,body.cnic==null?e.cnic:body.cnic,body.mobile==null?e.mobile:body.mobile,body.email==null?e.email:body.email,body.joining_date==null?e.joining_date:body.joining_date,status,body.notes==null?e.notes:body.notes,params.id);
  audit(user,'update','hr_employees',e.employee_code,{full_name:fullName,employee_type:type,designation,status});
  sendJSON(res,200,{ok:true});
});

// ===================== USERS & ROLES =====================
route('GET', '/api/roles', async (req, res) => {
  const user = requireAuth(req, res); if (!user) return;
  const rows = db.prepare('SELECT id, name, permissions FROM roles').all().map(r => ({ ...r, permissions: JSON.parse(r.permissions) }));
  sendJSON(res, 200, rows);
});

route('GET', '/api/admin/permission-catalog', async (req, res) => {
  const user = requireAuth(req, res); if (!user) return;
  if (!hasPerm(user, '*')) return sendJSON(res, 403, { error: 'Admin only' });
  sendJSON(res, 200, [
    ['patient.create','Patients','Create patient registrations'],['patient.view','Patients','View patient records'],
    ['order.create','Orders','Create laboratory orders'],['sample.collect','Samples','Collect specimens'],['sample.receive','Samples','Receive specimens'],
    ['result.enter','Results','Enter and correct results'],['result.view','Results','View laboratory results'],['result.verify','Results','Verify results'],['result.authorize','Results','Authorize results'],
    ['report.view','Reports','View reports'],['report.print','Reports','Print / reprint reports'],['report.release','Reports','Release reports'],
    ['invoice.create','Billing','Create invoices'],['invoice.view','Billing','View invoices'],['payment.create','Billing','Receive payments'],['payment.view','Billing','View payments'],
    ['critical.manage','Clinical Safety','Manage critical results'],['inventory.view','Inventory','View inventory'],['inventory.transaction','Inventory','Receive / issue / adjust stock'],
    ['doctor.manage','Doctors','Manage referring doctors'],['hr.manage','Human Resources','Manage laboratory employees and consultants'],['accounts.view','Accounts','View accounts dashboard, income and expenses'],['accounts.manage','Accounts','Add, edit and remove expenses'],['admin.audit','Administration','View audit trail']
  ].map(x=>({key:x[0],group:x[1],label:x[2]})));
});

route('GET', '/api/admin/roles-summary', async (req, res) => {
  const user = requireAuth(req, res); if (!user) return;
  if (!hasPerm(user, '*')) return sendJSON(res, 403, { error: 'Admin only' });
  const rows=db.prepare(`SELECT r.id,r.name,r.permissions,COUNT(u.id) AS user_count
    FROM roles r LEFT JOIN users u ON u.role_id=r.id GROUP BY r.id ORDER BY CASE WHEN r.name='Administrator' THEN 0 ELSE 1 END,r.name COLLATE NOCASE`).all();
  sendJSON(res,200,rows.map(r=>({...r,permissions:JSON.parse(r.permissions||'[]')})));
});

route('GET', '/api/admin/user-activity/:id', async (req, res, params) => {
  const user = requireAuth(req, res); if (!user) return;
  if (!hasPerm(user, '*')) return sendJSON(res, 403, { error: 'Admin only' });
  const target=db.prepare('SELECT id,username,full_name FROM users WHERE id=?').get(params.id);
  if(!target) return sendJSON(res,404,{error:'User not found'});
  sendJSON(res,200,{user:target,activity:db.prepare('SELECT * FROM audit_logs WHERE user_id=? ORDER BY id DESC LIMIT 100').all(params.id)});
});

route('GET', '/api/users', async (req, res) => {
  const user = requireAuth(req, res); if (!user) return;
  if (!hasPerm(user, '*')) return sendJSON(res, 403, { error: 'Admin only' });
  const rows = db.prepare(`SELECT u.id, u.username, u.full_name, u.email, u.status, u.created_at, u.last_login,
    u.role_id, r.name as role FROM users u JOIN roles r ON r.id=u.role_id ORDER BY u.id`).all();
  sendJSON(res, 200, rows);
});

// Admin UI compatibility alias
route('GET', '/api/admin/users', async (req, res) => {
  const user = requireAuth(req, res); if (!user) return;
  if (!hasPerm(user, '*')) return sendJSON(res, 403, { error: 'Admin only' });
  const u = new URL(req.url, 'http://x');
  const q = String(u.searchParams.get('q') || '').trim();
  const status = String(u.searchParams.get('status') || '').trim();
  const roleId = Number(u.searchParams.get('role_id') || 0);
  let sql = `SELECT u.id,u.username,u.full_name,u.email,u.status,u.created_at,u.last_login,u.role_id,
    r.name AS role, (SELECT COUNT(*) FROM audit_logs a WHERE a.user_id=u.id) AS activity_count
    FROM users u JOIN roles r ON r.id=u.role_id WHERE 1=1`;
  const args=[];
  if(q){sql += ` AND (u.username LIKE ? OR u.full_name LIKE ? OR COALESCE(u.email,'') LIKE ?)`; const like='%'+q+'%'; args.push(like,like,like);}
  if(status && ['active','disabled','locked'].includes(status)){sql += ` AND u.status=?`; args.push(status);}
  if(Number.isInteger(roleId) && roleId>0){sql += ` AND u.role_id=?`; args.push(roleId);}
  sql += ` ORDER BY CASE u.status WHEN 'active' THEN 0 WHEN 'locked' THEN 1 ELSE 2 END, u.full_name COLLATE NOCASE`;
  sendJSON(res, 200, db.prepare(sql).all(...args));
});

route('POST', '/api/users', async (req, res, params, body) => {
  const user = requireAuth(req, res); if (!user) return;
  if (!hasPerm(user, '*')) return sendJSON(res, 403, { error: 'Admin only' });
  const { username, full_name, email, role_id, password } = body;
  if (!username || !full_name || !role_id || !password) return sendJSON(res, 400, { error: 'Missing fields' });
  if (String(password).length < 8) return sendJSON(res,400,{error:'Password must be at least 8 characters'});
  if (!db.prepare('SELECT id FROM roles WHERE id=?').get(Number(role_id))) return sendJSON(res,400,{error:'Role not found'});
  try {
    const info = db.prepare('INSERT INTO users (username, full_name, email, role_id, password_hash) VALUES (?,?,?,?,?)')
      .run(username, full_name, email || null, role_id, hashPassword(password));
    audit(user, 'create', 'users', username, {});
    sendJSON(res, 201, { id: Number(info.lastInsertRowid) });
  } catch (e) { sendJSON(res, 400, { error: 'Username already exists' }); }
});

route('PATCH', '/api/users/:id/status', async (req, res, params, body) => {
  const user = requireAuth(req, res); if (!user) return;
  if (!hasPerm(user, '*')) return sendJSON(res, 403, { error: 'Admin only' });
  const status = String(body.status || '');
  if (!['active','disabled','locked'].includes(status)) return sendJSON(res, 400, { error: 'Invalid status' });
  if (Number(params.id) === Number(user.id) && status !== 'active') return sendJSON(res, 400, { error: 'You cannot disable or lock your own administrator session.' });
  const target = db.prepare('SELECT id,username FROM users WHERE id=?').get(params.id);
  if (!target) return sendJSON(res, 404, { error: 'User not found' });
  db.prepare('UPDATE users SET status = ? WHERE id = ?').run(status, params.id);
  audit(user, 'status_change', 'users', target.username, {status});
  sendJSON(res, 200, { ok: true });
});


// ===================== ADMIN CONTROL CENTER =====================
route('GET', '/api/admin/overview', async (req, res) => {
  const user = requireAuth(req, res); if (!user) return;
  if (!hasPerm(user, '*')) return sendJSON(res, 403, { error: 'Admin only' });
  const count = (table) => db.prepare(`SELECT COUNT(*) c FROM ${table}`).get().c;
  const activeUsers = db.prepare("SELECT COUNT(*) c FROM users WHERE status='active'").get().c;
  const criticalOpen = db.prepare("SELECT COUNT(*) c FROM critical_results WHERE status NOT IN ('Closed')").get().c;
  const lowStock = db.prepare('SELECT COUNT(*) c FROM inventory_items WHERE active=1 AND stock_qty <= reorder_level').get().c;
  sendJSON(res, 200, {
    users: count('users'), active_users: activeUsers, roles: count('roles'),
    patients: count('patients'), orders: count('orders'), tests: count('tests'),
    departments: count('departments'), inventory_items: count('inventory_items'),
    critical_open: criticalOpen, low_stock: lowStock, audit_entries: count('audit_logs'),
    mode: getSetting('mode') || 'demo'
  });
});

route('POST', '/api/admin/users/:id/reset-password', async (req, res, params, body) => {
  const user = requireAuth(req, res); if (!user) return;
  if (!hasPerm(user, '*')) return sendJSON(res, 403, { error: 'Admin only' });
  const password = String(body.password || '');
  if (password.length < 8) return sendJSON(res, 400, { error: 'Password must be at least 8 characters' });
  const target = db.prepare('SELECT id, username FROM users WHERE id=?').get(params.id);
  if (!target) return sendJSON(res, 404, { error: 'User not found' });
  db.prepare('UPDATE users SET password_hash=?, status=? WHERE id=?').run(hashPassword(password), 'active', params.id);
  audit(user, 'password_reset', 'users', target.username, {});
  sendJSON(res, 200, { ok: true });
});

route('PATCH', '/api/admin/users/:id', async (req, res, params, body) => {
  const user = requireAuth(req, res); if (!user) return;
  if (!hasPerm(user, '*')) return sendJSON(res, 403, { error: 'Admin only' });
  const target = db.prepare('SELECT * FROM users WHERE id=?').get(params.id);
  if (!target) return sendJSON(res, 404, { error: 'User not found' });
  const allowedStatus = ['active','disabled','locked'];
  const status = body.status == null ? target.status : String(body.status);
  if (!allowedStatus.includes(status)) return sendJSON(res, 400, { error: 'Invalid status' });
  const fullName = body.full_name == null ? target.full_name : String(body.full_name).trim();
  const email = body.email == null ? target.email : String(body.email).trim();
  const roleId = body.role_id == null ? target.role_id : Number(body.role_id);
  if (!fullName || !Number.isInteger(roleId)) return sendJSON(res, 400, { error: 'Invalid user data' });
  if (!db.prepare('SELECT id FROM roles WHERE id=?').get(roleId)) return sendJSON(res, 400, { error: 'Role not found' });
  if (Number(params.id) === Number(user.id) && roleId !== Number(target.role_id)) {
    return sendJSON(res, 400, { error: "Change another user's role instead of changing your own administrator role." });
  }
  db.prepare('UPDATE users SET full_name=?, email=?, role_id=?, status=? WHERE id=?')
    .run(fullName, email || null, roleId, status, params.id);
  audit(user, 'update', 'users', target.username, { full_name: fullName, email, role_id: roleId, status });
  sendJSON(res, 200, { ok: true });
});

route('POST', '/api/admin/roles', async (req, res, params, body) => {
  const user = requireAuth(req, res); if (!user) return;
  if (!hasPerm(user, '*')) return sendJSON(res, 403, { error: 'Admin only' });
  const name = String(body.name || '').trim();
  const permissions = Array.isArray(body.permissions) ? body.permissions.map(String) : [];
  if (!name) return sendJSON(res, 400, { error: 'Role name is required' });
  try {
    const info = db.prepare('INSERT INTO roles (name, permissions) VALUES (?,?)').run(name, JSON.stringify(permissions));
    audit(user, 'create', 'roles', name, { permissions });
    sendJSON(res, 201, { id: Number(info.lastInsertRowid) });
  } catch (e) { sendJSON(res, 400, { error: 'Role name already exists' }); }
});

route('PATCH', '/api/admin/roles/:id', async (req, res, params, body) => {
  const user = requireAuth(req, res); if (!user) return;
  if (!hasPerm(user, '*')) return sendJSON(res, 403, { error: 'Admin only' });
  const role = db.prepare('SELECT * FROM roles WHERE id=?').get(params.id);
  if (!role) return sendJSON(res, 404, { error: 'Role not found' });
  const name = String(body.name == null ? role.name : body.name).trim();
  const permissions = Array.isArray(body.permissions) ? body.permissions.map(String) : JSON.parse(role.permissions);
  if (!name) return sendJSON(res, 400, { error: 'Role name is required' });
  try {
    db.prepare('UPDATE roles SET name=?, permissions=? WHERE id=?').run(name, JSON.stringify(permissions), params.id);
    audit(user, 'update', 'roles', role.name, { name, permissions });
    sendJSON(res, 200, { ok: true });
  } catch (e) { sendJSON(res, 400, { error: 'Role name already exists' }); }
});

route('DELETE', '/api/admin/roles/:id', async (req, res, params) => {
  const user = requireAuth(req, res); if (!user) return;
  if (!hasPerm(user, '*')) return sendJSON(res, 403, { error: 'Admin only' });
  const role = db.prepare('SELECT * FROM roles WHERE id=?').get(params.id);
  if (!role) return sendJSON(res, 404, { error: 'Role not found' });
  if (role.name === 'Administrator') return sendJSON(res, 400, { error: 'Administrator role cannot be deleted' });
  const used = db.prepare('SELECT COUNT(*) c FROM users WHERE role_id=?').get(params.id).c;
  if (used > 0) return sendJSON(res, 400, { error: 'Role is assigned to users; reassign them first' });
  db.prepare('DELETE FROM roles WHERE id=?').run(params.id);
  audit(user, 'delete', 'roles', role.name, {});
  sendJSON(res, 200, { ok: true });
});

route('POST', '/api/admin/departments', async (req, res, params, body) => {
  const user = requireAuth(req, res); if (!user) return;
  if (!hasPerm(user, '*')) return sendJSON(res, 403, { error: 'Admin only' });
  const name = String(body.name || '').trim();
  if (!name) return sendJSON(res, 400, { error: 'Department name is required' });
  try {
    const info = db.prepare('INSERT INTO departments (name,status) VALUES (?,?)').run(name, 'active');
    audit(user, 'create', 'departments', name, {});
    sendJSON(res, 201, { id: Number(info.lastInsertRowid) });
  } catch (e) { sendJSON(res, 400, { error: 'Department already exists' }); }
});

route('PATCH', '/api/admin/departments/:id', async (req, res, params, body) => {
  const user = requireAuth(req, res); if (!user) return;
  if (!hasPerm(user, '*')) return sendJSON(res, 403, { error: 'Admin only' });
  const name = String(body.name || '').trim();
  const status = String(body.status || 'active');
  if (!name || !['active','disabled'].includes(status)) return sendJSON(res, 400, { error: 'Invalid department data' });
  try {
    db.prepare('UPDATE departments SET name=?, status=? WHERE id=?').run(name, status, params.id);
    audit(user, 'update', 'departments', params.id, { name, status });
    sendJSON(res, 200, { ok: true });
  } catch (e) { sendJSON(res, 400, { error: 'Department name already exists' }); }
});

route('POST', '/api/admin/inventory-items', async (req, res, params, body) => {
  const user = requireAuth(req, res); if (!user) return;
  if (!hasPerm(user, '*')) return sendJSON(res, 403, { error: 'Admin only' });
  const code = String(body.code || '').trim() || nextNumber('INVENTORY', 'ITM');
  const name = String(body.name || '').trim();
  if (!name) return sendJSON(res, 400, { error: 'Item name is required' });
  try {
    const info = db.prepare(`INSERT INTO inventory_items (code,name,category,unit,reorder_level,stock_qty,active)
      VALUES (?,?,?,?,?,?,1)`).run(code,name,body.category||null,body.unit||null,Number(body.reorder_level||0),Number(body.stock_qty||0));
    audit(user, 'create', 'inventory_items', code, {});
    sendJSON(res, 201, { id: Number(info.lastInsertRowid) });
  } catch (e) { sendJSON(res, 400, { error: 'Inventory code already exists or invalid data' }); }
});

route('PATCH', '/api/admin/inventory-items/:id', async (req, res, params, body) => {
  const user = requireAuth(req, res); if (!user) return;
  if (!hasPerm(user, '*')) return sendJSON(res, 403, { error: 'Admin only' });
  const item = db.prepare('SELECT * FROM inventory_items WHERE id=?').get(params.id);
  if (!item) return sendJSON(res, 404, { error: 'Inventory item not found' });
  const name = String(body.name == null ? item.name : body.name).trim();
  const category = body.category == null ? item.category : body.category;
  const unit = body.unit == null ? item.unit : body.unit;
  const reorder = body.reorder_level == null ? item.reorder_level : Number(body.reorder_level);
  const active = body.active == null ? item.active : (body.active ? 1 : 0);
  if (!name || !Number.isFinite(reorder) || reorder < 0) return sendJSON(res, 400, { error: 'Invalid inventory data' });
  db.prepare('UPDATE inventory_items SET name=?, category=?, unit=?, reorder_level=?, active=? WHERE id=?')
    .run(name, category || null, unit || null, reorder, active, params.id);
  audit(user, 'update', 'inventory_items', item.code, { name, category, unit, reorder_level: reorder, active });
  sendJSON(res, 200, { ok: true });
});

route('GET', '/api/admin/audit-summary', async (req, res) => {
  const user = requireAuth(req, res); if (!user) return;
  if (!hasPerm(user, '*')) return sendJSON(res, 403, { error: 'Admin only' });
  const rows = db.prepare(`SELECT action, module, COUNT(*) count FROM audit_logs GROUP BY action,module ORDER BY count DESC LIMIT 30`).all();
  sendJSON(res, 200, rows);
});

// ===================== CONSULTANTS / AUTHORIZERS =====================
route('GET','/api/consultants',async(req,res)=>{
  if(!requireAuth(req,res))return;
  const employees=db.prepare(`SELECT id,employee_code,full_name,employee_type,designation,qualification,mobile,email FROM employees WHERE status='active' AND employee_type IN ('Consultant','Pathologist') ORDER BY full_name COLLATE NOCASE`).all();
  const outside=db.prepare(`SELECT id,code,name,specialty,mobile,email,hospital_clinic FROM doctors ORDER BY name COLLATE NOCASE`).all();
  sendJSON(res,200,{employees,outside});
});

// ===================== DOCTORS =====================
route('GET', '/api/doctors', async (req, res) => {
  if (!requireAuth(req, res)) return;
  sendJSON(res, 200, db.prepare('SELECT * FROM doctors ORDER BY name').all());
});
route('POST', '/api/doctors', async (req, res, params, body) => {
  const user = requireAuth(req, res); if (!user) return;
  const code = body.code || nextNumber('DOCTOR', 'DOC');
  const info = db.prepare('INSERT INTO doctors (code,name,specialty,mobile,email,hospital_clinic) VALUES (?,?,?,?,?,?)')
    .run(code, body.name, body.specialty || null, body.mobile || null, body.email || null, body.hospital_clinic || null);
  audit(user, 'create', 'doctors', code, body);
  sendJSON(res, 201, { id: Number(info.lastInsertRowid), code });
});

// ===================== DEPARTMENTS =====================
route('GET', '/api/departments', async (req, res) => {
  if (!requireAuth(req, res)) return;
  sendJSON(res, 200, db.prepare('SELECT * FROM departments ORDER BY name').all());
});

// ===================== TEST MASTER =====================
route('GET', '/api/tests', async (req, res) => {
  if (!requireAuth(req, res)) return;
  sendJSON(res, 200, db.prepare(`SELECT t.*, d.name as department_name FROM tests t LEFT JOIN departments d ON d.id=t.department_id WHERE t.active=1 ORDER BY d.name, t.name`).all());
});
route('POST', '/api/tests', async (req, res, params, body) => {
  const user = requireAuth(req, res); if (!user) return;
  if (!hasPerm(user, '*')) return sendJSON(res, 403, { error: 'Only Administrator can add or change tests.' });
  const code=String(body.code||'').trim(), name=String(body.name||'').trim();
  if(!code||!name) return sendJSON(res,400,{error:'Test code and test name are required'});
  try {
    const info=db.prepare(`INSERT INTO tests (code,name,department_id,sample_type,unit,method,ref_low,ref_high,ref_text,critical_low,critical_high,result_type,price,tat_hours)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(code,name,body.department_id||null,body.sample_type||null,body.unit||null,body.method||null,
      body.ref_low===''||body.ref_low==null?null:Number(body.ref_low), body.ref_high===''||body.ref_high==null?null:Number(body.ref_high), body.ref_text||null,
      body.critical_low===''||body.critical_low==null?null:Number(body.critical_low), body.critical_high===''||body.critical_high==null?null:Number(body.critical_high),
      body.result_type||'numeric', Number(body.price||0), Number(body.tat_hours||24));
    audit(user,'create','tests',code,body); sendJSON(res,201,{id:Number(info.lastInsertRowid)});
  } catch(e){ sendJSON(res,400,{error:'Test code already exists or data is invalid'}); }
});
route('PATCH', '/api/tests/:id', async (req,res,params,body)=>{
  const user=requireAuth(req,res); if(!user)return;
  if(!hasPerm(user,'*')) return sendJSON(res,403,{error:'Only Administrator can change test master or prices.'});
  const t=db.prepare('SELECT * FROM tests WHERE id=?').get(params.id); if(!t)return sendJSON(res,404,{error:'Test not found'});
  const v=(k, fallback)=> body[k]===undefined?fallback:body[k];
  const code=String(v('code',t.code)).trim(), name=String(v('name',t.name)).trim();
  if(!code||!name)return sendJSON(res,400,{error:'Test code and name are required'});
  try{
    db.prepare(`UPDATE tests SET code=?,name=?,department_id=?,sample_type=?,unit=?,method=?,ref_low=?,ref_high=?,ref_text=?,critical_low=?,critical_high=?,result_type=?,price=?,tat_hours=?,active=? WHERE id=?`)
      .run(code,name,v('department_id',t.department_id)||null,v('sample_type',t.sample_type)||null,v('unit',t.unit)||null,v('method',t.method)||null,
      v('ref_low',t.ref_low)===''?null:v('ref_low',t.ref_low),v('ref_high',t.ref_high)===''?null:v('ref_high',t.ref_high),v('ref_text',t.ref_text)||null,
      v('critical_low',t.critical_low)===''?null:v('critical_low',t.critical_low),v('critical_high',t.critical_high)===''?null:v('critical_high',t.critical_high),v('result_type',t.result_type)||'numeric',Number(v('price',t.price)||0),Number(v('tat_hours',t.tat_hours)||24),v('active',t.active)?1:0,params.id);
    audit(user,'update','tests',t.code,{code,name,price:Number(v('price',t.price)||0)}); sendJSON(res,200,{ok:true});
  }catch(e){sendJSON(res,400,{error:'Test code already exists or invalid data'});}
});
route('DELETE', '/api/tests/:id', async (req,res,params)=>{
  const user=requireAuth(req,res); if(!user)return;
  if(!hasPerm(user,'*')) return sendJSON(res,403,{error:'Only Administrator can disable tests.'});
  const t=db.prepare('SELECT * FROM tests WHERE id=?').get(params.id); if(!t)return sendJSON(res,404,{error:'Test not found'});
  db.prepare('UPDATE tests SET active=0 WHERE id=?').run(params.id); audit(user,'disable','tests',t.code,{}); sendJSON(res,200,{ok:true});
});

// ===================== PATIENTS =====================
route('GET', '/api/patients', async (req, res, params, body, query) => {
  if (!requireAuth(req, res)) return;
  const q = query.get('q');
  const name = query.get('name');
  const mr = query.get('mr');
  const mobile = query.get('mobile');
  const cnic = query.get('cnic');
  let rows;
  if (name || mr || mobile || cnic) {
    // Advanced search: each provided field is matched independently and combined with AND.
    const clauses = []; const vals = [];
    if (name) { clauses.push('name LIKE ?'); vals.push(`%${name}%`); }
    if (mr) { clauses.push('patient_code LIKE ?'); vals.push(`%${mr}%`); }
    if (mobile) { clauses.push('mobile LIKE ?'); vals.push(`%${mobile}%`); }
    if (cnic) { clauses.push('cnic LIKE ?'); vals.push(`%${cnic}%`); }
    rows = db.prepare(`SELECT * FROM patients WHERE ${clauses.join(' AND ')} ORDER BY id DESC LIMIT 100`).all(...vals);
  } else if (q) {
    const like = `%${q}%`;
    rows = db.prepare(`SELECT * FROM patients WHERE name LIKE ? OR patient_code LIKE ? OR mobile LIKE ? OR cnic LIKE ? ORDER BY id DESC LIMIT 100`).all(like, like, like, like);
  } else {
    rows = db.prepare('SELECT * FROM patients ORDER BY id DESC LIMIT 100').all();
  }
  sendJSON(res, 200, rows);
});

route('GET', '/api/patients/:id', async (req, res, params) => {
  if (!requireAuth(req, res)) return;
  const patient = db.prepare('SELECT * FROM patients WHERE id = ?').get(params.id);
  if (!patient) return sendJSON(res, 404, { error: 'Not found' });
  const orders = db.prepare(`SELECT o.*, doc.name as doctor_name FROM orders o LEFT JOIN doctors doc ON doc.id=o.doctor_id WHERE o.patient_id = ? ORDER BY o.id DESC`).all(params.id);
  const criticalHistory = db.prepare(`SELECT cr.*, t.name as test_name FROM critical_results cr JOIN tests t ON t.id=cr.test_id WHERE cr.patient_id = ? ORDER BY cr.id DESC`).all(params.id);
  sendJSON(res, 200, { patient, orders, criticalHistory });
});

route('PATCH', '/api/patients/:id', async (req, res, params, body) => {
  const user = requireAuth(req, res); if (!user) return;
  if (!hasPerm(user, 'patient.create')) return sendJSON(res, 403, { error: 'Patient editing is not permitted for this user.' });
  const existing = db.prepare('SELECT * FROM patients WHERE id=?').get(params.id);
  if (!existing) return sendJSON(res, 404, { error: 'Patient not found.' });
  if (!body.name || !String(body.name).trim()) return sendJSON(res, 400, { error: 'Patient name is required.' });
  if (!body.cnic || !String(body.cnic).trim()) return sendJSON(res, 400, { error: 'CNIC is required for patient registration.' });
  const duplicate = db.prepare('SELECT id, patient_code, name FROM patients WHERE cnic=? AND id<>? LIMIT 1').get(String(body.cnic).trim(), params.id);
  if (duplicate) return sendJSON(res, 409, { error: `CNIC already registered for MR #${duplicate.patient_code} (${duplicate.name}).` });
  const age = body.age_years || calcAge(body.dob);
  db.prepare(`UPDATE patients SET name=?,guardian_name=?,gender=?,dob=?,age_years=?,cnic=?,mobile=?,email=?,address=?,blood_group=?,category=?,notes=? WHERE id=?`)
    .run(String(body.name).trim(), body.guardian_name||null, body.gender||null, body.dob||null, age||null, String(body.cnic).trim(), body.mobile||null, body.email||null, body.address||null, body.blood_group||null, body.category||'General', body.notes||null, params.id);
  audit(user, 'update', 'patients', existing.patient_code, { changed_patient: true });
  sendJSON(res, 200, { ok:true, patient: db.prepare('SELECT * FROM patients WHERE id=?').get(params.id) });
});

route('POST', '/api/patients', async (req, res, params, body) => {
  const user = requireAuth(req, res); if (!user) return;
  if (!hasPerm(user, 'patient.create')) return sendJSON(res, 403, { error: 'Patient registration is not permitted for this user.' });
  if (!body.cnic || !String(body.cnic).trim()) return sendJSON(res, 400, { error: 'CNIC is required for patient registration.' });
  const existingCnic = db.prepare('SELECT id, patient_code, name FROM patients WHERE cnic = ? LIMIT 1').get(String(body.cnic).trim());
  if (existingCnic) return sendJSON(res, 409, { error: `CNIC already registered for MR #${existingCnic.patient_code} (${existingCnic.name}). Search the existing patient and create a new order.` });
  const code = nextNumber('PATIENT', 'LAB');
  const age = body.age_years || calcAge(body.dob);
  const info = db.prepare(`INSERT INTO patients (patient_code,name,guardian_name,gender,dob,age_years,cnic,mobile,email,address,blood_group,category,notes)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(
    code, body.name, body.guardian_name || null, body.gender || null, body.dob || null, age || null,
    body.cnic || null, body.mobile || null, body.email || null, body.address || null, body.blood_group || null,
    body.category || 'General', body.notes || null);
  audit(user, 'create', 'patients', code, { name: body.name });
  sendJSON(res, 201, { id: Number(info.lastInsertRowid), patient_code: code, patient: { id: Number(info.lastInsertRowid), patient_code: code, name: body.name } });
});

// ===================== ORDERS (+ invoice) =====================
// Shared by the API route and demo-data seeding so both paths behave identically.
function createOrderWithInvoice({ patient_id, doctor_id, patient_type, priority, test_ids, discount, userId }) {
  const order_code = nextNumber('ORDER', 'ORD');
  const orderInfo = db.prepare('INSERT INTO orders (order_code, patient_id, doctor_id, patient_type, priority, created_by) VALUES (?,?,?,?,?,?)')
    .run(order_code, patient_id, doctor_id || null, patient_type || 'OPD', priority || 'Routine', userId || null);
  const orderId = Number(orderInfo.lastInsertRowid);

  let subtotal = 0;
  const itemIds = [];
  for (const tid of test_ids) {
    const test = db.prepare('SELECT * FROM tests WHERE id = ?').get(tid);
    if (!test) continue;
    const info = db.prepare('INSERT INTO order_items (order_id, test_id, price) VALUES (?,?,?)').run(orderId, tid, test.price);
    itemIds.push(Number(info.lastInsertRowid));
    subtotal += test.price;
    // auto-create sample per order item
    const sampleCode = nextNumber('SAMPLE', 'SMP');
    db.prepare('INSERT INTO samples (sample_code, order_id, order_item_id, sample_type, status) VALUES (?,?,?,?,?)')
      .run(sampleCode, orderId, itemIds[itemIds.length - 1], test.sample_type || 'Blood', 'Pending Collection');
  }
  const disc = discount || 0;
  const net = Math.max(0, subtotal - disc);
  const invoice_code = nextNumber('INVOICE', 'INV');
  const invInfo = db.prepare('INSERT INTO invoices (invoice_code, order_id, patient_id, subtotal, discount, tax, net_amount, paid_amount, balance, created_by) VALUES (?,?,?,?,?,?,?,?,?,?)')
    .run(invoice_code, orderId, patient_id, subtotal, disc, 0, net, 0, net, userId || null);

  return { orderId, order_code, itemIds, invoiceId: Number(invInfo.lastInsertRowid), invoice_code, net_amount: net };
}

route('POST', '/api/orders', async (req, res, params, body) => {
  const user = requireAuth(req, res); if (!user) return;
  if (!hasPerm(user, 'order.create')) return sendJSON(res, 403, { error: 'Order creation is not permitted for this user.' });
  const { patient_id, doctor_id, patient_type, priority, test_ids, discount } = body;
  if (!patient_id || !Array.isArray(test_ids) || test_ids.length === 0) return sendJSON(res, 400, { error: 'patient_id and test_ids required' });

  const result = createOrderWithInvoice({ patient_id, doctor_id, patient_type, priority, test_ids, discount, userId: user.id });
  audit(user, 'create', 'orders', result.order_code, { patient_id, test_ids });
  sendJSON(res, 201, { order_id: result.orderId, order_code: result.order_code, invoice_id: result.invoiceId, invoice_code: result.invoice_code, net_amount: result.net_amount, order: { id: result.orderId, order_code: result.order_code } });
});

function orderControlState(orderId) {
  const received = db.prepare(`SELECT COUNT(*) c FROM samples WHERE order_id=? AND status IN ('Received','Rejected')`).get(orderId).c > 0;
  const results = db.prepare(`SELECT COUNT(*) c FROM results r JOIN order_items oi ON oi.id=r.order_item_id WHERE oi.order_id=?`).get(orderId).c > 0;
  const reported = db.prepare(`SELECT COUNT(*) c FROM reports WHERE order_id=?`).get(orderId).c > 0;
  return { received, results, reported, editable: !received && !results && !reported, cancellable: !results && !reported };
}

route('PATCH', '/api/orders/:id', async (req, res, params, body) => {
  const user = requireAuth(req, res); if (!user) return;
  if (!hasPerm(user, 'order.create')) return sendJSON(res, 403, { error: 'Order modification is not permitted for this user.' });
  const order = db.prepare('SELECT * FROM orders WHERE id=?').get(params.id);
  if (!order) return sendJSON(res, 404, { error: 'Order not found.' });
  const ctl = orderControlState(order.id);
  // Test add/remove remains allowed after sample reception, but becomes locked
  // as soon as any result has been entered or a report has been processed.
  if (ctl.results || ctl.reported) return sendJSON(res, 409, { error: 'This order cannot be modified after result entry/report processing.' });
  if (order.status === 'Cancelled') return sendJSON(res, 409, { error: 'Cancelled orders cannot be modified.' });
  const testIds = Array.isArray(body.test_ids) ? [...new Set(body.test_ids.map(Number).filter(Boolean))] : [];
  if (!testIds.length) return sendJSON(res, 400, { error: 'Select at least one test.' });
  const tests = testIds.map(id => db.prepare('SELECT * FROM tests WHERE id=? AND active=1').get(id)).filter(Boolean);
  if (tests.length !== testIds.length) return sendJSON(res, 400, { error: 'One or more selected tests are unavailable.' });
  const invoice = db.prepare('SELECT * FROM invoices WHERE order_id=?').get(order.id);
  if (invoice && Number(invoice.paid_amount||0) > 0) return sendJSON(res, 409, { error: 'Paid invoices cannot be modified. Cancel/refund the payment first.' });
  try {
    db.exec('BEGIN');
    const existing = db.prepare(`SELECT oi.id as order_item_id, oi.test_id, oi.price, s.id as sample_id, s.status as sample_status
      FROM order_items oi LEFT JOIN samples s ON s.order_item_id=oi.id WHERE oi.order_id=?`).all(order.id);
    const selected = new Set(testIds);
    // Remove only tests that were deselected. No result exists here because the
    // endpoint is locked once result entry starts. Existing sample records for
    // retained tests are preserved, including Received/Collected status.
    for (const row of existing) {
      if (!selected.has(Number(row.test_id))) {
        db.prepare('DELETE FROM samples WHERE order_item_id=?').run(row.order_item_id);
        db.prepare('DELETE FROM order_items WHERE id=?').run(row.order_item_id);
      }
    }
    const existingTestIds = new Set(existing.filter(r => selected.has(Number(r.test_id))).map(r => Number(r.test_id)));
    let subtotal=0;
    for (const t of tests) {
      if (existingTestIds.has(Number(t.id))) {
        subtotal += Number(t.price||0);
        continue;
      }
      const oi=db.prepare('INSERT INTO order_items (order_id,test_id,price) VALUES (?,?,?)').run(order.id,t.id,t.price);
      const oiId=Number(oi.lastInsertRowid);
      const sampleCode=nextNumber('SAMPLE','SMP');
      db.prepare('INSERT INTO samples (sample_code,order_id,order_item_id,sample_type,status) VALUES (?,?,?,?,?)').run(sampleCode,order.id,oiId,t.sample_type||'Blood','Pending Collection');
      subtotal += Number(t.price||0);
    }
    const discount=Math.max(0,Number(body.discount||0));
    if (discount > subtotal) throw new Error('Discount cannot exceed subtotal.');
    const net=Math.max(0,subtotal-discount);
    if (invoice) db.prepare('UPDATE invoices SET subtotal=?,discount=?,net_amount=?,balance=?,status=? WHERE id=?').run(subtotal,discount,net,net,'Unpaid',invoice.id);
    const newStatus = ctl.received ? 'Sample Received' : 'Ordered';
    db.prepare('UPDATE orders SET doctor_id=?,patient_type=?,priority=?,status=? WHERE id=?').run(body.doctor_id||null,body.patient_type||order.patient_type,body.priority||order.priority,newStatus,order.id);
    db.exec('COMMIT');
  } catch(e) { try{db.exec('ROLLBACK')}catch{}; return sendJSON(res,500,{error:'Order modification failed: '+e.message}); }
  audit(user,'modify','orders',order.order_code,{test_ids:testIds});
  sendJSON(res,200,{ok:true,order_id:order.id,message:'Order modified successfully.'});
});

route('POST', '/api/orders/:id/cancel', async (req, res, params) => {
  const user = requireAuth(req, res); if (!user) return;
  if (!hasPerm(user, 'order.create')) return sendJSON(res, 403, { error: 'Order cancellation is not permitted for this user.' });
  const order=db.prepare('SELECT * FROM orders WHERE id=?').get(params.id);
  if(!order) return sendJSON(res,404,{error:'Order not found.'});
  const ctl=orderControlState(order.id);
  if(!ctl.cancellable) return sendJSON(res,409,{error:'This order cannot be cancelled after result entry/report processing.'});
  const invoice=db.prepare('SELECT * FROM invoices WHERE order_id=?').get(order.id);
  try {
    db.exec('BEGIN');
    db.prepare("UPDATE orders SET status='Cancelled' WHERE id=?").run(order.id);
    db.prepare("UPDATE order_items SET status='Rejected' WHERE order_id=?").run(order.id);
    db.prepare("UPDATE samples SET status='Rejected', rejection_reason='Order cancelled' WHERE order_id=?").run(order.id);
    if(invoice) db.prepare("UPDATE invoices SET status='Cancelled', balance=0 WHERE id=?").run(invoice.id);
    db.exec('COMMIT');
  } catch(e){try{db.exec('ROLLBACK')}catch{};return sendJSON(res,500,{error:'Cancellation failed: '+e.message});}
  audit(user,'cancel','orders',order.order_code,{invoice_id:invoice?.id||null,received:ctl.received});
  sendJSON(res,200,{ok:true,message:'Order and invoice cancelled.'});
});

route('GET', '/api/orders', async (req, res, params, body, query) => {
  if (!requireAuth(req, res)) return;
  const status = query.get('status');
  let rows;
  if (status) {
    rows = db.prepare(`SELECT o.*, p.name as patient_name, p.patient_code,
      (SELECT COUNT(*) FROM samples s WHERE s.order_id=o.id AND s.status IN ('Received','Rejected')) as sample_received,
      (SELECT COUNT(*) FROM results r JOIN order_items oi2 ON oi2.id=r.order_item_id WHERE oi2.order_id=o.id) as result_count,
      (SELECT COUNT(*) FROM reports r2 WHERE r2.order_id=o.id) as report_count,
      i.invoice_code, i.status as invoice_status, i.paid_amount, i.balance
      FROM orders o JOIN patients p ON p.id=o.patient_id LEFT JOIN invoices i ON i.order_id=o.id WHERE o.status = ? ORDER BY o.id DESC LIMIT 200`).all(status);
  } else {
    rows = db.prepare(`SELECT o.*, p.name as patient_name, p.patient_code,
      (SELECT COUNT(*) FROM samples s WHERE s.order_id=o.id AND s.status IN ('Received','Rejected')) as sample_received,
      (SELECT COUNT(*) FROM results r JOIN order_items oi2 ON oi2.id=r.order_item_id WHERE oi2.order_id=o.id) as result_count,
      (SELECT COUNT(*) FROM reports r2 WHERE r2.order_id=o.id) as report_count,
      i.invoice_code, i.status as invoice_status, i.paid_amount, i.balance
      FROM orders o JOIN patients p ON p.id=o.patient_id LEFT JOIN invoices i ON i.order_id=o.id ORDER BY o.id DESC LIMIT 200`).all();
  }
  sendJSON(res, 200, rows);
});

route('GET', '/api/orders/:id', async (req, res, params) => {
  if (!requireAuth(req, res)) return;
  const order = db.prepare(`SELECT o.*, p.name as patient_name, p.patient_code, p.gender, p.age_years, doc.name as doctor_name
    FROM orders o JOIN patients p ON p.id=o.patient_id LEFT JOIN doctors doc ON doc.id=o.doctor_id WHERE o.id=?`).get(params.id);
  if (!order) return sendJSON(res, 404, { error: 'Not found' });
  const items = db.prepare(`SELECT oi.*, t.name as test_name, t.unit, t.ref_low, t.ref_high, t.critical_low, t.critical_high, t.result_type
    FROM order_items oi JOIN tests t ON t.id=oi.test_id WHERE oi.order_id=?`).all(params.id);
  const samples = db.prepare('SELECT * FROM samples WHERE order_id=?').all(params.id);
  const invoice = db.prepare('SELECT * FROM invoices WHERE order_id=?').get(params.id);
  const results = db.prepare(`SELECT r.* FROM results r JOIN order_items oi ON oi.id=r.order_item_id WHERE oi.order_id=?`).all(params.id);
  sendJSON(res, 200, { order, items, samples, invoice, results });
});

// ===================== INVOICES / PAYMENTS =====================
route('GET', '/api/invoices', async (req, res) => {
  if (!requireAuth(req, res)) return;
  sendJSON(res, 200, db.prepare(`SELECT i.*, p.name as patient_name, p.patient_code, o.order_code FROM invoices i JOIN patients p ON p.id=i.patient_id JOIN orders o ON o.id=i.order_id ORDER BY i.id DESC LIMIT 200`).all());
});
route('POST', '/api/invoices/:id/pay', async (req, res, params, body) => {
  const user = requireAuth(req, res); if (!user) return;
  if (!hasPerm(user, 'payment.create')) return sendJSON(res, 403, { error: 'Payment collection is not permitted for this user.' });
  const invoice = db.prepare('SELECT * FROM invoices WHERE id=?').get(params.id);
  if (!invoice) return sendJSON(res, 404, { error: 'Not found' });

  // Discount is applied at payment/collection time. It is stored on the invoice
  // and therefore also appears on every subsequent print/reprint.
  const discountProvided = body.discount !== undefined && body.discount !== null && String(body.discount).trim() !== '';
  const requestedDiscount = discountProvided ? Number(body.discount) : Number(invoice.discount || 0);
  if (!Number.isFinite(requestedDiscount) || requestedDiscount < 0) return sendJSON(res, 400, { error: 'Invalid discount amount.' });
  if (requestedDiscount > Number(invoice.subtotal) + 0.0001) return sendJSON(res, 400, { error: 'Discount cannot exceed subtotal.' });

  const newNet = Math.max(0, Number(invoice.subtotal) - requestedDiscount + Number(invoice.tax || 0));
  if (newNet + 0.0001 < Number(invoice.paid_amount)) return sendJSON(res, 400, { error: 'Discount would make the invoice total lower than the amount already paid.' });

  if (requestedDiscount !== Number(invoice.discount || 0) || newNet !== Number(invoice.net_amount)) {
    const newBalance = Math.max(0, newNet - Number(invoice.paid_amount));
    const newStatus = newBalance <= 0 ? 'Paid' : (invoice.paid_amount > 0 ? 'Partial' : 'Unpaid');
    db.prepare('UPDATE invoices SET discount=?, net_amount=?, balance=?, status=? WHERE id=?')
      .run(requestedDiscount, newNet, newBalance, newStatus, invoice.id);
    invoice.discount = requestedDiscount; invoice.net_amount = newNet; invoice.balance = newBalance; invoice.status = newStatus;
  }

  const amount = parseFloat(body.amount);
  if (!Number.isFinite(amount) || amount < 0) return sendJSON(res, 400, { error: 'Invalid amount' });
  const currentBalance = Math.max(0, Number(invoice.net_amount) - Number(invoice.paid_amount));
  if (amount > currentBalance + 0.0001) return sendJSON(res, 400, { error: `Payment cannot exceed outstanding balance Rs ${currentBalance.toFixed(2)}.` });

  if (amount > 0) db.prepare('INSERT INTO payments (invoice_id, amount, method, received_by) VALUES (?,?,?,?)').run(invoice.id, amount, body.method || 'Cash', user.id);
  const paid = Number(invoice.paid_amount) + amount;
  const balance = Math.max(0, Number(invoice.net_amount) - paid);
  const status = balance <= 0 ? 'Paid' : (paid > 0 ? 'Partial' : 'Unpaid');
  db.prepare('UPDATE invoices SET paid_amount=?, balance=?, status=? WHERE id=?').run(paid, balance, status, invoice.id);
  audit(user, 'payment', 'invoices', invoice.invoice_code, { amount, discount: requestedDiscount });
  sendJSON(res, 200, { invoice_id: invoice.id, invoice_code: invoice.invoice_code, order_id: invoice.order_id, paid_amount: paid, balance, status, discount: requestedDiscount, net_amount: invoice.net_amount });
});

// ===================== INVOICE / PATIENT SLIP PRINT =====================
function addHours(dateStr, hours) {
  // dateStr comes from SQLite datetime('now') => 'YYYY-MM-DD HH:MM:SS' (UTC)
  const d = new Date(dateStr.replace(' ', 'T') + 'Z');
  d.setTime(d.getTime() + hours * 3600 * 1000);
  return d;
}
function fmtDateTime(d) {
  return d.toLocaleString('en-GB', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' });
}

route('GET', '/api/invoices/:id/print', async (req, res, params) => {
  const url = new URL(req.url, 'http://x');
  const payloadUser = verifyToken(url.searchParams.get('token'));
  if (!payloadUser) return sendHTML(res, 401, '<h3>Not authorized</h3>');

  const invoice = db.prepare('SELECT * FROM invoices WHERE id=?').get(params.id);
  if (!invoice) return sendHTML(res, 404, '<h3>Invoice not found</h3>');
  const order = db.prepare(`SELECT o.*, p.name as patient_name, p.patient_code, p.gender, p.age_years, p.mobile, doc.name as doctor_name
    FROM orders o JOIN patients p ON p.id=o.patient_id LEFT JOIN doctors doc ON doc.id=o.doctor_id WHERE o.id=?`).get(invoice.order_id);
  const items = db.prepare(`SELECT oi.*, t.name as test_name, t.tat_hours, t.department_id FROM order_items oi JOIN tests t ON t.id=oi.test_id WHERE oi.order_id=?`).all(invoice.order_id);
  const samples = db.prepare('SELECT * FROM samples WHERE order_id=?').all(invoice.order_id);
  const payments = db.prepare('SELECT * FROM payments WHERE invoice_id=? ORDER BY id').all(invoice.id);
  const settings = getAllSettings();

  let maxDue = null;
  const rowsHtml = items.map(it => {
    const tat = it.tat_hours || 24;
    const due = addHours(order.created_at, tat);
    if (!maxDue || due > maxDue) maxDue = due;
    return `<tr>
      <td style="padding:6px;border-bottom:1px solid #ddd">${it.test_name}</td>
      <td style="padding:6px;border-bottom:1px solid #ddd;text-align:right">${it.price.toFixed(2)}</td>
      <td style="padding:6px;border-bottom:1px solid #ddd;text-align:center">${tat} hrs</td>
      <td style="padding:6px;border-bottom:1px solid #ddd">${fmtDateTime(due)}</td>
    </tr>`;
  }).join('');

  const sampleCodes = samples.map(s => s.sample_code).join(' &middot; ');
  const paymentsHtml = payments.map(p => `<tr><td style="padding:4px 6px">${p.created_at}</td><td style="padding:4px 6px">${p.method}</td><td style="padding:4px 6px;text-align:right">${p.amount.toFixed(2)}</td></tr>`).join('');

  const html = `<!doctype html><html><head><meta charset="utf-8"><title>Invoice ${invoice.invoice_code}</title>
  <style>body{font-family:Arial,sans-serif;padding:24px;color:#111;max-width:720px;margin:0 auto} h1{font-size:18px;margin:0} table{width:100%;border-collapse:collapse;margin-top:14px}
  th{text-align:left;padding:6px;border-bottom:2px solid #333;background:#f5f5f5;font-size:13px} td{font-size:13px}
  .meta{display:flex;justify-content:space-between;margin-top:12px;font-size:13px;gap:12px} .box{border:1px solid #ddd;padding:10px;border-radius:6px;flex:1}
  .totals{margin-top:14px;font-size:14px} .totals div{display:flex;justify-content:space-between;padding:3px 0}
  .badge{display:inline-block;padding:2px 10px;border-radius:20px;font-size:12px;font-weight:600}
  .paid{background:#dcfce7;color:#166534} .unpaid{background:#fee2e2;color:#991b1b} .partial{background:#fef9c3;color:#854d0e}
  @media print {.no-print{display:none}}</style></head>
  <body onload="setTimeout(function(){window.print()},300)">
    <button class="no-print" onclick="window.print()" style="float:right;padding:8px 14px;">Print / Save as PDF</button>
    <div style="display:flex;align-items:center;gap:14px;border-bottom:2px solid #b91c1c;padding-bottom:10px"><img src="/iqra-personal-logo.png" style="width:105px;height:90px;object-fit:contain"><div><h1 style="color:#991b1b;font-size:22px">${settings.lab_name || 'IQRA GROUP OF LABORATORY'}</h1><div style="font-size:12px;color:#555">${settings.lab_address || ''}</div><div style="font-size:12px;color:#555">${settings.lab_phone || ''}${settings.lab_email ? ' · '+settings.lab_email : ''}</div></div></div>
    <h2 style="font-size:15px;margin-top:16px">Patient Invoice / Slip &mdash; ${invoice.invoice_code}</h2>
    <div class="meta">
      <div class="box"><b>Patient:</b> ${order.patient_name} (${order.patient_code})<br><b>Gender/Age:</b> ${order.gender || '-'} / ${order.age_years || '-'}<br><b>Mobile:</b> ${order.mobile || '-'}</div>
      <div class="box"><b>Order:</b> ${order.order_code}<br><b>Referring Doctor:</b> ${order.doctor_name || '-'}<br><b>Date:</b> ${order.created_at}</div>
    </div>
    <div style="margin-top:10px;font-size:12px;color:#555"><b>Sample ID(s):</b> ${sampleCodes || '-'}</div>
    <table><thead><tr><th>Test</th><th style="text-align:right">Price</th><th style="text-align:center">TAT</th><th>Expected Report By</th></tr></thead><tbody>${rowsHtml}</tbody></table>
    <div class="totals">
      <div><span>Subtotal</span><span>${invoice.subtotal.toFixed(2)}</span></div>
      <div><span>Discount</span><span>-${invoice.discount.toFixed(2)}</span></div>
      <div style="font-weight:700;border-top:1px solid #333;padding-top:6px"><span>Net Amount</span><span>${invoice.net_amount.toFixed(2)}</span></div>
      <div><span>Paid</span><span>${invoice.paid_amount.toFixed(2)}</span></div>
      <div style="font-weight:700"><span>Balance</span><span>${invoice.balance.toFixed(2)}</span></div>
    </div>
    <div style="margin-top:8px"><span class="badge ${invoice.status.toLowerCase()}">${invoice.status}</span></div>
    ${payments.length ? `<h4 style="font-size:13px;margin-top:14px">Payment History</h4><table><tbody>${paymentsHtml}</tbody></table>` : ''}
    <div style="margin-top:20px;padding:10px;background:#f5f5f5;border-radius:6px;font-size:13px"><b>Overall report expected by:</b> ${maxDue ? fmtDateTime(maxDue) : '-'}</div>
    <p style="margin-top:30px;font-size:11px;color:#777">This is a computer-generated invoice/slip. Please retain the Sample ID(s) above for tracking your report status.</p>
  
    <div style="position:fixed;left:50%;top:50%;transform:translate(-50%,-50%) rotate(-25deg);font-size:46px;font-weight:800;color:#991b1b;opacity:.055;white-space:nowrap;z-index:-1;pointer-events:none">IQRA GROUP OF LABORATORY</div>
    <div style="margin-top:24px;padding-top:10px;border-top:1px solid #ddd;text-align:center;font-size:10px;color:#666">IQRA GROUP OF LABORATORY · 0301-5549322, 0302-7326325 · hafizsaleem2959@gmail.com<br>Main Bazar Taty Pur, Qadir Pur Rawan Road, Multan</div>
</body></html>`;
  sendHTML(res, 200, html);
});

// ===================== SAMPLES (collection/reception) =====================
route('GET', '/api/samples', async (req, res, params, body, query) => {
  if (!requireAuth(req, res)) return;
  const status = query.get('status');
  let rows;
  if (status) {
    rows = db.prepare(`SELECT s.*, p.name as patient_name, t.name as test_name FROM samples s
      JOIN orders o ON o.id=s.order_id JOIN patients p ON p.id=o.patient_id
      LEFT JOIN order_items oi ON oi.id=s.order_item_id LEFT JOIN tests t ON t.id=oi.test_id
      WHERE s.status = ? ORDER BY s.id DESC LIMIT 200`).all(status);
  } else {
    rows = db.prepare(`SELECT s.*, p.name as patient_name, t.name as test_name FROM samples s
      JOIN orders o ON o.id=s.order_id JOIN patients p ON p.id=o.patient_id
      LEFT JOIN order_items oi ON oi.id=s.order_item_id LEFT JOIN tests t ON t.id=oi.test_id
      ORDER BY s.id DESC LIMIT 200`).all();
  }
  sendJSON(res, 200, rows);
});

route('POST', '/api/samples/:id/collect', async (req, res, params) => {
  const user = requireAuth(req, res); if (!user) return;
  if (!hasPerm(user, 'sample.collect')) return sendJSON(res, 403, { error: 'Sample collection is not permitted for this user.' });
  db.prepare(`UPDATE samples SET status='Collected', collected_by=?, collected_at=datetime('now') WHERE id=?`).run(user.id, params.id);
  const s = db.prepare('SELECT order_item_id FROM samples WHERE id=?').get(params.id);
  if (s.order_item_id) db.prepare(`UPDATE order_items SET status='Collected' WHERE id=?`).run(s.order_item_id);
  audit(user, 'collect', 'samples', params.id, {});
  sendJSON(res, 200, { ok: true });
});

route('POST', '/api/samples/:id/receive', async (req, res, params) => {
  const user = requireAuth(req, res); if (!user) return;
  if (!hasPerm(user, 'sample.receive')) return sendJSON(res, 403, { error: 'Sample reception is not permitted for this user.' });
  db.prepare(`UPDATE samples SET status='Received', received_at=datetime('now') WHERE id=?`).run(params.id);
  const s = db.prepare('SELECT order_item_id FROM samples WHERE id=?').get(params.id);
  if (s.order_item_id) db.prepare(`UPDATE order_items SET status='Received' WHERE id=?`).run(s.order_item_id);
  audit(user, 'receive', 'samples', params.id, {});
  sendJSON(res, 200, { ok: true });
});

route('POST', '/api/samples/:id/reject', async (req, res, params, body) => {
  const user = requireAuth(req, res); if (!user) return;
  if (!hasPerm(user, 'sample.receive') && !hasPerm(user, 'sample.collect')) return sendJSON(res, 403, { error: 'Sample rejection is not permitted for this user.' });
  db.prepare(`UPDATE samples SET status='Rejected', rejection_reason=? WHERE id=?`).run(body.reason || 'Other', params.id);
  audit(user, 'reject', 'samples', params.id, { reason: body.reason });
  sendJSON(res, 200, { ok: true });
});

// ===================== RESULTS =====================
route('GET', '/api/results/pending-entry', async (req, res) => {
  if (!requireAuth(req, res)) return;
  const rows = db.prepare(`SELECT oi.id as order_item_id, o.id as order_id, o.order_code, p.name as patient_name, p.gender, p.age_years,
      t.name as test_name, t.unit, t.ref_low, t.ref_high, t.critical_low, t.critical_high, t.result_type, s.id as sample_id, s.status as sample_status
    FROM order_items oi
    JOIN orders o ON o.id = oi.order_id
    JOIN patients p ON p.id = o.patient_id
    JOIN tests t ON t.id = oi.test_id
    LEFT JOIN samples s ON s.order_item_id = oi.id
    WHERE oi.status = 'Received' ORDER BY oi.id`).all();
  sendJSON(res, 200, rows);
});

route('POST', '/api/results', async (req, res, params, body) => {
  const user = requireAuth(req, res); if (!user) return;
  if (!hasPerm(user, 'result.enter')) return sendJSON(res, 403, { error: 'Result entry is not permitted for this user.' });
  const { order_item_id, sample_id, value, remarks } = body;
  const item = db.prepare(`SELECT oi.*, t.ref_low, t.ref_high, t.critical_low, t.critical_high, t.id as test_id FROM order_items oi JOIN tests t ON t.id=oi.test_id WHERE oi.id=?`).get(order_item_id);
  if (!item) return sendJSON(res, 404, { error: 'Order item not found' });
  const flag = flagResult(value, item.ref_low, item.ref_high, item.critical_low, item.critical_high);
  const info = db.prepare(`INSERT INTO results (order_item_id, sample_id, value, flag, ref_low, ref_high, remarks, entered_by, status)
    VALUES (?,?,?,?,?,?,?,?, 'Entered')`).run(order_item_id, sample_id || null, String(value), flag, item.ref_low, item.ref_high, remarks ? String(remarks).trim() : null, user.id);
  const resultId = Number(info.lastInsertRowid);
  db.prepare(`UPDATE order_items SET status='Resulted' WHERE id=?`).run(order_item_id);

  if (flag === 'Critical-High' || flag === 'Critical-Low') {
    const order = db.prepare('SELECT patient_id FROM orders o JOIN order_items oi ON oi.order_id=o.id WHERE oi.id=?').get(order_item_id);
    const threshold = flag === 'Critical-High' ? item.critical_high : item.critical_low;
    db.prepare(`INSERT INTO critical_results (result_id, order_item_id, patient_id, test_id, value, threshold, direction, status)
      VALUES (?,?,?,?,?,?,?, 'Detected')`).run(resultId, order_item_id, order.patient_id, item.test_id, String(value), String(threshold), flag === 'Critical-High' ? 'High' : 'Low');
  }
  audit(user, 'enter_result', 'results', String(resultId), { order_item_id, value, flag });
  sendJSON(res, 201, { id: resultId, flag });
});

route('GET', '/api/results/pending-verification', async (req, res) => {
  if (!requireAuth(req, res)) return;
  const rows = db.prepare(`SELECT r.*, t.name as test_name, t.unit, o.order_code, p.name as patient_name
    FROM results r JOIN order_items oi ON oi.id=r.order_item_id JOIN tests t ON t.id=oi.test_id
    JOIN orders o ON o.id=oi.order_id JOIN patients p ON p.id=o.patient_id
    WHERE r.status='Entered' ORDER BY r.id`).all();
  sendJSON(res, 200, rows);
});
route('POST', '/api/results/:id/verify', async (req, res, params) => {
  const user = requireAuth(req, res); if (!user) return;
  if (!hasPerm(user, 'result.verify')) return sendJSON(res, 403, { error: 'Result verification is restricted to authorized users.' });
  db.prepare(`UPDATE results SET status='Verified', verified_by=?, verified_at=datetime('now') WHERE id=?`).run(user.id, params.id);
  const r = db.prepare('SELECT order_item_id FROM results WHERE id=?').get(params.id);
  db.prepare(`UPDATE order_items SET status='Verified' WHERE id=?`).run(r.order_item_id);
  db.prepare(`UPDATE critical_results SET status='Notified', notified_by=?, notified_at=datetime('now'), notified_person=? WHERE result_id=? AND status='Detected'`)
    .run(user.id, req._body && req._body.notified_person || 'Referring physician', params.id);
  audit(user, 'verify', 'results', params.id, {});
  sendJSON(res, 200, { ok: true });
});

route('GET', '/api/results/pending-authorization', async (req, res) => {
  if (!requireAuth(req, res)) return;
  const rows = db.prepare(`SELECT r.*, t.name as test_name, t.unit, o.order_code, o.id as order_id, p.name as patient_name
    FROM results r JOIN order_items oi ON oi.id=r.order_item_id JOIN tests t ON t.id=oi.test_id
    JOIN orders o ON o.id=oi.order_id JOIN patients p ON p.id=o.patient_id
    WHERE r.status='Verified' ORDER BY r.id`).all();
  sendJSON(res, 200, rows);
});
route('POST', '/api/results/:id/authorize', async (req, res, params) => {
  const user = requireAuth(req, res); if (!user) return;
  if (!hasPerm(user, 'result.authorize')) return sendJSON(res, 403, { error: 'Result authorization is restricted to authorized users.' });
  const requestedEmployeeId=req._body && req._body.authorized_employee_id ? Number(req._body.authorized_employee_id) : null;
  if(requestedEmployeeId){
    const emp=db.prepare(`SELECT id FROM employees WHERE id=? AND status='active' AND employee_type IN ('Consultant','Pathologist')`).get(requestedEmployeeId);
    if(!emp)return sendJSON(res,400,{error:'Selected consultant/pathologist is not active or is invalid'});
    db.prepare(`INSERT INTO result_authorizers(result_id,employee_id) VALUES(?,?) ON CONFLICT(result_id) DO UPDATE SET employee_id=excluded.employee_id, assigned_at=datetime('now')`).run(params.id,requestedEmployeeId);
  }
  db.prepare(`UPDATE results SET status='Authorized', authorized_by=?, authorized_at=datetime('now') WHERE id=?`).run(user.id, params.id);
  const r = db.prepare('SELECT order_item_id FROM results WHERE id=?').get(params.id);
  db.prepare(`UPDATE order_items SET status='Authorized' WHERE id=?`).run(r.order_item_id);
  audit(user, 'authorize', 'results', params.id, {});

  // if all items of the order are authorized, generate a report + mark order Reported
  const oi = db.prepare('SELECT order_id FROM order_items WHERE id=?').get(r.order_item_id);
  const remaining = db.prepare(`SELECT COUNT(*) c FROM order_items WHERE order_id=? AND status != 'Authorized'`).get(oi.order_id).c;
  if (remaining === 0) {
    const report_code = nextNumber('REPORT', 'RPT');
    db.prepare('INSERT INTO reports (report_code, order_id, authorized_by) VALUES (?,?,?)').run(report_code, oi.order_id, user.id);
    db.prepare(`UPDATE orders SET status='Reported' WHERE id=?`).run(oi.order_id);
  }
  sendJSON(res, 200, { ok: true });
});

route('POST', '/api/results/:id/correct', async (req, res, params, body) => {
  const user = requireAuth(req, res); if (!user) return;
  if (!hasPerm(user, '*') && user.role !== 'Pathologist') return sendJSON(res, 403, { error: 'Not permitted to correct authorized results' });
  const r = db.prepare('SELECT * FROM results WHERE id=?').get(params.id);
  if (!r) return sendJSON(res, 404, { error: 'Not found' });
  db.prepare('INSERT INTO result_history (result_id, old_value, new_value, reason, changed_by) VALUES (?,?,?,?,?)')
    .run(r.id, r.value, body.new_value, body.reason || '', user.id);
  db.prepare(`UPDATE results SET value=?, status='Corrected' WHERE id=?`).run(body.new_value, r.id);
  audit(user, 'correct_result', 'results', params.id, { old: r.value, new: body.new_value, reason: body.reason });
  sendJSON(res, 200, { ok: true });
});

// ===================== CRITICAL RESULTS REGISTER =====================
function criticalRegisterRows(query) {
  const clauses = []; const vals = [];
  const from = (query.get('from') || '').trim();
  const to = (query.get('to') || '').trim();
  if (from) { clauses.push("date(cr.detected_at) >= date(?)"); vals.push(from); }
  if (to) { clauses.push("date(cr.detected_at) <= date(?)"); vals.push(to); }
  const where = clauses.length ? 'WHERE ' + clauses.join(' AND ') : '';
  return db.prepare(`SELECT cr.id, cr.result_id, cr.order_item_id, cr.patient_id, cr.test_id,
      cr.value as critical_value, cr.threshold, cr.direction, cr.status, cr.detected_at,
      cr.notified_person, cr.notified_by, cr.notified_at, cr.acknowledged_at, cr.closed_at, cr.remarks,
      p.name as patient_name, p.patient_code, p.cnic, p.mobile, p.gender, p.age_years, p.guardian_name, p.address,
      o.order_code, o.created_at as order_date, d.name as doctor_name,
      t.code as test_code, t.name as test_name, t.unit, t.sample_type,
      dep.name as department_name, r.value as result_value
    FROM critical_results cr
      JOIN patients p ON p.id=cr.patient_id
      JOIN order_items oi ON oi.id=cr.order_item_id
      JOIN orders o ON o.id=oi.order_id
      JOIN tests t ON t.id=cr.test_id
      LEFT JOIN departments dep ON dep.id=t.department_id
      LEFT JOIN doctors d ON d.id=o.doctor_id
      LEFT JOIN results r ON r.id=cr.result_id
    ${where}
    ORDER BY cr.detected_at DESC, cr.id DESC`).all(...vals);
}
route('GET', '/api/critical-results', async (req, res, params, body, query) => {
  if (!requireAuth(req, res)) return;
  const rows = criticalRegisterRows(query);
  sendJSON(res, 200, rows.slice(0, 500));
});
route('GET', '/api/critical-results/backup.csv', async (req, res, params, body, query) => {
  const user = verifyToken(query.get('token')) || getUser(req);
  if (!user) return sendJSON(res, 401, {error:'Not authenticated'});
  if (!hasPerm(user, 'critical.manage') && !hasPerm(user, '*')) return sendJSON(res, 403, {error:'Critical backup access is restricted.'});
  const rows = criticalRegisterRows(query);
  const cols = ['id','detected_at','patient_name','patient_code','cnic','mobile','gender','age_years','guardian_name','address','order_code','order_date','doctor_name','department_name','test_code','test_name','sample_type','unit','critical_value','threshold','direction','status','notified_person','notified_at','acknowledged_at','closed_at','remarks'];
  const csv = [cols.join(','), ...rows.map(r => cols.map(k => { const v = r[k] ?? ''; return '"'+String(v).replace(/"/g,'""')+'"'; }).join(','))].join('\r\n');
  res.writeHead(200, {'Content-Type':'text/csv; charset=utf-8','Content-Disposition':'attachment; filename="iqra-critical-results-backup.csv"'});
  res.end(csv);
});
route('GET', '/api/critical-results/print-register', async (req, res, params, body, query) => {
  const user = verifyToken(query.get('token')) || getUser(req);
  if (!user) return sendHTML(res, 401, '<h3>Not authenticated</h3>');
  if (!hasPerm(user, 'critical.manage') && !hasPerm(user, '*')) return sendHTML(res, 403, '<h3>Critical register access is restricted.</h3>');
  const rows = criticalRegisterRows(query);
  const settings = getAllSettings();
  const issued = new Date().toLocaleString('en-GB',{day:'2-digit',month:'short',year:'numeric',hour:'2-digit',minute:'2-digit'});
  const tr = rows.map((r,i)=>`<tr><td>${i+1}</td><td>${esc(r.detected_at)}</td><td><b>${esc(r.patient_name)}</b><br>MR#: ${esc(r.patient_code)}<br>CNIC: ${esc(r.cnic||'-')}<br>Mobile: ${esc(r.mobile||'-')}<br>Age/Gender: ${esc(r.age_years??'-')} / ${esc(r.gender||'-')}</td><td><b>${esc(r.test_name)}</b><br>${esc(r.department_name||'-')}<br>Sample: ${esc(r.sample_type||'-')}</td><td><b>${esc(r.result_value ?? r.critical_value ?? '')}</b> ${esc(r.unit||'')}<br>Critical ${esc(r.direction||'')}: ${esc(r.threshold||'-')}</td><td>${esc(r.status)}<br>Notified: ${esc(r.notified_person||'-')}<br>${esc(r.notified_at||'')}</td><td>Order: ${esc(r.order_code)}<br>Doctor: ${esc(r.doctor_name||'-')}<br>Remarks: ${esc(r.remarks||'-')}</td></tr>`).join('');
  sendHTML(res,200,`<!doctype html><html><head><meta charset="utf-8"><title>Critical Results Register - PHC Visit</title><style>*{box-sizing:border-box}body{font-family:Arial,Helvetica,sans-serif;color:#111;margin:0;background:#fff}.page{padding:18px;max-width:1500px;margin:auto}.head{display:flex;align-items:center;gap:16px;border-bottom:2px solid #9b1c1c;padding-bottom:10px}.logo{width:78px;height:78px}.lab{flex:1;text-align:center}.lab h1{margin:0;color:#9b1c1c;font-size:25px}.lab p{margin:3px 0;font-size:11px}.title{text-align:center;margin:12px 0 8px;font-size:20px;font-weight:800}.sub{text-align:center;font-size:11px;margin-bottom:12px}.actions{text-align:right;margin-bottom:10px}.actions button{padding:8px 13px;margin-left:6px}.watermark{position:fixed;left:50%;top:52%;transform:translate(-50%,-50%);opacity:.12;z-index:-1;pointer-events:none}.watermark img{width:430px;height:430px;object-fit:contain}table{width:100%;border-collapse:collapse}th{background:#eee;border:1px solid #555;padding:7px;font-size:10px;text-align:left}td{border:1px solid #aaa;padding:6px;font-size:9px;vertical-align:top}.summary{display:flex;justify-content:space-between;border:1px solid #aaa;padding:8px;margin-bottom:10px;font-size:11px}.foot{border-top:1px solid #999;margin-top:14px;padding-top:7px;font-size:9px;display:flex;justify-content:space-between}@media print{.actions{display:none}.page{padding:8mm}.watermark{position:fixed}}</style></head><body><div class="page"><div class="actions"><button onclick="window.print()">Print / Save PDF</button><button onclick="location.href='/api/critical-results/backup.csv${query.toString()?'?'+query.toString():''}'">Download CSV Backup</button></div><div class="watermark"><img src="/iqra-watermark-gray.png" alt=""></div><div class="head"><img class="logo" src="/iqra-personal-logo.png"><div class="lab"><h1>${esc(settings.lab_name||'IQRA GROUP OF LABORATORY')}</h1><p>${esc(settings.lab_address||'')} · ${esc(settings.lab_phone||'')}</p><p>${esc(settings.lab_email||'')}</p></div></div><div class="title">CRITICAL RESULTS REGISTER</div><div class="sub">For Regulatory / PHC Inspection & Record Review · Generated: ${issued}</div><div class="summary"><span><b>Total Critical Records:</b> ${rows.length}</span><span><b>Register:</b> Complete historical critical-result record</span></div><table><thead><tr><th>#</th><th>Detected</th><th>Patient Information</th><th>Critical Test</th><th>Result / Critical Limit</th><th>Notification / Status</th><th>Order / Clinical Information</th></tr></thead><tbody>${tr||'<tr><td colspan="7">No critical results recorded.</td></tr>'}</tbody></table><div class="foot"><span>IQRA GROUP OF LABORATORY · Critical Results Register</span><span>Electronically generated record — signature not required.</span></div></div></body></html>`);
});
route('POST', '/api/critical-results/:id/acknowledge', async (req, res, params, body) => {
  const user = requireAuth(req, res); if (!user) return;
  if (!hasPerm(user, 'critical.manage')) return sendJSON(res, 403, { error: 'Critical result management is restricted.' });
  db.prepare(`UPDATE critical_results SET status='Acknowledged', acknowledged_at=datetime('now'), remarks=? WHERE id=?`).run(body.remarks || null, params.id);
  audit(user, 'acknowledge', 'critical_results', params.id, {});
  sendJSON(res, 200, { ok: true });
});
route('POST', '/api/critical-results/:id/close', async (req, res, params, body) => {
  const user = requireAuth(req, res); if (!user) return;
  if (!hasPerm(user, 'critical.manage')) return sendJSON(res, 403, { error: 'Critical result management is restricted.' });
  db.prepare(`UPDATE critical_results SET status='Closed', closed_at=datetime('now'), remarks=? WHERE id=?`).run(body.remarks || null, params.id);
  audit(user, 'close', 'critical_results', params.id, {});
  sendJSON(res, 200, { ok: true });
});

// ===================== REPORTS (printable HTML -> browser Print to PDF) =====================
route('GET', '/api/reports', async (req,res,params,body,query)=>{
  const user=requireAuth(req,res); if(!user)return;
  if(!hasPerm(user,'report.view') && !hasPerm(user,'*')) return sendJSON(res,403,{error:'Report access is not permitted for this user.'});
  const q=(query.get('q')||'').trim();
  const status=(query.get('status')||'').trim();
  const clauses=[]; const vals=[];
  if(q){ clauses.push('(o.order_code LIKE ? OR p.patient_code LIKE ? OR p.name LIKE ? OR r.report_code LIKE ?)'); const x=`%${q}%`; vals.push(x,x,x,x); }
  if(status==='Pending') clauses.push("o.status!='Reported'");
  if(status==='Reported') clauses.push("o.status='Reported'");
  const where=clauses.length?'WHERE '+clauses.join(' AND '):'';
  const rows=db.prepare(`SELECT o.id as order_id,o.order_code,o.status,o.created_at,p.patient_code,p.name as patient_name,p.gender,p.age_years,
      d.name as doctor_name,r.report_code,r.version,r.status as report_status
      FROM orders o JOIN patients p ON p.id=o.patient_id LEFT JOIN doctors d ON d.id=o.doctor_id
      LEFT JOIN reports r ON r.id=(SELECT id FROM reports rr WHERE rr.order_id=o.id ORDER BY id DESC LIMIT 1)
      ${where} ORDER BY o.id DESC LIMIT 300`).all(...vals);
  sendJSON(res,200,rows);
});

route('GET','/api/reports/:orderId/consent',async(req,res,params)=>{
  const u=new URL(req.url,'http://x'); const tokenUser=verifyToken(u.searchParams.get('token'));
  const user=tokenUser || getUser(req); if(!user)return sendHTML(res,401,'<h3>Not authorized</h3>');
  if(!hasPerm(user,'report.print')&&!hasPerm(user,'*'))return sendHTML(res,403,'<h3>Not authorized</h3>');
  const order=db.prepare(`SELECT o.*,p.name patient_name,p.patient_code,p.guardian_name,p.gender,p.age_years,p.mobile,p.address,doc.name doctor_name
    FROM orders o JOIN patients p ON p.id=o.patient_id LEFT JOIN doctors doc ON doc.id=o.doctor_id WHERE o.id=?`).get(params.orderId);
  if(!order)return sendHTML(res,404,'<h3>Order not found</h3>');
  const settings=getAllSettings();
  sendHTML(res,200,`<!doctype html><html><head><meta charset="utf-8"><title>Consent Form - ${esc(order.patient_name)}</title><style>body{font-family:Arial;max-width:800px;margin:0 auto;padding:40px;color:#111}.head{text-align:center;border-bottom:2px solid #111;padding-bottom:14px}.logo{width:74px;height:74px;margin:auto}.row{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin:20px 0}.box{border:1px solid #aaa;padding:10px;min-height:30px}.sig{display:grid;grid-template-columns:1fr 1fr;gap:60px;margin-top:80px}.line{border-top:1px solid #111;padding-top:6px}@media print{button{display:none}}</style></head><body><button onclick="window.print()">Print</button><div class="head"><img class="logo" src="/iqra-personal-logo.png"><h1>${esc(settings.lab_name)}</h1><div>${esc(settings.lab_address||'')} · ${esc(settings.lab_phone||'')}</div><h2>LABORATORY CONSENT FORM</h2></div><div class="row"><div class="box"><b>Patient:</b> ${esc(order.patient_name)}<br><b>MR #:</b> ${esc(order.patient_code)}<br><b>Guardian:</b> ${esc(order.guardian_name||'-')}</div><div class="box"><b>Order:</b> ${esc(order.order_code)}<br><b>Doctor:</b> ${esc(order.doctor_name||'-')}<br><b>Date:</b> ${esc(order.created_at)}</div></div><p>I consent to the collection, processing and reporting of laboratory specimens for the tests ordered by the referring clinician. I understand that results should be interpreted by a qualified healthcare professional and that critical findings may be communicated to the responsible clinician.</p><p>Patient/Guardian Signature: __________________________________________</p><p>CNIC/ID (optional): _____________________ &nbsp;&nbsp; Contact: ${esc(order.mobile||'')}</p><div class="sig"><div class="line">Patient / Guardian</div><div class="line">Authorized Laboratory Staff</div></div></body></html>`);
});

route('GET', '/api/reports/:orderId/view', async (req,res,params)=>{
  const url=new URL(req.url,'http://x'); const payloadUser=verifyToken(url.searchParams.get('token'));
  if(!payloadUser) return sendHTML(res,401,'<h3>Not authorized</h3>');
  if(!hasPerm(payloadUser,'report.print')&&!hasPerm(payloadUser,'*')) return sendHTML(res,403,'<h3>Report access is not permitted</h3>');
  const order=db.prepare(`SELECT o.*,p.name patient_name,p.patient_code,p.guardian_name,p.gender,p.age_years,p.mobile,p.cnic,p.address,p.blood_group,doc.name doctor_name
    FROM orders o JOIN patients p ON p.id=o.patient_id LEFT JOIN doctors doc ON doc.id=o.doctor_id WHERE o.id=?`).get(params.orderId);
  if(!order)return sendHTML(res,404,'<h3>Order not found</h3>');
  const items=db.prepare(`SELECT oi.*,t.name test_name,t.unit,t.ref_low,t.ref_high,t.ref_text,t.critical_low,t.critical_high,t.tat_hours,d.name department_name FROM order_items oi JOIN tests t ON t.id=oi.test_id LEFT JOIN departments d ON d.id=t.department_id WHERE oi.order_id=? ORDER BY d.name,t.name`).all(params.orderId);
  const results=db.prepare('SELECT * FROM results WHERE order_item_id IN (SELECT id FROM order_items WHERE order_id=?) ORDER BY id DESC').all(params.orderId);
  const resultByItem={}; for(const r of results) if(!resultByItem[r.order_item_id]) resultByItem[r.order_item_id]=r;
  const report=db.prepare('SELECT * FROM reports WHERE order_id=? ORDER BY id DESC LIMIT 1').get(params.orderId);
  const settings=getAllSettings();
  const groups=[]; for(const it of items){const key=it.department_name||'Laboratory';let g=groups.find(x=>x.key===key);if(!g){g={key,rows:[]};groups.push(g)}g.rows.push(it)}
  let critical=false;
  const groupHtml=groups.map(g=>{
    const dept=g.key;
    const lower=dept.toLowerCase();
    const tone=lower.includes('hemat')?'hema':lower.includes('chem')&&!lower.includes('special')?'chem':lower.includes('special')?'special':'general';
    return `<section class="dept-section"><div class="dept ${tone}"><span>${esc(dept)}</span><small>(Department): ${esc(dept)}</small></div><table><thead><tr><th>TEST NAME</th><th>RESULT</th><th>UNIT</th><th>REFERENCE RANGE</th></tr></thead><tbody>${g.rows.map(it=>{
      const r=resultByItem[it.id];
      const rawValue=r?.value;
      const cleanValue=(rawValue==null||/^undefined|null$/i.test(String(rawValue).trim()))?'':String(rawValue);
      const flag=cleanValue?flagResult(cleanValue,it.ref_low,it.ref_high,it.critical_low,it.critical_high):'';
      const crit=flag.includes('Critical'); const abn=flag==='High'||flag==='Low'; if(crit)critical=true;
      const ref=it.ref_text||(it.ref_low!=null&&it.ref_high!=null?`${it.ref_low} - ${it.ref_high}`:'-');
      const resultText=crit?`${esc(cleanValue)} <span class="critical-flag">⚠ ${esc(flag.toUpperCase())}</span>`:abn?`${esc(cleanValue)} <span class="abnormal-flag">${esc(flag.toUpperCase())}</span>`:esc(cleanValue);
      const remarks=r?.remarks?`<div class="remarks ${crit?'critical-remark':''}"><b>Remarks:</b> ${esc(r.remarks)}</div>`:'';
      return `<tr class="${crit?'crit':abn?'abn':''}"><td><b>${esc(it.test_name)}</b>${remarks}</td><td class="result-cell ${crit?'criticalText':''}">${resultText}</td><td>${esc(it.unit||'')}</td><td>${esc(ref)}</td></tr>`;
    }).join('')}</tbody></table></section>`;
  }).join('');
  const issued=new Date().toLocaleString('en-GB',{day:'2-digit',month:'short',year:'numeric',hour:'2-digit',minute:'2-digit'});
  const reportDate=report?.created_at || order.created_at || issued;
  const reportStatus=report?.status || 'Released';
  const reportCode=report?.report_code || ('RPT-'+String(order.order_code||order.id));
  const html=`<!doctype html><html><head><meta charset="utf-8"><title>${esc(order.patient_name)} - Laboratory Report</title><style>
  *{box-sizing:border-box}body{font-family:Arial,Helvetica,sans-serif;color:#152033;margin:0;background:#fff}.page{max-width:1000px;margin:0 auto;padding:0 18px 22px;position:relative}.watermark{position:fixed;left:50%;top:55%;transform:translate(-50%,-50%);z-index:0;pointer-events:none;opacity:.11}.watermark img{width:430px;height:430px;object-fit:contain}.content{position:relative;z-index:1}
  .report-main-header{width:100%;margin:0 0 10px;line-height:0;background:#fff;border-bottom:2px solid #b91c1c}.report-main-header img{display:block;width:100%;height:auto;max-height:230px;object-fit:cover;object-position:top center}
  .report-bar{margin-top:10px;border:1px solid #ef8d94;border-radius:7px;padding:8px 10px;display:grid;grid-template-columns:42px 1fr 245px;align-items:center;background:#fff}.report-icon{width:42px;height:42px;border-radius:6px;background:#d10f1b;color:#fff;display:grid;place-items:center;font-size:25px}.report-title{font-size:13px;font-weight:400;color:#172033;padding-left:12px}.report-meta{border-left:1px solid #efc1c4;padding-left:12px;font-size:10px;line-height:1.7}.report-meta b{display:inline-block;width:60px}
  .patient-box{margin-top:10px;border:1px solid #cfe4f3;border-radius:7px;padding:9px 11px;background:linear-gradient(180deg,#fff,#fbfdff)}.box-title{font-size:15px;font-weight:900;color:#123b69;margin-bottom:6px}.patient-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px}.info-table{width:100%;border-collapse:collapse}.info-table td{border:0;padding:3px 4px;font-size:10px}.info-table td:first-child{font-weight:700;width:110px;color:#2e4e69}
  .results-title{margin-top:10px;font-size:16px;font-weight:900;color:#123b69;display:flex;align-items:center;gap:7px}.results-icon{width:28px;height:28px;border-radius:5px;background:#d10f1b;color:#fff;display:grid;place-items:center}.dept-section{margin-top:9px;break-inside:avoid}.dept{height:34px;border-radius:6px 6px 0 0;display:flex;align-items:center;justify-content:space-between;padding:0 10px;font-weight:900}.dept small{font-size:8px}.dept.hema{background:#fde0e3;color:#9d0b16}.dept.chem{background:#dcecfb;color:#07538d}.dept.special{background:#eee1fb;color:#6430a0}.dept.general{background:#eceff3;color:#27384a}table.results{width:100%;border-collapse:collapse}table{width:100%;border-collapse:collapse}th{font-size:10px;border:1px solid #d7e0e8;padding:6px;text-align:left;background:#f7f9fb;color:#111827}td{font-size:10px;border:1px solid #d7e0e8;padding:5px 7px;vertical-align:top}.result-cell{text-align:left}.crit td{background:#fff0f0}.abn td{background:#fff9e5}.criticalText{color:#a00000;font-weight:900}.critical-flag{display:inline-block;margin-left:5px;font-size:7px;color:#a00000;font-weight:900}.abnormal-flag{display:inline-block;margin-left:5px;font-size:7px;color:#9a6500;font-weight:900}.remarks{margin-top:4px;font-size:8px;color:#555;font-weight:500}.critical-remark{color:#a00000}.notice{margin-top:9px;padding:7px 9px;border:1px solid #d8a1a1;background:#fff5f5;border-radius:5px;font-size:9px}.note{margin-top:8px;padding:6px 9px;border-left:3px solid #b5121b;background:#fafafa;font-size:8px;color:#555}.foot{margin-top:7px;border-top:1px solid #b5121b;padding-top:4px;font-size:7px;color:#555;display:flex;justify-content:space-between;gap:12px;line-height:1.35}.no-print{position:fixed;right:15px;top:15px;z-index:20;padding:8px 12px;border:1px solid #aaa;background:#fff;border-radius:5px;cursor:pointer}@media print{.no-print{display:none}.page{padding:0 5mm 8mm;max-width:none}.report-main-header{break-inside:avoid}.report-main-header img{width:100%;max-height:none}.report-bar,.patient-box,.dept-section{break-inside:avoid}.watermark{opacity:.10}.results-title{break-after:avoid}.foot{break-inside:avoid}body{print-color-adjust:exact;-webkit-print-color-adjust:exact}}@media(max-width:700px){.report-main-header img{max-height:150px;object-fit:cover}.report-bar{grid-template-columns:42px 1fr}.report-meta{grid-column:2;margin-top:6px;border-left:0;padding-left:0}.patient-grid{grid-template-columns:1fr}}
  </style></head><body><button class="no-print" onclick="window.print()">Print / Save PDF</button><div class="page"><div class="watermark"><img src="/iqra-watermark-gray.png" alt=""></div><div class="content">
  <div class="report-main-header"><img src="/report-header.png" alt="IQRA GROUP OF LABORATORY Report Header"></div>
  <div class="patient-box"><div class="box-title">● &nbsp;Patient Information</div><div class="patient-grid"><table class="info-table"><tr><td>Patient Code</td><td>: ${esc(order.patient_code)}</td></tr><tr><td>Patient Name</td><td>: ${esc(order.patient_name)}</td></tr><tr><td>Age / Gender</td><td>: ${esc(order.age_years??'-')} / ${esc(order.gender||'-')}</td></tr><tr><td>CNIC</td><td>: ${esc(order.cnic||'-')}</td></tr></table><table class="info-table"><tr><td>Guardian Name</td><td>: ${esc(order.guardian_name||'-')}</td></tr><tr><td>Address</td><td>: ${esc(order.address||'-')}</td></tr><tr><td>Contact No.</td><td>: ${esc(order.mobile||'-')}</td></tr><tr><td>Collection Centre</td><td>: ${esc(order.collection_centre||'Main Lab')}</td></tr><tr><td>Referred By</td><td>: ${esc(order.doctor_name||'-')}</td></tr></table></div></div>
  <div class="report-bar"><div class="report-icon">▤</div><div class="report-title">Clinical Laboratory Report</div><div class="report-meta"><div><b>Report No:</b> ${esc(reportCode)}</div><div><b>Date:</b> ${esc(fmtDateTime(reportDate))}</div><div><b>Status:</b> <span style="background:#baf0c7;color:#166534;padding:2px 8px;border-radius:12px;font-weight:800">${esc(reportStatus)}</span></div></div></div>
  <div class="results-title"><div class="results-icon">⚗</div> Test Results</div>
  ${groupHtml||'<p>No test results available.</p>'}
  ${critical?'<div class="notice"><b>⚠ Critical Result:</b> Please correlate clinically and notify the responsible clinician immediately.</div>':''}
  <div class="note"><b>Note:</b> Laboratory results should be interpreted together with the patient clinical history and other relevant findings.</div>
  <div class="foot"><div>Mob: 0301-5549322 | 0302-7326325 &nbsp;|&nbsp; Email: hafizsaleem2959@gmail.com</div><div style="text-align:right">Main Bazar Taty Pur, Qadir Pur Rawan Road, Multan &nbsp;|&nbsp; Electronically generated report — signature not required.</div></div>
  </div></div></body></html>`;
  sendHTML(res,200,html);
});

// ===================== ACCOUNTS =====================
function accountRange(searchParams){
  const period=String(searchParams.get('period')||'month');
  const now=new Date();
  const isoToday=new Date(now.getTime()-now.getTimezoneOffset()*60000).toISOString().slice(0,10);
  let from=String(searchParams.get('from')||''), to=String(searchParams.get('to')||'');
  if(period==='today'){from=isoToday;to=isoToday;}
  else if(period==='month'){from=isoToday.slice(0,7)+'-01';to=isoToday;}
  else if(period==='year'){from=isoToday.slice(0,4)+'-01-01';to=isoToday;}
  else if(period==='all'){from='';to='';}
  if(from && !/^\d{4}-\d{2}-\d{2}$/.test(from)) from='';
  if(to && !/^\d{4}-\d{2}-\d{2}$/.test(to)) to='';
  return {period,from,to};
}
route('GET','/api/accounts/summary',async(req,res)=>{
  const user=requireAuth(req,res); if(!user)return;
  if(!hasPerm(user,'accounts.view')) return sendJSON(res,403,{error:'Accounts access is not permitted for this user.'});
  const u=new URL(req.url,'http://x'); const {period,from,to}=accountRange(u.searchParams); const range=from&&to;
  const income=Number(db.prepare(`SELECT COALESCE(SUM(amount),0) s FROM payments${range?' WHERE date(created_at) BETWEEN ? AND ?':''}`).get(...(range?[from,to]:[])).s||0);
  const billed=Number(db.prepare(`SELECT COALESCE(SUM(net_amount),0) s FROM invoices${range?' WHERE date(created_at) BETWEEN ? AND ?':''}`).get(...(range?[from,to]:[])).s||0);
  const expenses=Number(db.prepare(`SELECT COALESCE(SUM(amount),0) s FROM expenses${range?' WHERE expense_date BETWEEN ? AND ?':''}`).get(...(range?[from,to]:[])).s||0);
  const expenseCount=Number(db.prepare(`SELECT COUNT(*) c FROM expenses${range?' WHERE expense_date BETWEEN ? AND ?':''}`).get(...(range?[from,to]:[])).c||0);
  const invoiceCount=Number(db.prepare(`SELECT COUNT(*) c FROM invoices${range?' WHERE date(created_at) BETWEEN ? AND ?':''}`).get(...(range?[from,to]:[])).c||0);
  const paymentCount=Number(db.prepare(`SELECT COUNT(*) c FROM payments${range?' WHERE date(created_at) BETWEEN ? AND ?':''}`).get(...(range?[from,to]:[])).c||0);
  const byCategory=db.prepare(`SELECT category,COALESCE(SUM(amount),0) amount,COUNT(*) count FROM expenses${range?' WHERE expense_date BETWEEN ? AND ?':''} GROUP BY category ORDER BY amount DESC`).all(...(range?[from,to]:[]));
  const byMethod=db.prepare(`SELECT payment_method,COALESCE(SUM(amount),0) amount,COUNT(*) count FROM expenses${range?' WHERE expense_date BETWEEN ? AND ?':''} GROUP BY payment_method ORDER BY amount DESC`).all(...(range?[from,to]:[]));
  sendJSON(res,200,{period,from,to,income,billed,expenses,profit_loss:income-expenses,expense_count:expenseCount,invoices:invoiceCount,payments:paymentCount,by_category:byCategory,by_method:byMethod});
});
route('GET','/api/accounts/income',async(req,res)=>{
  const user=requireAuth(req,res); if(!user)return;
  if(!hasPerm(user,'accounts.view')) return sendJSON(res,403,{error:'Accounts access is not permitted for this user.'});
  const u=new URL(req.url,'http://x'); const {from,to}=accountRange(u.searchParams); let sql=`SELECT p.*,i.invoice_code,pt.patient_code,pt.full_name AS patient_name FROM payments p LEFT JOIN invoices i ON i.id=p.invoice_id LEFT JOIN orders o ON o.id=i.order_id LEFT JOIN patients pt ON pt.id=o.patient_id WHERE 1=1`,args=[];
  if(from&&to){sql+=' AND date(p.created_at) BETWEEN ? AND ?';args.push(from,to)} sql+=' ORDER BY p.created_at DESC LIMIT 2000'; sendJSON(res,200,db.prepare(sql).all(...args));
});
route('GET','/api/accounts/statement',async(req,res)=>{
  const user=requireAuth(req,res); if(!user)return;
  if(!hasPerm(user,'accounts.view')) return sendJSON(res,403,{error:'Accounts access is not permitted for this user.'});
  const u=new URL(req.url,'http://x'); const {period,from,to}=accountRange(u.searchParams); const range=from&&to;
  const income=Number(db.prepare(`SELECT COALESCE(SUM(amount),0) s FROM payments${range?' WHERE date(created_at) BETWEEN ? AND ?':''}`).get(...(range?[from,to]:[])).s||0);
  const expenses=Number(db.prepare(`SELECT COALESCE(SUM(amount),0) s FROM expenses${range?' WHERE expense_date BETWEEN ? AND ?':''}`).get(...(range?[from,to]:[])).s||0);
  const payments=db.prepare(`SELECT p.*,i.invoice_code,pt.patient_code,pt.full_name AS patient_name FROM payments p LEFT JOIN invoices i ON i.id=p.invoice_id LEFT JOIN orders o ON o.id=i.order_id LEFT JOIN patients pt ON pt.id=o.patient_id${range?' WHERE date(p.created_at) BETWEEN ? AND ?':''} ORDER BY p.created_at DESC`).all(...(range?[from,to]:[]));
  const ex=db.prepare(`SELECT * FROM expenses${range?' WHERE expense_date BETWEEN ? AND ?':''} ORDER BY expense_date DESC,id DESC`).all(...(range?[from,to]:[]));
  const rows=(a)=>a.map(x=>`<tr>${x}</tr>`).join('');
  const html=`<!doctype html><html><head><meta charset="utf-8"><title>Accounts Statement</title><style>body{font-family:Arial,sans-serif;margin:30px;color:#222}h1{margin:0;color:#9d1111}h2{margin:24px 0 8px}.head{border-bottom:3px solid #9d1111;padding-bottom:12px}.meta{margin-top:8px}.cards{display:flex;gap:10px;margin:18px 0}.card{border:1px solid #ddd;padding:12px;flex:1}.card b{display:block;font-size:18px;margin-top:5px}table{width:100%;border-collapse:collapse;margin-top:8px}th,td{border:1px solid #ddd;padding:7px;text-align:left}th{background:#f3f5f7}.profit{font-size:18px;font-weight:bold;margin:15px 0}.foot{margin-top:25px;border-top:1px solid #ddd;padding-top:10px;font-size:12px}@media print{body{margin:12mm}.noprint{display:none}}</style></head><body><div class="head"><h1>IQRA GROUP OF LABORATORY</h1><div>Accounts & Financial Statement</div><div class="meta">Period: ${esc(from||'Beginning')} to ${esc(to||'Today')} · ${esc(period)}</div></div><div class="cards"><div class="card">Payments Received<b>Rs ${income.toFixed(2)}</b></div><div class="card">Expenses<b>Rs ${expenses.toFixed(2)}</b></div><div class="card">Net ${income-expenses>=0?'Profit':'Loss'}<b>Rs ${Math.abs(income-expenses).toFixed(2)}</b></div></div><div class="profit">Profit / Loss = Payments Received − Expenses = Rs ${Math.abs(income-expenses).toFixed(2)} ${income-expenses>=0?'Profit':'Loss'}</div><h2>Income / Payments</h2><table><thead><tr><th>Date</th><th>Invoice</th><th>Patient</th><th>Method</th><th>Amount</th></tr></thead><tbody>${payments.map(x=>`<tr><td>${esc(x.created_at||'')}</td><td>${esc(x.invoice_code||'-')}</td><td>${esc(x.patient_name||'-')}</td><td>${esc(x.method||'-')}</td><td>Rs ${Number(x.amount||0).toFixed(2)}</td></tr>`).join('')||'<tr><td colspan="5">No payments.</td></tr>'}</tbody></table><h2>Expenses</h2><table><thead><tr><th>Date</th><th>Code</th><th>Category</th><th>Vendor / Payee</th><th>Description</th><th>Amount</th></tr></thead><tbody>${ex.map(x=>`<tr><td>${esc(x.expense_date)}</td><td>${esc(x.expense_code)}</td><td>${esc(x.category)}</td><td>${esc(x.vendor||'-')}</td><td>${esc(x.description||'-')}</td><td>Rs ${Number(x.amount||0).toFixed(2)}</td></tr>`).join('')||'<tr><td colspan="6">No expenses.</td></tr>'}</tbody></table><div class="foot">IQRA GROUP OF LABORATORY · Main Bazar Taty Pur, Qadir Pur Rawan Road, Multan · Mob: 0301-5549322, 0302-7326325 · Email: hafizsaleem2959@gmail.com</div><script>window.onload=()=>window.print()</script></body></html>`; sendHTML(res,200,html);
});
route('GET','/api/accounts/expenses',async(req,res)=>{
  const user=requireAuth(req,res); if(!user)return;
  if(!hasPerm(user,'accounts.view')) return sendJSON(res,403,{error:'Accounts access is not permitted for this user.'});
  const u=new URL(req.url,'http://x'); const {from,to}=accountRange(u.searchParams); const q=String(u.searchParams.get('q')||'').trim();
  let sql=`SELECT e.*,u.full_name AS created_by_name FROM expenses e LEFT JOIN users u ON u.id=e.created_by WHERE 1=1`,args=[];
  if(from&&to){sql+=' AND e.expense_date BETWEEN ? AND ?';args.push(from,to)}
  if(q){sql+=' AND (e.expense_code LIKE ? OR e.category LIKE ? OR COALESCE(e.description,\'\') LIKE ? OR COALESCE(e.vendor,\'\') LIKE ?)';const like='%'+q+'%';args.push(like,like,like,like)}
  sql+=' ORDER BY e.expense_date DESC,e.id DESC LIMIT 1000'; sendJSON(res,200,db.prepare(sql).all(...args));
});
route('POST','/api/accounts/expenses',async(req,res,params,body)=>{
  const user=requirePerm(req,res,'accounts.manage'); if(!user)return;
  const amount=Number(body.amount), category=String(body.category||'').trim(), date=String(body.expense_date||'').trim();
  if(!category||!Number.isFinite(amount)||amount<=0)return sendJSON(res,400,{error:'Category and a valid positive amount are required.'});
  const expenseDate=/^\d{4}-\d{2}-\d{2}$/.test(date)?date:new Date().toISOString().slice(0,10), code=nextNumber('EXPENSE','EXP');
  const r=db.prepare(`INSERT INTO expenses(expense_code,expense_date,category,description,vendor,payment_method,amount,notes,created_by) VALUES(?,?,?,?,?,?,?,?,?)`).run(code,expenseDate,category,body.description||null,body.vendor||null,body.payment_method||'Cash',amount,body.notes||null,user.id);
  audit(user,'create','accounts_expense',code,{amount,category,expense_date:expenseDate}); sendJSON(res,201,{id:Number(r.lastInsertRowid),expense_code:code});
});
route('PATCH','/api/accounts/expenses/:id',async(req,res,params,body)=>{
  const user=requirePerm(req,res,'accounts.manage'); if(!user)return; const e=db.prepare('SELECT * FROM expenses WHERE id=?').get(params.id); if(!e)return sendJSON(res,404,{error:'Expense not found'});
  const amount=Number(body.amount==null?e.amount:body.amount),category=String(body.category==null?e.category:body.category).trim(),d=String(body.expense_date==null?e.expense_date:body.expense_date);
  if(!category||!Number.isFinite(amount)||amount<=0||!/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/.test(d))return sendJSON(res,400,{error:'Valid category, amount and date are required.'});
  db.prepare(`UPDATE expenses SET expense_date=?,category=?,description=?,vendor=?,payment_method=?,amount=?,notes=?,updated_at=datetime('now') WHERE id=?`).run(d,category,body.description==null?e.description:body.description,body.vendor==null?e.vendor:body.vendor,body.payment_method==null?e.payment_method:body.payment_method,amount,body.notes==null?e.notes:body.notes,params.id);
  audit(user,'update','accounts_expense',e.expense_code,{amount,category,expense_date:d}); sendJSON(res,200,{ok:true});
});
route('DELETE','/api/accounts/expenses/:id',async(req,res,params)=>{
  const user=requirePerm(req,res,'accounts.manage'); if(!user)return; const e=db.prepare('SELECT * FROM expenses WHERE id=?').get(params.id); if(!e)return sendJSON(res,404,{error:'Expense not found'});
  db.prepare('DELETE FROM expenses WHERE id=?').run(params.id); audit(user,'delete','accounts_expense',e.expense_code,{amount:e.amount,category:e.category}); sendJSON(res,200,{ok:true});
});

// ===================== INVENTORY =====================
route('GET', '/api/inventory', async (req, res) => {
  if (!requireAuth(req, res)) return;
  sendJSON(res, 200, db.prepare('SELECT * FROM inventory_items ORDER BY name').all());
});
route('POST', '/api/inventory/:id/transaction', async (req, res, params, body) => {
  const user = requireAuth(req, res); if (!user) return;
  if (!hasPerm(user, 'inventory.transaction')) return sendJSON(res, 403, { error: 'Inventory transactions are not permitted for this user.' });
  const item = db.prepare('SELECT * FROM inventory_items WHERE id=?').get(params.id);
  if (!item) return sendJSON(res, 404, { error: 'Not found' });
  const qty = parseFloat(body.quantity);
  if (!qty) return sendJSON(res, 400, { error: 'Invalid quantity' });
  let newStock = item.stock_qty;
  if (body.type === 'Receipt') newStock += qty;
  else if (body.type === 'Issue' || body.type === 'Waste') newStock -= qty;
  else if (body.type === 'Adjustment') newStock = qty;
  if (newStock < 0) return sendJSON(res, 400, { error: 'Insufficient stock' });
  db.prepare('INSERT INTO inventory_transactions (item_id, type, quantity, batch, expiry, reason, created_by) VALUES (?,?,?,?,?,?,?)')
    .run(item.id, body.type, qty, body.batch || null, body.expiry || null, body.reason || null, user.id);
  db.prepare('UPDATE inventory_items SET stock_qty=? WHERE id=?').run(newStock, item.id);
  audit(user, body.type.toLowerCase(), 'inventory', item.code, { qty });
  sendJSON(res, 200, { stock_qty: newStock });
});

// ===================== DASHBOARD =====================
route('GET', '/api/dashboard', async (req, res) => {
  if (!requireAuth(req, res)) return;
  const today = new Date().toISOString().slice(0, 10);
  const stats = {
    patients_total: db.prepare('SELECT COUNT(*) c FROM patients').get().c,
    orders_today: db.prepare(`SELECT COUNT(*) c FROM orders WHERE date(created_at)=date('now')`).get().c,
    samples_pending_collection: db.prepare(`SELECT COUNT(*) c FROM samples WHERE status='Pending Collection'`).get().c,
    samples_pending_reception: db.prepare(`SELECT COUNT(*) c FROM samples WHERE status='Collected'`).get().c,
    pending_result_entry: db.prepare(`SELECT COUNT(*) c FROM order_items WHERE status='Received'`).get().c,
    pending_verification: db.prepare(`SELECT COUNT(*) c FROM results WHERE status='Entered'`).get().c,
    pending_authorization: db.prepare(`SELECT COUNT(*) c FROM results WHERE status='Verified'`).get().c,
    critical_open: db.prepare(`SELECT COUNT(*) c FROM critical_results WHERE status NOT IN ('Closed')`).get().c,
    revenue_today: db.prepare(`SELECT COALESCE(SUM(amount),0) s FROM payments WHERE date(created_at)=date('now')`).get().s,
    outstanding: db.prepare(`SELECT COALESCE(SUM(balance),0) s FROM invoices WHERE status != 'Paid'`).get().s,
    low_stock: db.prepare(`SELECT COUNT(*) c FROM inventory_items WHERE stock_qty <= reorder_level`).get().c
  };
  sendJSON(res, 200, stats);
});

// ===================== SETTINGS / DEMO & GO-LIVE =====================
route('GET', '/api/settings', async (req, res) => {
  if (!requireAuth(req, res)) return;
  sendJSON(res, 200, getAllSettings());
});
route('PATCH', '/api/settings', async (req, res, params, body) => {
  const user = requireAuth(req, res); if (!user) return;
  if (!hasPerm(user, '*')) return sendJSON(res, 403, { error: 'Admin only' });
  for (const [k, v] of Object.entries(body)) {
    if (['lab_name', 'lab_address', 'lab_phone', 'lab_email'].includes(k)) setSetting(k, v);
  }
  audit(user, 'update', 'settings', null, body);
  sendJSON(res, 200, getAllSettings());
});

route('POST', '/api/admin/load-demo-data', async (req, res) => {
  const user = requireAuth(req, res); if (!user) return;
  if (!hasPerm(user, '*')) return sendJSON(res, 403, { error: 'Admin only' });

  const doctor = db.prepare('SELECT id FROM doctors LIMIT 1').get();
  const hb = db.prepare("SELECT id FROM tests WHERE code='HB'").get();
  const glu = db.prepare("SELECT id FROM tests WHERE code='GLU'").get();
  const plt = db.prepare("SELECT id FROM tests WHERE code='PLT'").get();
  if (!hb || !glu) return sendJSON(res, 400, { error: 'Test master is missing default tests (HB/GLU) — cannot seed demo data' });

  // --- Patient 1: fully completed pipeline, normal result, paid ---
  const p1 = db.prepare(`INSERT INTO patients (patient_code,name,gender,dob,age_years,mobile,category,notes) VALUES (?,?,?,?,?,?,?,?)`)
    .run(nextNumber('PATIENT','LAB'), 'Ahmed Bilal', 'Male', '1988-03-12', 38, '03001112222', 'General', '[DEMO DATA]');
  const p1Id = Number(p1.lastInsertRowid);
  const o1 = createOrderWithInvoice({ patient_id: p1Id, doctor_id: doctor ? doctor.id : null, patient_type: 'OPD', priority: 'Routine', test_ids: [hb.id], userId: user.id });
  db.prepare(`INSERT INTO payments (invoice_id, amount, method, received_by) VALUES (?,?,?,?)`).run(o1.invoiceId, o1.net_amount, 'Cash', user.id);
  db.prepare(`UPDATE invoices SET paid_amount=?, balance=0, status='Paid' WHERE id=?`).run(o1.net_amount, o1.invoiceId);
  const s1 = db.prepare('SELECT id FROM samples WHERE order_item_id=?').get(o1.itemIds[0]);
  db.prepare(`UPDATE samples SET status='Received', collected_by=?, collected_at=datetime('now'), received_at=datetime('now') WHERE id=?`).run(user.id, s1.id);
  db.prepare(`UPDATE order_items SET status='Received' WHERE id=?`).run(o1.itemIds[0]);
  const r1 = db.prepare(`INSERT INTO results (order_item_id, sample_id, value, flag, ref_low, ref_high, entered_by, status, verified_by, verified_at, authorized_by, authorized_at)
    VALUES (?,?,?,?,?,?,?, 'Authorized', ?, datetime('now'), ?, datetime('now'))`).run(o1.itemIds[0], s1.id, '14.5', 'Normal', 13, 17, user.id, user.id, user.id);
  db.prepare(`UPDATE order_items SET status='Authorized' WHERE id=?`).run(o1.itemIds[0]);
  const rep1 = nextNumber('REPORT', 'RPT');
  db.prepare('INSERT INTO reports (report_code, order_id, authorized_by) VALUES (?,?,?)').run(rep1, o1.orderId, user.id);
  db.prepare(`UPDATE orders SET status='Reported' WHERE id=?`).run(o1.orderId);

  // --- Patient 2: critical result, verified + notified but not yet acknowledged ---
  const p2 = db.prepare(`INSERT INTO patients (patient_code,name,gender,dob,age_years,mobile,category,notes) VALUES (?,?,?,?,?,?,?,?)`)
    .run(nextNumber('PATIENT','LAB'), 'Sara Malik', 'Female', '1995-07-20', 31, '03005556666', 'General', '[DEMO DATA]');
  const p2Id = Number(p2.lastInsertRowid);
  const o2 = createOrderWithInvoice({ patient_id: p2Id, doctor_id: doctor ? doctor.id : null, patient_type: 'Emergency', priority: 'STAT', test_ids: [glu.id], userId: user.id });
  db.prepare(`INSERT INTO payments (invoice_id, amount, method, received_by) VALUES (?,?,?,?)`).run(o2.invoiceId, o2.net_amount, 'Cash', user.id);
  db.prepare(`UPDATE invoices SET paid_amount=?, balance=0, status='Paid' WHERE id=?`).run(o2.net_amount, o2.invoiceId);
  const s2 = db.prepare('SELECT id FROM samples WHERE order_item_id=?').get(o2.itemIds[0]);
  db.prepare(`UPDATE samples SET status='Received', collected_by=?, collected_at=datetime('now'), received_at=datetime('now') WHERE id=?`).run(user.id, s2.id);
  db.prepare(`UPDATE order_items SET status='Received' WHERE id=?`).run(o2.itemIds[0]);
  const r2Info = db.prepare(`INSERT INTO results (order_item_id, sample_id, value, flag, ref_low, ref_high, entered_by, status, verified_by, verified_at)
    VALUES (?,?,?,?,?,?,?, 'Verified', ?, datetime('now'))`).run(o2.itemIds[0], s2.id, '560', 'Critical-High', 70, 100, user.id, user.id);
  db.prepare(`UPDATE order_items SET status='Verified' WHERE id=?`).run(o2.itemIds[0]);
  db.prepare(`INSERT INTO critical_results (result_id, order_item_id, patient_id, test_id, value, threshold, direction, status, notified_person, notified_by, notified_at)
    VALUES (?,?,?,?,?,?,?, 'Notified', ?, ?, datetime('now'))`).run(Number(r2Info.lastInsertRowid), o2.itemIds[0], p2Id, glu.id, '560', '500', 'High', doctor ? 'Referring physician' : 'Duty doctor', user.id);

  // --- Patient 3: just ordered, unpaid, sample pending collection ---
  const p3 = db.prepare(`INSERT INTO patients (patient_code,name,gender,dob,age_years,mobile,category,notes) VALUES (?,?,?,?,?,?,?,?)`)
    .run(nextNumber('PATIENT','LAB'), 'Kamran Sheikh', 'Male', '1975-11-02', 50, '03007778888', 'Corporate', '[DEMO DATA]');
  const p3Id = Number(p3.lastInsertRowid);
  createOrderWithInvoice({ patient_id: p3Id, doctor_id: doctor ? doctor.id : null, patient_type: 'OPD', priority: 'Routine', test_ids: plt ? [hb.id, plt.id] : [hb.id], userId: user.id });

  setSetting('mode', 'demo');
  audit(user, 'load_demo_data', 'admin', null, {});
  sendJSON(res, 200, { ok: true, message: 'Demo data loaded: 3 patients covering a completed report, an open critical result, and a fresh unpaid order.' });
});

route('POST', '/api/admin/go-live', async (req, res, params, body) => {
  const user = requireAuth(req, res); if (!user) return;
  if (!hasPerm(user, '*')) return sendJSON(res, 403, { error: 'Admin only' });
  if (body.confirm !== 'GO LIVE') return sendJSON(res, 400, { error: 'Type GO LIVE to confirm this irreversible action' });

  try {
    db.exec('BEGIN');
    db.exec('DELETE FROM result_history');
    db.exec('DELETE FROM critical_results');
    db.exec('DELETE FROM results');
    db.exec('DELETE FROM samples');
    db.exec('DELETE FROM order_items');
    db.exec('DELETE FROM reports');
    db.exec('DELETE FROM payments');
    db.exec('DELETE FROM invoices');
    db.exec('DELETE FROM orders');
    db.exec('DELETE FROM patients');
    db.exec('DELETE FROM inventory_transactions');
    db.exec('DELETE FROM expenses');
    db.exec('UPDATE inventory_items SET stock_qty = 0');
    db.exec('DELETE FROM counters');
    db.exec('DELETE FROM audit_logs');
    db.exec('COMMIT');
  } catch (e) {
    db.exec('ROLLBACK');
    return sendJSON(res, 500, { error: 'Go-live reset failed, no changes were made: ' + e.message });
  }
  setSetting('mode', 'live');
  audit(user, 'go_live', 'admin', null, { note: 'All patient/order/sample/result/billing/inventory-transaction data cleared. Configuration (users, roles, tests, doctors, departments, inventory items) retained.' });
  sendJSON(res, 200, { ok: true, message: 'System reset to a clean live state. All demo/test transactional data has been cleared.' });
});

// ===================== AUDIT LOG =====================
route('GET', '/api/audit', async (req, res) => {
  const user = requireAuth(req, res); if (!user) return;
  if (!hasPerm(user, '*')) return sendJSON(res, 403, { error: 'Admin only' });
  const u=new URL(req.url,'http://x'); const q=String(u.searchParams.get('q')||'').trim(); const action=String(u.searchParams.get('action')||'').trim();
  let sql='SELECT * FROM audit_logs WHERE 1=1',args=[];
  if(q){sql+=' AND (COALESCE(username,\'\') LIKE ? OR COALESCE(module,\'\') LIKE ? OR COALESCE(record_ref,\'\') LIKE ?)'; const like='%'+q+'%';args.push(like,like,like);}
  if(action){sql+=' AND action=?';args.push(action);}
  sql+=' ORDER BY id DESC LIMIT 500';
  sendJSON(res, 200, db.prepare(sql).all(...args));
});


// ===================== DATABASE BACKUP =====================
route('GET', '/api/admin/backup', async (req, res) => {
  const user = requireAuth(req, res); if (!user) return;
  if (!hasPerm(user, '*')) return sendJSON(res, 403, { error: 'Admin only' });
  try {
    db.exec('PRAGMA wal_checkpoint(TRUNCATE);');
    const file = path.join(__dirname, 'data', 'lims.db');
    if (!fs.existsSync(file)) return sendJSON(res, 404, { error: 'Database file not found' });
    const stat = fs.statSync(file);
    res.writeHead(200, {
      'Content-Type': 'application/octet-stream',
      'Content-Length': stat.size,
      'Content-Disposition': `attachment; filename="mini-lims-backup-${new Date().toISOString().slice(0,10)}.db"`
    });
    fs.createReadStream(file).pipe(res);
    audit(user, 'backup', 'system', 'lims.db', {});
  } catch (e) { sendJSON(res, 500, { error: 'Backup failed: ' + e.message }); }
});

// ===================== NETWORK / MULTI-WORKSTATION =====================
route('GET', '/api/network-info', async (req, res) => {
  const user = requireAuth(req, res); if (!user) return;
  if (!hasPerm(user, '*')) return sendJSON(res, 403, { error: 'Admin only' });
  const os = require('os');
  const interfaces = os.networkInterfaces();
  const addresses = [];
  for (const list of Object.values(interfaces)) for (const item of (list || [])) {
    if (item.family === 'IPv4' && !item.internal) addresses.push(item.address);
  }
  sendJSON(res, 200, { host: HOST, port: PORT, addresses, urls: addresses.map(ip => `http://${ip}:${PORT}`) });
});

// ===================== HEALTH =====================
route('GET', '/health', async (req, res) => {
  sendJSON(res, 200, { status: 'ok', time: new Date().toISOString(), db: fs.existsSync(path.join(__dirname, 'data', 'lims.db')) ? 'connected' : 'missing' });
});

// ---------- request dispatcher ----------
const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const pathname = url.pathname;

    if (!pathname.startsWith('/api/') && pathname !== '/health') {
      return serveStatic(req, res, pathname);
    }

    for (const r of routes) {
      if (r.method !== req.method) continue;
      const m = pathname.match(r.regex);
      if (!m) continue;
      const params = {};
      r.keys.forEach((k, i) => { params[k] = decodeURIComponent(m[i + 1]); });
      const body = (req.method === 'POST' || req.method === 'PATCH' || req.method === 'PUT') ? await readBody(req) : {};
      req._body = body;
      await r.handler(req, res, params, body, url.searchParams);
      return;
    }
    sendJSON(res, 404, { error: 'Route not found' });
  } catch (err) {
    console.error(err);
    if (!res.headersSent) sendJSON(res, 500, { error: 'Internal server error', message: err.message });
  }
});

server.listen(PORT, HOST, () => {
  const os = require('os');
  const ips = [];
  for (const list of Object.values(os.networkInterfaces())) for (const item of (list || [])) {
    if (item.family === 'IPv4' && !item.internal) ips.push(item.address);
  }
  console.log(`\n  IQRA GROUP OF LAB LIMS running on port ${PORT}`);
  console.log(`  Local: http://localhost:${PORT}`);
  ips.forEach(ip => console.log(`  LAN:   http://${ip}:${PORT}`));
  console.log(`  Default login -> username: admin  password: admin123\n`);
});
