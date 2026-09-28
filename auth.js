// auth.js - password hashing + signed tokens using only Node's built-in crypto
'use strict';
const crypto = require('crypto');

const SECRET = process.env.LIMS_SECRET || (function () {
  // Persist a random secret to disk so tokens survive restarts.
  const fs = require('fs');
  const path = require('path');
  const p = path.join(__dirname, 'data', '.secret');
  try {
    if (fs.existsSync(p)) return fs.readFileSync(p, 'utf8').trim();
    const s = crypto.randomBytes(32).toString('hex');
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, s);
    return s;
  } catch (e) {
    return 'dev-only-fallback-secret-change-me';
  }
})();

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  const [salt, hash] = stored.split(':');
  const check = crypto.scryptSync(password, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(check, 'hex'));
}

function base64url(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function signToken(payload, expiresInSec = 8 * 3600) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const body = { ...payload, iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + expiresInSec };
  const h = base64url(JSON.stringify(header));
  const b = base64url(JSON.stringify(body));
  const sig = base64url(crypto.createHmac('sha256', SECRET).update(`${h}.${b}`).digest());
  return `${h}.${b}.${sig}`;
}

function verifyToken(token) {
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [h, b, sig] = parts;
  const expectedSig = base64url(crypto.createHmac('sha256', SECRET).update(`${h}.${b}`).digest());
  if (sig !== expectedSig) return null;
  try {
    const body = JSON.parse(Buffer.from(b.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'));
    if (body.exp && Date.now() / 1000 > body.exp) return null;
    return body;
  } catch (e) {
    return null;
  }
}

module.exports = { hashPassword, verifyPassword, signToken, verifyToken };
