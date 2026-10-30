const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname, '../src/server.js'), 'utf8');

test('backend usa PostgreSQL y no contiene dependencias SQLite', () => {
  const pkg = require('../package.json');
  assert.ok(pkg.dependencies.pg);
  assert.equal(pkg.dependencies['better-sqlite3'], undefined);
  assert.match(source, /new Pool\(/);
});

test('rutas principales del contrato EGO BAR están presentes', () => {
  for (const route of [
    "'/health'", "'/auth/request-code'", "'/auth/verify-code'",
    "'/auth/activate-controller'", "'/auth/me'", "'/admin/users'",
    "'/admin/controllers'", "'/admin/credentials'",
    "'/private/credentials/:token'", "'/private/credentials/:token/scan'",
    "'/controller/entries'", "'/admin/statistics'", "'/admin/entries'"
  ]) assert.ok(source.includes(route), `Falta la ruta ${route}`);
});

test('protecciones críticas están declaradas', () => {
  assert.match(source, /FOR UPDATE/);
  assert.match(source, /session_version/);
  assert.match(source, /adminOnly/);
  assert.match(source, /attempts >= 5/);
  assert.match(source, /credentials\.status NOT IN \('used','revoked'\)/);
});


test('administradores invitados usan token de un solo uso y contraseña; Resend solo principal', () => {
  assert.match(source, /admin_activation_codes/);
  assert.match(source, /'\/admin\/administrators'/);
  assert.match(source, /'\/auth\/activate-admin'/);
  assert.match(source, /'\/auth\/admin-login'/);
  assert.match(source, /bcrypt\.hash/);
  assert.match(source, /bcrypt\.compare/);
  assert.match(source, /email !== ADMIN_EMAIL/);
  assert.match(source, /Resend está reservado exclusivamente/);
});
