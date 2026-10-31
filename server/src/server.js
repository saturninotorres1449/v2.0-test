require('dotenv').config();

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { z } = require('zod');

const PORT = Number(process.env.PORT || 8080);
const JWT_SECRET = process.env.JWT_SECRET || '';
const ADMIN_EMAIL = String(process.env.ADMIN_EMAIL || '').trim().toLowerCase();
const DATABASE_URL = process.env.DATABASE_URL || '';

if (JWT_SECRET.length < 32) {
  throw new Error('JWT_SECRET debe tener al menos 32 caracteres.');
}

if (!ADMIN_EMAIL.includes('@')) {
  throw new Error('Configurá ADMIN_EMAIL.');
}

if (!DATABASE_URL) {
  throw new Error('Falta configurar DATABASE_URL de Neon.');
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

const app = express();

app.disable('x-powered-by');

app.use(helmet({
  crossOriginResourcePolicy: { policy: 'cross-origin' }
}));

const allowedOrigins = String(process.env.CORS_ORIGIN || '')
  .split(',').map(v => v.trim()).filter(Boolean);
app.use(cors({
  origin(origin, callback) {
    // Native Android/Hoppscotch Agent requests may omit Origin.
    if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error('Origen no autorizado por CORS.'));
  },
  methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  maxAge: 600
}));

app.use(express.json({ limit: '8mb' }));

const asyncRoute = fn => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

// Inicialización de tablas
async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      email TEXT PRIMARY KEY,
      role TEXT NOT NULL CHECK(role IN ('Administrador','Controlador')),
      active BOOLEAN NOT NULL DEFAULT TRUE,
      verified BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS email_codes (
      email TEXT PRIMARY KEY,
      code_hash TEXT NOT NULL,
      expires_at BIGINT NOT NULL,
      attempts INTEGER NOT NULL DEFAULT 0,
      purpose TEXT NOT NULL DEFAULT 'login'
    );

    ALTER TABLE users ADD COLUMN IF NOT EXISTS first_name TEXT NOT NULL DEFAULT '';
    ALTER TABLE users ADD COLUMN IF NOT EXISTS last_name TEXT NOT NULL DEFAULT '';
    ALTER TABLE users ADD COLUMN IF NOT EXISTS session_version INTEGER NOT NULL DEFAULT 1;

    CREATE TABLE IF NOT EXISTS admin_activation_codes (
      id BIGSERIAL PRIMARY KEY,
      email TEXT NOT NULL REFERENCES users(email) ON DELETE CASCADE,
      code_hash TEXT NOT NULL UNIQUE,
      expires_at TIMESTAMPTZ NOT NULL,
      used_at TIMESTAMPTZ,
      revoked_at TIMESTAMPTZ,
      created_by TEXT NOT NULL,
      attempts INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_admin_activation_email ON admin_activation_codes(email);
    ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash TEXT;

    CREATE TABLE IF NOT EXISTS controller_activation_codes (
      id BIGSERIAL PRIMARY KEY,
      email TEXT NOT NULL REFERENCES users(email) ON DELETE CASCADE,
      code_hash TEXT NOT NULL UNIQUE,
      expires_at TIMESTAMPTZ NOT NULL,
      used_at TIMESTAMPTZ,
      revoked_at TIMESTAMPTZ,
      created_by TEXT NOT NULL,
      attempts INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    ALTER TABLE controller_activation_codes ADD COLUMN IF NOT EXISTS attempts INTEGER NOT NULL DEFAULT 0;
    CREATE INDEX IF NOT EXISTS idx_controller_codes_email
      ON controller_activation_codes(email);

    CREATE TABLE IF NOT EXISTS credentials (
      token TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      dni TEXT,
      email TEXT,
      event TEXT NOT NULL,
      date TEXT,
      type TEXT,
      status TEXT NOT NULL DEFAULT 'active'
        CHECK(status IN ('active','used','expired','revoked')),
      photo_data TEXT,
      benefits JSONB NOT NULL DEFAULT '[]'::jsonb,
      is_invite BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS entries (
      id BIGSERIAL PRIMARY KEY,
      token TEXT NOT NULL,
      actor_email TEXT NOT NULL,
      result TEXT NOT NULL,
      scanned_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_entries_token
      ON entries(token);

    CREATE INDEX IF NOT EXISTS idx_entries_scanned_at
      ON entries(scanned_at);

    CREATE INDEX IF NOT EXISTS idx_credentials_status
      ON credentials(status);
  `);

  await pool.query(`
    INSERT INTO users(email, role, active, verified)
    VALUES($1, 'Administrador', TRUE, TRUE)
    ON CONFLICT(email) DO NOTHING
  `, [ADMIN_EMAIL]);

  console.log('Base de datos EGO BAR inicializada.');
}

// Envío de correo mediante Resend API
const mailReady = () => Boolean(
  process.env.RESEND_API_KEY &&
  process.env.RESEND_FROM
);

async function sendEmail(to, subject, text) {
  if (!mailReady()) {
    throw new Error('Resend no está configurado.');
  }

  const response = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${process.env.RESEND_API_KEY}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      from: process.env.RESEND_FROM,
      to: [to],
      subject,
      text
    })
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    console.error('Resend API error:', {
      status: response.status,
      message: data.message || data.error || 'Error de envío'
    });

    throw new Error('Resend no pudo enviar el correo.');
  }

  return data;
}

const hashCode = (email, code) =>
  crypto.createHash('sha256')
    .update(`${email}:${code}:${JWT_SECRET}`)
    .digest('hex');

const emailSchema = z.string()
  .email()
  .max(254)
  .transform(v => v.toLowerCase().trim());

// Autenticación: errores JWT separados de fallos de PostgreSQL.
const auth = asyncRoute(async (req, res, next) => {
  const raw = String(req.headers.authorization || '');
  if (!raw.startsWith('Bearer ')) return res.status(401).json({ error: 'Iniciá sesión.' });
  let payload;
  try {
    payload = jwt.verify(raw.slice(7), JWT_SECRET, { issuer: 'ego-bar-api' });
  } catch (_error) {
    return res.status(401).json({ error: 'Sesión vencida o inválida.' });
  }
  if (!payload.email || !payload.role) return res.status(401).json({ error: 'Sesión inválida.' });
  const result = await pool.query(
    `SELECT email, role, active, verified, first_name, last_name, session_version
     FROM users WHERE email = $1`, [payload.email]
  );
  const user = result.rows[0];
  if (!user || !user.active || !user.verified || user.role !== payload.role ||
      Number(user.session_version) !== Number(payload.sessionVersion || 1)) {
    return res.status(403).json({ error: 'Usuario deshabilitado, no verificado o sesión revocada.' });
  }
  req.user = user;
  next();
});

// Límite sencillo por IP+identificador. Para varias instancias, complementar con Redis.
const rateBuckets = new Map();
function rateLimit({ windowMs, max, key }) {
  return (req, res, next) => {
    const id = `${req.ip}:${key(req)}`;
    const now = Date.now();
    let bucket = rateBuckets.get(id);
    if (!bucket || bucket.until <= now) bucket = { count: 0, until: now + windowMs };
    bucket.count += 1;
    rateBuckets.set(id, bucket);
    if (bucket.count > max) return res.status(429).json({ error: 'Demasiados intentos. Esperá unos minutos.' });
    if (rateBuckets.size > 5000) {
      for (const [k, v] of rateBuckets) if (v.until <= now) rateBuckets.delete(k);
    }
    next();
  };
}
const authRequestLimit = rateLimit({ windowMs: 15 * 60 * 1000, max: 5, key: req => String(req.body?.email || '').toLowerCase() });
const authVerifyLimit = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, key: req => String(req.body?.email || '').toLowerCase() });
const controllerActivateLimit = rateLimit({ windowMs: 15 * 60 * 1000, max: 8, key: req => String(req.body?.email || '').toLowerCase() });

const adminOnly = (req, res, next) =>
  req.user?.role === 'Administrador'
    ? next()
    : res.status(403).json({
        error: 'Se requiere rol Administrador.'
      });

// Estado del servicio
app.get('/health', asyncRoute(async (_req, res) => {
  await pool.query('SELECT 1');

  res.json({
    ok: true,
    service: 'ego-bar-api',
    database: 'connected',
    time: new Date().toISOString()
  });
}));

// Solicitar código de acceso
app.post('/auth/request-code', authRequestLimit, asyncRoute(async (req, res) => {
  const parsed = emailSchema.safeParse(req.body?.email);

  if (!parsed.success) {
    return res.status(400).json({
      error: 'Correo electrónico inválido.'
    });
  }

  const email = parsed.data;

  if (email !== ADMIN_EMAIL) {
    return res.status(403).json({ error: 'Resend está reservado exclusivamente para el Administrador principal. Los demás Administradores ingresan con correo y contraseña.' });
  }

  const result = await pool.query(
    'SELECT email, active FROM users WHERE email = $1',
    [email]
  );

  let user = result.rows[0];

  if (!user && email === ADMIN_EMAIL) {
    await pool.query(`
      INSERT INTO users(email, role, active, verified)
      VALUES($1, 'Administrador', TRUE, TRUE)
      ON CONFLICT(email) DO NOTHING
    `, [email]);

    const updated = await pool.query(
      'SELECT email, active FROM users WHERE email = $1',
      [email]
    );

    user = updated.rows[0];
  }

  if (!user || !user.active) {
    return res.status(403).json({
      error: 'El correo no está autorizado. Pedile al administrador que lo agregue.'
    });
  }

  if (!mailReady()) {
    return res.status(503).json({
      error: 'El servicio de correo no está configurado.'
    });
  }

  const code = String(
    crypto.randomInt(0, 1000000)
  ).padStart(6, '0');

  const expires = Date.now() + 10 * 60 * 1000;

  await pool.query(`
    INSERT INTO email_codes(email, code_hash, expires_at, attempts, purpose)
    VALUES($1, $2, $3, 0, 'login')
    ON CONFLICT(email) DO UPDATE SET
      code_hash = EXCLUDED.code_hash,
      expires_at = EXCLUDED.expires_at,
      attempts = 0,
      purpose = 'login'
  `, [email, hashCode(email, code), expires]);

  try {
    await sendEmail(
      email,
      'Código de acceso · EGO BAR',
      `Tu código de acceso es ${code}. Vence en 10 minutos. Si no lo solicitaste, ignorá este correo.`
    );

    res.json({
      ok: true,
      message: 'Te enviamos un código de verificación. Revisá también Spam.'
    });
  } catch (e) {
    console.error('Email send failed:', e.message);

    res.status(502).json({
      error: 'No se pudo enviar el correo mediante Resend.'
    });
  }
}));

// Verificar código e iniciar sesión
app.post('/auth/verify-code', authVerifyLimit, asyncRoute(async (req, res) => {
  const parsed = emailSchema.safeParse(req.body?.email);
  const code = String(req.body?.code || '').trim();

  if (!parsed.success || !/^\d{6}$/.test(code)) {
    return res.status(400).json({
      error: 'Ingresá el correo y el código de seis dígitos.'
    });
  }

  const email = parsed.data;

  const client = await pool.connect();
  let user;
  try {
    await client.query('BEGIN');
    const recordResult = await client.query(
      'SELECT * FROM email_codes WHERE email = $1 FOR UPDATE', [email]
    );
    const record = recordResult.rows[0];
    const valid = record && record.purpose === 'login' &&
      Number(record.expires_at) >= Date.now() && record.attempts < 5 &&
      record.code_hash === hashCode(email, code);
    if (!valid) {
      if (record) {
        const attempts = Number(record.attempts) + 1;
        await client.query(
          `UPDATE email_codes SET attempts = $2 WHERE email = $1`, [email, attempts]
        );
        if (attempts >= 5) await client.query('DELETE FROM email_codes WHERE email = $1', [email]);
      }
      await client.query('COMMIT');
      return res.status(401).json({ error: 'Código incorrecto o vencido.' });
    }
    const userResult = await client.query(
      `UPDATE users SET verified = TRUE
       WHERE email = $1 AND active = TRUE AND role = 'Administrador'
       RETURNING email, role, session_version`, [email]
    );
    user = userResult.rows[0];
    if (!user) {
      await client.query('ROLLBACK');
      return res.status(403).json({ error: 'Usuario deshabilitado o no autorizado para este acceso.' });
    }
    await client.query('DELETE FROM email_codes WHERE email = $1', [email]);
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally { client.release(); }

  const token = jwt.sign(
    { email: user.email, role: user.role, sessionVersion: Number(user.session_version) },
    JWT_SECRET, { expiresIn: '8h', issuer: 'ego-bar-api' }
  );

  res.json({
    token,
    user: {
      email: user.email,
      role: user.role
    },
    expiresIn: 28800
  });
}));

app.get('/auth/me', auth, (req, res) => {
  res.json({
    email: req.user.email,
    role: req.user.role,
    active: req.user.active,
    verified: req.user.verified
  });
});

// Administración de usuarios
app.get('/admin/users', auth, adminOnly,
  asyncRoute(async (_req, res) => {
    const result = await pool.query(`
      SELECT email, role, active, verified,
      first_name AS "firstName", last_name AS "lastName",
      created_at AS "createdAt"
      FROM users ORDER BY created_at
    `);

    res.json({ users: result.rows });
  })
);

app.post('/admin/users', auth, adminOnly,
  asyncRoute(async (req, res) => {
    const parsed = emailSchema.safeParse(req.body?.email);
    const role = String(req.body?.role || '');

    if (
      !parsed.success ||
      !['Administrador', 'Controlador'].includes(role)
    ) {
      return res.status(400).json({
        error: 'Correo o rol inválido.'
      });
    }

    const email = parsed.data;
    if (role === 'Administrador' && email !== ADMIN_EMAIL) {
      return res.status(400).json({ error: 'Los nuevos Administradores deben crearse mediante /admin/administrators para generar su token de activación.' });
    }
    if (email === ADMIN_EMAIL && role !== 'Administrador') {
      return res.status(400).json({ error: 'No se puede cambiar el rol del administrador principal.' });
    }
    const firstName = String(req.body?.firstName || '').trim().slice(0, 100);
    const lastName = String(req.body?.lastName || '').trim().slice(0, 100);

    await pool.query(`
      INSERT INTO users(email, role, active, verified, first_name, last_name)
      VALUES($1, $2, TRUE, FALSE, $3, $4)
      ON CONFLICT(email) DO UPDATE SET
        verified = CASE WHEN users.role <> EXCLUDED.role THEN FALSE ELSE users.verified END,
        session_version = CASE WHEN users.role <> EXCLUDED.role OR users.active = FALSE THEN users.session_version + 1 ELSE users.session_version END,
        role = EXCLUDED.role,
        active = TRUE,
        first_name = CASE WHEN EXCLUDED.first_name <> '' THEN EXCLUDED.first_name ELSE users.first_name END,
        last_name = CASE WHEN EXCLUDED.last_name <> '' THEN EXCLUDED.last_name ELSE users.last_name END
    `, [email, role, firstName, lastName]);

    res.status(201).json({
      ok: true,
      message: 'Usuario autorizado. Debe verificar el correo para iniciar sesión.',
      email,
      role
    });
  })
);

app.patch('/admin/users/:email/role', auth, adminOnly,
  asyncRoute(async (req, res) => {
    const parsedEmail = emailSchema.safeParse(decodeURIComponent(req.params.email));
    const role = String(req.body?.role || '');
    if (!parsedEmail.success || !['Administrador', 'Controlador'].includes(role))
      return res.status(400).json({ error: 'Correo o rol inválido.' });
    if (parsedEmail.data === ADMIN_EMAIL && role !== 'Administrador')
      return res.status(400).json({ error: 'No se puede cambiar el rol del administrador principal.' });
    const result = await pool.query(`UPDATE users SET role = $1, verified = FALSE,
      password_hash = CASE WHEN $1 = 'Administrador' THEN password_hash ELSE NULL END,
      session_version = session_version + 1 WHERE email = $2 RETURNING email, role, active, verified`,
      [role, parsedEmail.data]);
    if (!result.rowCount) return res.status(404).json({ error: 'Usuario no encontrado.' });
    res.json({ ok: true, user: result.rows[0] });
  })
);

app.post('/admin/users/:email/active', auth, adminOnly,
  asyncRoute(async (req, res) => {
    const email = decodeURIComponent(req.params.email)
      .toLowerCase();

    if (
      email === ADMIN_EMAIL &&
      req.body?.active === false
    ) {
      return res.status(400).json({
        error: 'No se puede desactivar el administrador principal.'
      });
    }

    const result = await pool.query(
      'UPDATE users SET active = $1, session_version = session_version + 1 WHERE email = $2',
      [req.body?.active === true, email]
    );

    if (!result.rowCount) {
      return res.status(404).json({
        error: 'Usuario no encontrado.'
      });
    }

    res.json({
      ok: true,
      email,
      active: req.body.active === true
    });
  })
);


// Invitaciones de Administradores: token de un solo uso compartible por WhatsApp.
const hashAdminActivationCode = (email, code) => crypto.createHash('sha256')
  .update(`${email}:${String(code).trim().toUpperCase()}:${JWT_SECRET}`).digest('hex');
const passwordSchema = z.string().min(10).max(128);

async function issueAdminCode(email, createdBy, db = pool) {
  const code = crypto.randomBytes(16).toString('hex').toUpperCase(); // 128 bits
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
  await db.query(`UPDATE admin_activation_codes SET revoked_at = NOW()
    WHERE email = $1 AND used_at IS NULL AND revoked_at IS NULL`, [email]);
  await db.query(`INSERT INTO admin_activation_codes
    (email, code_hash, expires_at, created_by, attempts)
    VALUES($1, $2, $3, $4, 0)`, [email, hashAdminActivationCode(email, code), expiresAt, createdBy]);
  return { code, expiresAt: expiresAt.toISOString() };
}

app.get('/admin/administrators', auth, adminOnly, asyncRoute(async (_req, res) => {
  const result = await pool.query(`SELECT email, first_name AS "firstName",
    last_name AS "lastName", active, verified, created_at AS "createdAt"
    FROM users WHERE role = 'Administrador' ORDER BY created_at`);
  res.json({ administrators: result.rows });
}));

app.post('/admin/administrators', auth, adminOnly, asyncRoute(async (req, res) => {
  const email = emailSchema.safeParse(req.body?.email);
  const first = nameSchema.safeParse(req.body?.firstName);
  const last = nameSchema.safeParse(req.body?.lastName);
  if (!email.success || !first.success || !last.success)
    return res.status(400).json({ error: 'Ingresá nombre, apellido y correo válidos.' });
  if (email.data === ADMIN_EMAIL)
    return res.status(400).json({ error: 'El administrador principal ya está configurado.' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const existing = await client.query('SELECT role FROM users WHERE email = $1 FOR UPDATE', [email.data]);
    if (existing.rows[0]?.role === 'Controlador') {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'Ese correo ya pertenece a un Controlador. Cambiá su rol desde la administración antes de invitarlo como Administrador.' });
    }
    await client.query(`INSERT INTO users(email, role, active, verified, first_name, last_name, password_hash)
      VALUES($1, 'Administrador', TRUE, FALSE, $2, $3, NULL)
      ON CONFLICT(email) DO UPDATE SET role = 'Administrador', active = TRUE,
        verified = FALSE, password_hash = NULL, session_version = users.session_version + 1,
        first_name = EXCLUDED.first_name, last_name = EXCLUDED.last_name`,
      [email.data, first.data, last.data]);
    const activation = await issueAdminCode(email.data, req.user.email, client);
    await client.query('COMMIT');
    res.status(201).json({ ok: true, administrator: { email: email.data,
      firstName: first.data, lastName: last.data }, activationToken: activation.code,
      expiresAt: activation.expiresAt, activationExpiresIn: 86400,
      shareText: `Invitación EGO BAR\\nCorreo: ${email.data}\\nToken: ${activation.code}\\nVence: ${activation.expiresAt}\\nActivá tu cuenta desde la aplicación.` });
  } catch (error) { await client.query('ROLLBACK'); throw error; }
  finally { client.release(); }
}));

app.post('/admin/administrators/:email/token', auth, adminOnly, asyncRoute(async (req, res) => {
  const email = emailSchema.safeParse(decodeURIComponent(req.params.email));
  if (!email.success) return res.status(400).json({ error: 'Correo inválido.' });
  if (email.data === ADMIN_EMAIL) return res.status(400).json({ error: 'No se genera token para el administrador principal.' });
  const found = await pool.query(`SELECT email FROM users WHERE email = $1 AND role = 'Administrador' AND active = TRUE`, [email.data]);
  if (!found.rowCount) return res.status(404).json({ error: 'Administrador activo no encontrado.' });
  const activation = await issueAdminCode(email.data, req.user.email);
  res.json({ ok: true, activationToken: activation.code, expiresAt: activation.expiresAt, activationExpiresIn: 86400 });
}));

app.post('/auth/activate-admin', controllerActivateLimit, asyncRoute(async (req, res) => {
  const email = emailSchema.safeParse(req.body?.email);
  const code = String(req.body?.token || '').trim().toUpperCase();
  const password = passwordSchema.safeParse(req.body?.password);
  if (!email.success || !/^[A-F0-9]{32}$/.test(code) || !password.success)
    return res.status(400).json({ error: 'Ingresá correo, token válido y contraseña de al menos 10 caracteres.' });
  if (email.data === ADMIN_EMAIL) return res.status(403).json({ error: 'El administrador principal utiliza el acceso mediante Resend.' });
  const client = await pool.connect();
  let user;
  try {
    await client.query('BEGIN');
    const codeResult = await client.query(`SELECT id, code_hash, attempts FROM admin_activation_codes
      WHERE email = $1 AND used_at IS NULL AND revoked_at IS NULL AND expires_at > NOW()
      ORDER BY created_at DESC LIMIT 1 FOR UPDATE`, [email.data]);
    const activation = codeResult.rows[0];
    if (!activation || Number(activation.attempts) >= 5 ||
        activation.code_hash !== hashAdminActivationCode(email.data, code)) {
      if (activation) {
        const attempts = Number(activation.attempts) + 1;
        await client.query(`UPDATE admin_activation_codes SET attempts = $2,
          revoked_at = CASE WHEN $2 >= 5 THEN NOW() ELSE revoked_at END WHERE id = $1`, [activation.id, attempts]);
      }
      await client.query('COMMIT');
      return res.status(401).json({ error: 'Token incorrecto, vencido o revocado.' });
    }
    const passwordHash = await bcrypt.hash(password.data, 12);
    const updated = await client.query(`UPDATE users SET password_hash = $2, verified = TRUE,
      active = TRUE, session_version = session_version + 1
      WHERE email = $1 AND role = 'Administrador' AND active = TRUE
      RETURNING email, role, first_name, last_name, session_version`, [email.data, passwordHash]);
    user = updated.rows[0];
    if (!user) { await client.query('ROLLBACK'); return res.status(403).json({ error: 'Administrador no autorizado o deshabilitado.' }); }
    await client.query('UPDATE admin_activation_codes SET used_at = NOW() WHERE id = $1', [activation.id]);
    await client.query('COMMIT');
  } catch (error) { await client.query('ROLLBACK'); throw error; }
  finally { client.release(); }
  const token = jwt.sign({ email: user.email, role: user.role,
    sessionVersion: Number(user.session_version), sessionType: 'admin-password' },
    JWT_SECRET, { expiresIn: '12h', issuer: 'ego-bar-api' });
  res.json({ token, user: { email: user.email, role: user.role,
    firstName: user.first_name, lastName: user.last_name }, expiresIn: 43200 });
}));

app.post('/auth/admin-login', authVerifyLimit, asyncRoute(async (req, res) => {
  const email = emailSchema.safeParse(req.body?.email);
  const password = String(req.body?.password || '');
  if (!email.success || !password || password.length > 128)
    return res.status(400).json({ error: 'Correo o contraseña inválidos.' });
  if (email.data === ADMIN_EMAIL)
    return res.status(403).json({ error: 'El administrador principal debe ingresar mediante Resend.' });
  const result = await pool.query(`SELECT email, role, active, verified, password_hash,
    first_name, last_name, session_version FROM users WHERE email = $1`, [email.data]);
  const user = result.rows[0];
  if (!user || user.role !== 'Administrador' || !user.active || !user.verified ||
      !user.password_hash || !(await bcrypt.compare(password, user.password_hash)))
    return res.status(401).json({ error: 'Correo o contraseña incorrectos.' });
  const token = jwt.sign({ email: user.email, role: user.role,
    sessionVersion: Number(user.session_version), sessionType: 'admin-password' },
    JWT_SECRET, { expiresIn: '12h', issuer: 'ego-bar-api' });
  res.json({ token, user: { email: user.email, role: user.role,
    firstName: user.first_name, lastName: user.last_name }, expiresIn: 43200 });
}));

// Gestión de Controladores y Administradores v2.0
const nameSchema = z.string().trim().min(1).max(100);
const hashActivationCode = (email, code) => crypto.createHash('sha256')
  .update(`${email}:${String(code).trim().toUpperCase()}:${JWT_SECRET}`).digest('hex');

async function issueControllerCode(email, createdBy, db = pool) {
  const code = crypto.randomBytes(4).toString('hex').toUpperCase(); // 32 bits + vencimiento, uso único y límites anti-fuerza-bruta
  const expiresAt = new Date(Date.now() + 30 * 60 * 1000);
  await db.query(`UPDATE controller_activation_codes SET revoked_at = NOW()
    WHERE email = $1 AND used_at IS NULL AND revoked_at IS NULL`, [email]);
  await db.query(`INSERT INTO controller_activation_codes
    (email, code_hash, expires_at, created_by, attempts)
    VALUES($1, $2, $3, $4, 0)`, [email, hashActivationCode(email, code), expiresAt, createdBy]);
  return { code, expiresAt: expiresAt.toISOString() };
}

app.get('/admin/controllers', auth, adminOnly, asyncRoute(async (_req, res) => {
  const result = await pool.query(`
    SELECT email, first_name AS "firstName", last_name AS "lastName",
           active, created_at AS "createdAt"
    FROM users WHERE role = 'Controlador'
    ORDER BY last_name, first_name, email
  `);
  res.json({ controllers: result.rows });
}));

app.post('/admin/controllers', auth, adminOnly, asyncRoute(async (req, res) => {
  const first = nameSchema.safeParse(req.body?.firstName);
  const last = nameSchema.safeParse(req.body?.lastName);
  const email = emailSchema.safeParse(req.body?.email);
  if (!first.success || !last.success || !email.success) {
    return res.status(400).json({ error: 'Ingresá nombre, apellido y correo válidos.' });
  }
  if (email.data === ADMIN_EMAIL) return res.status(400).json({ error: 'El administrador principal no puede convertirse en Controlador.' });
  const existing = await pool.query('SELECT role FROM users WHERE email = $1', [email.data]);
  if (existing.rows[0]?.role === 'Administrador') return res.status(409).json({ error: 'Ese correo ya pertenece a un Administrador.' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`
      INSERT INTO users(email, role, active, verified, first_name, last_name)
      VALUES($1, 'Controlador', TRUE, FALSE, $2, $3)
      ON CONFLICT(email) DO UPDATE SET
        role = 'Controlador', active = TRUE,
        first_name = EXCLUDED.first_name, last_name = EXCLUDED.last_name
    `, [email.data, first.data, last.data]);
    const activation = await issueControllerCode(email.data, req.user.email, client);
    await client.query('COMMIT');
    res.status(201).json({
      ok: true, controller: { email: email.data, firstName: first.data, lastName: last.data },
      activationCode: activation.code, expiresAt: activation.expiresAt,
      activationExpiresIn: 1800
    });
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally { client.release(); }
}));

app.post('/admin/controllers/:email/code', auth, adminOnly,
  asyncRoute(async (req, res) => {
    const email = emailSchema.safeParse(decodeURIComponent(req.params.email));
    if (!email.success) return res.status(400).json({ error: 'Correo inválido.' });
    const found = await pool.query(
      `SELECT email FROM users WHERE email = $1 AND role = 'Controlador'`,
      [email.data]
    );
    if (!found.rowCount) return res.status(404).json({ error: 'Controlador no encontrado.' });
    const activation = await issueControllerCode(email.data, req.user.email);
    res.json({ ok: true, activationCode: activation.code,
      expiresAt: activation.expiresAt, activationExpiresIn: 1800 });
  })
);

// Activación por código de un solo uso. La sesión del Controlador dura 12 horas.
app.post('/auth/activate-controller', controllerActivateLimit, asyncRoute(async (req, res) => {
  const email = emailSchema.safeParse(req.body?.email);
  const code = String(req.body?.code || '').trim().toUpperCase();
  if (!email.success || !/^[A-F0-9]{8}$/.test(code)) {
    return res.status(400).json({ error: 'Ingresá correo y código de activación válidos.' });
  }
  const client = await pool.connect();
  let user;
  try {
    await client.query('BEGIN');
    const codeResult = await client.query(`
      SELECT id, code_hash, attempts FROM controller_activation_codes
      WHERE email = $1 AND used_at IS NULL AND revoked_at IS NULL AND expires_at > NOW()
      ORDER BY created_at DESC LIMIT 1 FOR UPDATE
    `, [email.data]);
    const activation = codeResult.rows[0];
    if (!activation || Number(activation.attempts) >= 5 ||
        activation.code_hash !== hashActivationCode(email.data, code)) {
      if (activation) {
        const attempts = Number(activation.attempts) + 1;
        await client.query('UPDATE controller_activation_codes SET attempts = $2, revoked_at = CASE WHEN $2 >= 5 THEN NOW() ELSE revoked_at END WHERE id = $1', [activation.id, attempts]);
      }
      await client.query('COMMIT');
      return res.status(401).json({ error: 'Código incorrecto, vencido o revocado.' });
    }
    const userResult = await client.query(`
      SELECT email, role, active, first_name, last_name, session_version
      FROM users WHERE email = $1 FOR UPDATE`, [email.data]);
    user = userResult.rows[0];
    if (!user || user.role !== 'Controlador' || !user.active) {
      await client.query('ROLLBACK');
      return res.status(403).json({ error: 'Controlador deshabilitado o no autorizado.' });
    }
    await client.query('UPDATE controller_activation_codes SET used_at = NOW() WHERE id = $1', [activation.id]);
    await client.query('UPDATE users SET verified = TRUE WHERE email = $1', [email.data]);
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally { client.release(); }
  const token = jwt.sign(
    { email: user.email, role: user.role, sessionVersion: Number(user.session_version), sessionType: 'controller' },
    JWT_SECRET, { expiresIn: '12h', issuer: 'ego-bar-api' }
  );
  res.json({ token, user: { email: user.email, role: user.role,
    firstName: user.first_name, lastName: user.last_name }, expiresIn: 43200 });
}));

// Crear credenciales
const credentialSchema = z.object({
  token: z.string().min(1).max(128),
  name: z.string().min(1).max(200),
  dni: z.string().max(32).optional().default(''),
  email: z.string().max(254).optional().default(''),
  event: z.string().min(1).max(200),
  date: z.string().max(80).optional().default(''),
  type: z.string().max(120).optional().default('Access Card'),
  status: z.enum([
    'active', 'used', 'expired', 'revoked'
  ]).optional().default('active'),
  photoData: z.string().max(6000000).optional().default(''),
  benefits: z.array(z.string().max(160))
    .optional().default([]),
  isInvite: z.boolean().optional().default(false)
});

app.get('/admin/credentials', auth, adminOnly,
  asyncRoute(async (req, res) => {
    const limit = Math.min(Math.max(Number(req.query.limit) || 100, 1), 500);
    const offset = Math.max(Number(req.query.offset) || 0, 0);
    const status = req.query.status ? String(req.query.status) : null;
    if (status && !['active','used','expired','revoked'].includes(status))
      return res.status(400).json({ error: 'Estado de credencial inválido.' });
    const result = await pool.query(`
      SELECT token, name, dni, email, event, date, type, status,
        photo_data AS "photoData", benefits, is_invite AS "isInvite",
        created_at AS "createdAt", updated_at AS "updatedAt"
      FROM credentials
      WHERE ($1::text IS NULL OR status = $1)
      ORDER BY created_at DESC LIMIT $2 OFFSET $3
    `, [status, limit, offset]);
    res.json({ credentials: result.rows, limit, offset });
  })
);

app.post('/admin/credentials', auth, adminOnly,
  asyncRoute(async (req, res) => {
    const parsed = credentialSchema.safeParse(req.body);

    if (!parsed.success) {
      return res.status(400).json({
        error: 'Datos de credencial inválidos.'
      });
    }

    const c = parsed.data;

    await pool.query(`
      INSERT INTO credentials(
        token, name, dni, email, event, date,
        type, status, photo_data, benefits,
        is_invite, updated_at
      )
      VALUES(
        $1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11,NOW()
      )
      ON CONFLICT(token) DO UPDATE SET
        name = EXCLUDED.name,
        dni = EXCLUDED.dni,
        email = EXCLUDED.email,
        event = EXCLUDED.event,
        date = EXCLUDED.date,
        type = EXCLUDED.type,
        status = CASE WHEN credentials.status IN ('used','revoked') THEN credentials.status ELSE EXCLUDED.status END,
        photo_data = EXCLUDED.photo_data,
        benefits = EXCLUDED.benefits,
        is_invite = EXCLUDED.is_invite,
        updated_at = NOW()
      WHERE credentials.status NOT IN ('used','revoked')
    `, [
      c.token, c.name, c.dni, c.email, c.event,
      c.date, c.type, c.status, c.photoData,
      JSON.stringify(c.benefits), c.isInvite
    ]);

    const saved = await pool.query('SELECT status FROM credentials WHERE token = $1', [c.token]);
    if (!saved.rowCount) return res.status(409).json({ error: 'La credencial ya fue utilizada o revocada y no puede reactivarse.' });
    res.json({ ok: true, token: c.token, status: saved.rows[0].status });
  })
);

// Consulta pública: nunca devuelve DNI ni fotografía
app.get('/public/credentials/:token',
  asyncRoute(async (req, res) => {
    const result = await pool.query(`
      SELECT token, name, event, date, type,
      status, is_invite
      FROM credentials WHERE token = $1
    `, [req.params.token]);

    const c = result.rows[0];

    if (!c) {
      return res.status(404).json({
        error: 'Credencial inexistente.'
      });
    }

    res.json({
      token: c.token,
      name: c.name,
      event: c.event,
      date: c.date,
      type: c.type,
      status: c.status === 'active' ? 'active' : 'invalid',
      isInvite: c.is_invite
    });
  })
);

// Consulta privada de credencial
app.get('/private/credentials/:token', auth,
  asyncRoute(async (req, res) => {
    if (
      !['Administrador', 'Controlador'].includes(req.user.role)
    ) {
      return res.status(403).json({
        error: 'Sin permisos.'
      });
    }

    const result = await pool.query(
      'SELECT * FROM credentials WHERE token = $1',
      [req.params.token]
    );

    const c = result.rows[0];

    if (!c) {
      return res.status(404).json({
        error: 'Credencial inexistente.'
      });
    }

    const base = {
      token: c.token, name: c.name, event: c.event, date: c.date,
      type: c.type, status: c.status, benefits: c.benefits,
      isInvite: c.is_invite
    };
    if (req.user.role === 'Administrador') {
      return res.json({ ...base, dni: c.dni, email: c.email,
        photoData: c.photo_data, createdAt: c.created_at });
    }
    // El Controlador recibe solo lo necesario para verificar el acceso.
    res.json({ ...base, photoData: c.photo_data });
  })
);

// Escaneo QR: operación transaccional para impedir doble ingreso
app.post('/private/credentials/:token/scan', auth,
  asyncRoute(async (req, res) => {
    if (
      !['Administrador', 'Controlador'].includes(req.user.role)
    ) {
      return res.status(403).json({
        error: 'Sin permisos.'
      });
    }

    const client = await pool.connect();

    try {
      await client.query('BEGIN');

      const result = await client.query(
        `SELECT token, name, status
         FROM credentials
         WHERE token = $1
         FOR UPDATE`,
        [req.params.token]
      );

      const c = result.rows[0];

      const scanResult = !c
        ? 'not_found'
        : c.status === 'active'
          ? 'authorized'
          : 'denied';

      if (scanResult === 'authorized') {
        await client.query(`
          UPDATE credentials
          SET status = 'used', updated_at = NOW()
          WHERE token = $1
        `, [req.params.token]);
      }

      await client.query(`
        INSERT INTO entries(token, actor_email, result)
        VALUES($1, $2, $3)
      `, [
        req.params.token,
        req.user.email,
        scanResult
      ]);

      await client.query('COMMIT');

      res.json({
        result: scanResult,
        credential: c ? {
          token: c.token,
          name: c.name,
          status: scanResult === 'authorized'
            ? 'used'
            : c.status
        } : null,
        scannedBy: req.user.email
      });

    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  })
);

// Historial limitado al propio Controlador.
app.get('/controller/entries', auth, asyncRoute(async (req, res) => {
  if (req.user.role !== 'Controlador') return res.status(403).json({ error: 'Ruta exclusiva para Controladores.' });
  const limit = Math.min(Math.max(Number(req.query.limit) || 50, 1), 100);
  const result = await pool.query(`SELECT id, token, result, scanned_at AS "scannedAt"
    FROM entries WHERE actor_email = $1 ORDER BY scanned_at DESC LIMIT $2`, [req.user.email, limit]);
  res.json({ entries: result.rows });
}));

// Estadísticas administrativas
app.get('/admin/statistics', auth, adminOnly,
  asyncRoute(async (_req, res) => {
    const credentials = await pool.query(`
      SELECT
        COUNT(*) FILTER (WHERE is_invite = FALSE)::int AS sold,
        COUNT(*) FILTER (WHERE is_invite = TRUE)::int AS invitations,
        COUNT(*) FILTER (WHERE status = 'active')::int AS available,
        COUNT(*) FILTER (WHERE status = 'used')::int AS used,
        COUNT(*) FILTER (WHERE status = 'revoked')::int AS revoked,
        COUNT(*) FILTER (WHERE status = 'expired')::int AS expired
      FROM credentials
    `);

    const entries = await pool.query(`
      SELECT
        COUNT(*) FILTER (WHERE result = 'authorized')::int AS authorized,
        COUNT(*) FILTER (WHERE result = 'denied')::int AS denied,
        COUNT(*) FILTER (WHERE result = 'not_found')::int AS not_found
      FROM entries
    `);

    res.json({
      credentials: credentials.rows[0],
      entries: entries.rows[0]
    });
  })
);

// Historial administrativo de escaneos
app.get('/admin/entries', auth, adminOnly,
  asyncRoute(async (req, res) => {
    const limit = Math.min(
      Math.max(Number(req.query.limit) || 50, 1),
      200
    );

    const result = await pool.query(`
      SELECT
        id, token, actor_email AS "actorEmail",
        result, scanned_at AS "scannedAt"
      FROM entries
      ORDER BY scanned_at DESC
      LIMIT $1
    `, [limit]);

    res.json({ entries: result.rows });
  })
);

// Errores
app.use((err, _req, res, _next) => {
  console.error('API error:', err.message);
  if (err.message === 'Origen no autorizado por CORS.') return res.status(403).json({ error: 'Origen no autorizado.' });
  if (err instanceof SyntaxError && err.status === 400) return res.status(400).json({ error: 'JSON inválido.' });
  if (!res.headersSent) {
    res.status(500).json({
      error: 'Error interno del servidor.'
    });
  }
});

// Inicio
async function start() {
  await initializeDatabase();

  const server = app.listen(PORT, () => { console.log(`EGO BAR API escuchando en ${PORT}`); });
  const shutdown = async () => { server.close(); await pool.end(); process.exit(0); };
  process.on('SIGTERM', shutdown); process.on('SIGINT', shutdown);
}

start().catch(error => {
  console.error('No se pudo iniciar EGO BAR API:', error);
  process.exit(1);
});
