-- Referencia del esquema EGO BAR v2.0. El servidor aplica CREATE/ALTER IF NOT EXISTS
-- al iniciar. Ejecutar manualmente solo si se acuerda una migración controlada.
CREATE TABLE IF NOT EXISTS users (
  email TEXT PRIMARY KEY,
  role TEXT NOT NULL CHECK (role IN ('Administrador','Controlador')),
  active BOOLEAN NOT NULL DEFAULT TRUE,
  verified BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  first_name TEXT NOT NULL DEFAULT '',
  last_name TEXT NOT NULL DEFAULT '',
  session_version INTEGER NOT NULL DEFAULT 1,
  password_hash TEXT
);
CREATE TABLE IF NOT EXISTS email_codes (
  email TEXT PRIMARY KEY,
  code_hash TEXT NOT NULL,
  expires_at BIGINT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  purpose TEXT NOT NULL DEFAULT 'login'
);
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
CREATE INDEX IF NOT EXISTS idx_controller_codes_email ON controller_activation_codes(email);
CREATE TABLE IF NOT EXISTS credentials (
  token TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  dni TEXT,
  email TEXT,
  event TEXT NOT NULL,
  date TEXT,
  type TEXT,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','used','expired','revoked')),
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
CREATE INDEX IF NOT EXISTS idx_entries_token ON entries(token);
CREATE INDEX IF NOT EXISTS idx_entries_scanned_at ON entries(scanned_at);
CREATE INDEX IF NOT EXISTS idx_credentials_status ON credentials(status);
