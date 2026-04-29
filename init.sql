CREATE TYPE user_role AS ENUM ('MANAGER', 'USER', 'ANALYST'); --cream tipul de date pentru role
CREATE TYPE ticket_severity AS ENUM ('LOW', 'MEDIUM', 'HIGH');
CREATE TYPE ticket_status AS ENUM ('OPEN', 'IN_PROGRESS', 'RESOLVED');
CREATE TYPE audit_action AS ENUM ('LOGIN', 'LOGOUT', 'CREATE', 'UPDATE', 'DELETE');
CREATE TYPE resource_type AS ENUM ('USER', 'TICKET');


CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role user_role DEFAULT 'USER',
    created_at TIMESTAMP DEFAULT NOW(),
    locked BOOLEAN DEFAULT FALSE,
    -- Brute-force lockout: counts consecutive failures; resets on successful login.
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    -- Auto-expires after LOCKOUT_DURATION. NULL means not locked. Admin uses 'locked' for permanent bans.
    locked_until TIMESTAMPTZ DEFAULT NULL
);

CREATE TABLE tickets (
    id SERIAL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    status ticket_status DEFAULT 'OPEN' NOT NULL,
    priority ticket_severity,
    owner_id INTEGER REFERENCES users(id),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE audit_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    action audit_action NOT NULL,
    resource resource_type NOT NULL,
    resource_id INTEGER,
    timestamp TIMESTAMP DEFAULT NOW(),
    ip_address INET
);

CREATE TABLE password_reset_tokens (
    id          SERIAL PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- SHA-256 hex digest of the raw token. Never store the raw token.
    token_hash  CHAR(64)  NOT NULL UNIQUE,
    created_at  TIMESTAMP NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMP NOT NULL,
    used        BOOLEAN   NOT NULL DEFAULT FALSE,
    used_at     TIMESTAMP           -- NULL until the token is consumed
);

CREATE INDEX idx_prt_token_hash ON password_reset_tokens (token_hash);
CREATE INDEX idx_prt_user_id    ON password_reset_tokens (user_id);
