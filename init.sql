CREATE TYPE user_role AS ENUM ('MANAGER', 'USER', 'ANALYST'); --cream tipul de date pentru role
CREATE TYPE ticket_severity AS ENUM ('LOW', 'MEDIUM', 'HIGH');
CREATE TYPE ticket_status AS ENUM ('OPEN', 'IN_PROGRESS', 'RESOLVED');
CREATE TYPE audit_action AS ENUM ('LOGIN', 'LOGOUT', 'CREATE', 'UPDATE', 'DELETE');
CREATE TYPE resource_type AS ENUM ('USER', 'TICKET');


CREATE TABLE users (
    id SERIAL PRIMARY KEY, --Serial pentru generarea automata de id 
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role user_role DEFAULT 'USER',
    created_at TIMESTAMP DEFAULT NOW(),
    locked BOOLEAN DEFAULT FALSE
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
    resource resource_type,
    resource_id INTEGER,
    timestamp TIMESTAMP DEFAULT NOW(),
    ip_address INET
);


