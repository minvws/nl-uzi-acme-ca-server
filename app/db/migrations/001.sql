
-- check mail contains "@" and a TLD
CREATE DOMAIN mail_addr AS TEXT CHECK( VALUE ~ '^[^@]+@[^@]+\.[^@]+$');


-- random ids are not generated by postgres as
-- 1. high entropy randomness is not guarantied by postgres
-- 2. moves load from postgres to application server
CREATE DOMAIN random_id AS TEXT CHECK( length(VALUE) > 20 );

-- hex represenation of a certificate serial number
CREATE DOMAIN serial_number AS TEXT CHECK( VALUE ~ '^[0-9A-F]+$');

-- these acme error types can be stored in db, list not exhausive
CREATE TYPE acme_error_type AS ENUM ('connection', 'incorrectResponse', 'serverInternal', 'malformed', 'unauthorized', 'dns');
CREATE TYPE acme_error AS (
    type        acme_error_type,
    detail      text 
);

-- unlogged table
--   pro: less write overhead as WAL writes are not necessary => better performance
--   contra: table is truncated on server crash, not part of WAL => streaming replication not possible
create unlogged table nonces (
    id random_id not null,
    expires_at timestamptz default now() + interval '30 minutes',
    PRIMARY KEY (id)
);

CREATE TYPE account_status AS ENUM ('valid', 'deactivated', 'revoked');
create table accounts (
    id random_id NOT NULL,
    mail mail_addr not null,
    jwk jsonb not null unique check (jsonb_typeof(jwk) = 'object'),
    status account_status not null default 'valid',
    created_at timestamptz default now(),
    PRIMARY KEY (id)
);
-- index type "hash" is sufficient as only equality in jsonb is relevant
create index accounts_jwk on accounts using hash (jwk);

CREATE TYPE order_status AS ENUM ('pending', 'ready', 'processing', 'valid', 'invalid');
create table orders (
    id random_id not null,
    account_id random_id not null references accounts(id),
    status order_status not null default 'pending',
    error acme_error default null check ((error is null and status <> 'invalid') or (error is not null and status = 'invalid')),
    expires_at timestamptz default now() + interval '60 minutes',
    PRIMARY KEY (id)
);

CREATE TYPE authz_status AS ENUM ('pending', 'valid', 'invalid', 'deactivated', 'expired', 'revoked');
create table authorizations (
    id random_id not null,
    order_id random_id not null references orders(id),
    status authz_status not null default 'pending',
    domain VARCHAR(255) not null,
    PRIMARY KEY (id)
);

CREATE TYPE challenge_status AS ENUM ('pending', 'processing', 'valid', 'invalid');
create table challenges (
    id random_id not null,
    authz_id random_id not null unique references authorizations(id),
    status challenge_status not null default 'pending',
    token random_id not null,
    validated_at timestamptz default null check ((validated_at is null and status <> 'valid') or (validated_at is not null and status = 'valid')),
    error acme_error default null check ((error is null and status <> 'invalid') or (error is not null and status = 'invalid')),
    PRIMARY KEY (id)
);

create table certificates (
    serial_number serial_number not null,
    csr_pem text not null,
    chain_pem text not null,
    order_id random_id not null unique references orders(id),
    not_valid_before timestamptz not null,
    not_valid_after timestamptz not null check (not_valid_after > not_valid_before),
    revoked_at timestamptz default null,
    user_informed_cert_will_expire boolean not null default false,
    user_informed_cert_has_expired boolean not null default false,
    PRIMARY KEY (serial_number)
);

-- only used if CA_ENABLED=True (builtin CA)
create table cas (
    serial_number serial_number not null,
    cert_pem text not null,
    key_pem_enc bytea not null,
    active boolean not null default false,
    crl_pem text not null,
    PRIMARY KEY (serial_number)
);
CREATE UNIQUE INDEX cas_only_one_active ON cas (active) WHERE (active = true);