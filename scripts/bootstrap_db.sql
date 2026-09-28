-- One-time setup. Run as a PostgreSQL superuser, passing the two role passwords:
--   psql -U postgres -h localhost -v ON_ERROR_STOP=1 -v owner_pw=... -v app_pw=... -f scripts/bootstrap_db.sql
-- On Windows use scripts/bootstrap_db.ps1, which reads the passwords from .env.
-- Not idempotent: to start over, DROP DATABASE securedb, securedb_test; DROP ROLE securedb_app, securedb_owner.

CREATE ROLE securedb_owner LOGIN PASSWORD :'owner_pw';
CREATE ROLE securedb_app LOGIN PASSWORD :'app_pw'
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;

CREATE DATABASE securedb OWNER securedb_owner;
CREATE DATABASE securedb_test OWNER securedb_owner;

\connect securedb
REVOKE ALL ON DATABASE securedb FROM PUBLIC;
GRANT CONNECT ON DATABASE securedb TO securedb_app;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO securedb_app;

\connect securedb_test
REVOKE ALL ON DATABASE securedb_test FROM PUBLIC;
GRANT CONNECT ON DATABASE securedb_test TO securedb_app;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO securedb_app;
