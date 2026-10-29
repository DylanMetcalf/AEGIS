-- One-time database provisioning. Run as a PostgreSQL superuser (or a role
-- with CREATEROLE + CREATEDB), supplying names and passwords as psql variables:
--
--   psql -v db_name=aegis -v owner_role=aegis_owner -v owner_password='...' \
--        -v app_login=aegis_app_login -v app_password='...' -f provision.sql
--
-- Roles:
--   aegis_app     NOLOGIN group role. Migrations grant runtime privileges and
--                 RLS policies to this role only.
--   <owner_role>  Owns the database schema and runs migrations.
--   <app_login>   Runtime login role, member of aegis_app. Owns nothing, has no
--                 BYPASSRLS, cannot run DDL. The application refuses to start
--                 if its role is a superuser, has BYPASSRLS, or can act as a
--                 table owner.

SELECT 'CREATE ROLE aegis_app NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS'
 WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aegis_app') \gexec

SELECT format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD %L', :'owner_role', :'owner_password')
 WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'owner_role') \gexec
SELECT format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS INHERIT PASSWORD %L IN ROLE aegis_app', :'app_login', :'app_password')
 WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'app_login') \gexec

SELECT format('CREATE DATABASE %I OWNER %I', :'db_name', :'owner_role')
 WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = :'db_name') \gexec

SELECT format('REVOKE ALL ON DATABASE %I FROM PUBLIC', :'db_name') \gexec
SELECT format('GRANT CONNECT ON DATABASE %I TO aegis_app', :'db_name') \gexec
