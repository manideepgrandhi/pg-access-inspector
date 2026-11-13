-- Test fixture for pg-access-inspector. Builds a deliberately messy role graph.
-- Run as a superuser in a disposable cluster only (tests/run_tests.sh does this).
\set ON_ERROR_STOP on
SELECT current_setting('server_version_num')::int >= 160000 AS pg16 \gset

-- Roles (cluster-wide) ------------------------------------------------------
-- 4 hops: app_user → app_team → app_rw → app_read → app_base
CREATE ROLE app_base NOLOGIN;
CREATE ROLE app_read NOLOGIN;  GRANT app_base TO app_read;
CREATE ROLE app_rw   NOLOGIN;  GRANT app_read TO app_rw;
CREATE ROLE app_team NOLOGIN;  GRANT app_rw   TO app_team;
CREATE ROLE app_user LOGIN;    GRANT app_team TO app_user;
CREATE ROLE app_user2 LOGIN;   GRANT app_read TO app_user2;
-- NOINHERIT hop
CREATE ROLE reporting NOLOGIN;
CREATE ROLE report_user LOGIN NOINHERIT;  GRANT reporting TO report_user;
CREATE ROLE fin_reader LOGIN;
CREATE ROLE hr_reader LOGIN;
CREATE ROLE sales_owner NOLOGIN;
CREATE ROLE sales_emea LOGIN;
CREATE ROLE sales_apac LOGIN;
CREATE ROLE etl_owner NOLOGIN;
CREATE ROLE app_owner NOLOGIN;
CREATE ROLE ghost_creator NOLOGIN;
CREATE ROLE old_contractor LOGIN VALID UNTIL '2020-01-01';
CREATE ROLE locked_user LOGIN CONNECTION LIMIT 0;
CREATE ROLE nocon_user LOGIN;
-- RDS-style admin chain (rds_superuser is an ordinary role, as on RDS/Aurora)
CREATE ROLE rds_superuser NOLOGIN CREATEROLE CREATEDB;
CREATE ROLE dba_team NOLOGIN;  GRANT rds_superuser TO dba_team;
CREATE ROLE dba_user LOGIN;    GRANT dba_team TO dba_user;
CREATE ROLE legacy_su NOLOGIN SUPERUSER;
CREATE ROLE legacy_admin LOGIN; GRANT legacy_su TO legacy_admin;
CREATE ROLE auditor LOGIN;     GRANT pg_read_all_data TO auditor;
CREATE ROLE orphan_group NOLOGIN;
CREATE ROLE rls_admin LOGIN BYPASSRLS;
CREATE ROLE plain_user LOGIN;
CREATE ROLE db_owner_role LOGIN;
\if :pg16
-- PG16+ per-grant options
CREATE ROLE ops_admin NOLOGIN;
CREATE ROLE vault NOLOGIN;
CREATE ROLE dead_end NOLOGIN;
CREATE ROLE ops_user LOGIN;
GRANT ops_admin TO ops_user WITH INHERIT FALSE, SET TRUE;   -- SET-only
GRANT vault     TO ops_user WITH INHERIT TRUE,  SET FALSE;  -- inherit, no SET ROLE
GRANT dead_end  TO ops_user WITH INHERIT FALSE, SET FALSE;  -- grants nothing
\endif

CREATE DATABASE inspector_test OWNER db_owner_role;
\connect inspector_test
SELECT current_setting('server_version_num')::int >= 160000 AS pg16 \gset

REVOKE CONNECT ON DATABASE inspector_test FROM PUBLIC;
GRANT CONNECT ON DATABASE inspector_test TO app_base, report_user, fin_reader, hr_reader,
  sales_emea, sales_apac, old_contractor, locked_user, dba_user, legacy_admin, auditor,
  rls_admin, plain_user;
\if :pg16
GRANT CONNECT ON DATABASE inspector_test TO ops_user;
\endif

-- sales: RLS, sequence, view, matview, function, foreign table, PUBLIC grant
CREATE SCHEMA sales AUTHORIZATION sales_owner;
GRANT USAGE ON SCHEMA sales TO app_read, sales_emea, sales_apac, reporting;
GRANT CREATE ON SCHEMA sales TO etl_owner, app_owner;
SET ROLE sales_owner;
CREATE TABLE sales.orders (id serial PRIMARY KEY, region text NOT NULL, amount numeric NOT NULL);
INSERT INTO sales.orders (region, amount) VALUES ('EMEA', 100), ('EMEA', 250), ('APAC', 75);
ALTER TABLE sales.orders ENABLE ROW LEVEL SECURITY;
CREATE POLICY emea_only ON sales.orders FOR SELECT TO sales_emea USING (region = 'EMEA');
GRANT SELECT ON sales.orders TO app_read, sales_emea, sales_apac, rls_admin;
GRANT INSERT, UPDATE ON sales.orders TO app_rw;
GRANT USAGE ON SEQUENCE sales.orders_id_seq TO app_rw;
CREATE VIEW sales.order_summary AS SELECT region, sum(amount) AS total FROM sales.orders GROUP BY region;
GRANT SELECT ON sales.order_summary TO app_read;
CREATE MATERIALIZED VIEW sales.region_totals AS SELECT region, count(*) AS n FROM sales.orders GROUP BY region;
GRANT SELECT ON sales.region_totals TO reporting;
CREATE FUNCTION sales.calc_total(p_id integer) RETURNS numeric LANGUAGE sql STABLE
  AS 'SELECT amount FROM sales.orders WHERE id = p_id';
REVOKE EXECUTE ON FUNCTION sales.calc_total(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sales.calc_total(integer) TO app_rw;
CREATE TABLE sales.price_list (sku text, price numeric);
GRANT SELECT ON sales.price_list TO PUBLIC;
RESET ROLE;

CREATE FOREIGN DATA WRAPPER dummy_fdw;
CREATE SERVER dummy_srv FOREIGN DATA WRAPPER dummy_fdw;
CREATE FOREIGN TABLE sales.remote_orders (id integer) SERVER dummy_srv;
ALTER FOREIGN TABLE sales.remote_orders OWNER TO sales_owner;
GRANT SELECT ON sales.remote_orders TO app_read;

-- default privileges per creator: app_owner is covered, etl_owner is not
ALTER DEFAULT PRIVILEGES FOR ROLE app_owner IN SCHEMA sales GRANT SELECT ON TABLES TO app_read;
ALTER DEFAULT PRIVILEGES FOR ROLE ghost_creator GRANT SELECT ON TABLES TO app_read;
SET ROLE app_owner;
CREATE TABLE sales.customers (id integer, name text);
CREATE TABLE sales."Daily Report" (day date, total numeric);
RESET ROLE;
SET ROLE etl_owner;
CREATE TABLE sales.daily_load (load_date date, rows_loaded integer);
RESET ROLE;

-- finance: SELECT granted, schema USAGE missing for fin_reader
CREATE SCHEMA finance;
GRANT USAGE ON SCHEMA finance TO reporting;
CREATE TABLE finance.ledger (id integer, account text, amount numeric);
GRANT SELECT ON finance.ledger TO fin_reader, reporting;

-- hr: column-level grant only
CREATE SCHEMA hr;
GRANT USAGE ON SCHEMA hr TO hr_reader;
CREATE TABLE hr.employees (id integer, name text, dept text, salary numeric);
GRANT SELECT (id, name, dept) ON hr.employees TO hr_reader;

-- audit: PUBLIC write grant
CREATE SCHEMA audit;
GRANT USAGE ON SCHEMA audit TO PUBLIC;
CREATE TABLE audit.events (at timestamptz DEFAULT now(), msg text);
GRANT INSERT ON audit.events TO PUBLIC;

-- SECURITY DEFINER function anyone can run (default EXECUTE to PUBLIC)
CREATE FUNCTION public.reset_counter() RETURNS integer LANGUAGE sql SECURITY DEFINER AS 'SELECT 1';

\if :pg16
CREATE SCHEMA ops;
GRANT USAGE ON SCHEMA ops TO ops_user;
CREATE TABLE ops.jobs (id integer);
CREATE TABLE ops.secrets (id integer);
CREATE TABLE ops.dead (id integer);
GRANT SELECT ON ops.jobs TO ops_admin;
GRANT SELECT ON ops.secrets TO vault;
GRANT SELECT ON ops.dead TO dead_end;
\endif
