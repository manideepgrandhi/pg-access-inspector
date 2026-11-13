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

-- functions and triggers ------------------------------------------------------
-- A made-up copy of a real case: an UPDATE fails with
--   permission denied for schema cfg
--   CONTEXT: PL/pgSQL function cfg.fn_config_audit_trg() line 13 at SQL statement
-- because the trigger function is SECURITY DEFINER and its OWNER (audit_owner)
-- has INSERT on the audit table but no USAGE on schema cfg.
CREATE ROLE cfg_owner NOLOGIN;
CREATE ROLE cfg_app NOLOGIN;
CREATE ROLE cfg_user LOGIN;      GRANT cfg_app TO cfg_user;
CREATE ROLE audit_owner NOLOGIN;
CREATE ROLE cfg_writer NOLOGIN;
CREATE ROLE noinh_owner NOLOGIN NOINHERIT;  GRANT cfg_writer TO noinh_owner;
GRANT CONNECT ON DATABASE inspector_test TO cfg_user;

CREATE SCHEMA cfg AUTHORIZATION cfg_owner;
GRANT USAGE ON SCHEMA cfg TO cfg_app, cfg_writer;
SET ROLE cfg_owner;
CREATE TABLE cfg.app_config (key text PRIMARY KEY, value text);
CREATE TABLE cfg.config_audit (id bigserial, key text, old_value text, new_value text,
                               changed_by text, changed_at timestamptz DEFAULT now());
CREATE TABLE cfg.feature_flags (name text PRIMARY KEY, enabled boolean NOT NULL DEFAULT false);
CREATE TABLE cfg.flag_audit (name text, enabled boolean, changed_by text);
CREATE TABLE cfg.change_log (msg text);
CREATE SEQUENCE cfg.change_seq;
GRANT SELECT, INSERT, UPDATE ON cfg.app_config, cfg.feature_flags TO cfg_app;
GRANT INSERT ON cfg.config_audit TO audit_owner;
GRANT USAGE ON SEQUENCE cfg.config_audit_id_seq TO audit_owner;
GRANT SELECT ON cfg.flag_audit TO cfg_app;
GRANT INSERT ON cfg.change_log TO cfg_writer;
INSERT INTO cfg.app_config VALUES ('timeout', '30');
RESET ROLE;

-- 1. SECURITY DEFINER audit trigger; the owner lacks USAGE on cfg (line 13)
CREATE FUNCTION cfg.fn_config_audit_trg() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $body$
DECLARE
  v_old text;
  v_new text;
BEGIN
  IF TG_OP = 'UPDATE' THEN
    v_old := OLD.value;
  END IF;
  v_new := NEW.value;
  IF v_old IS NOT DISTINCT FROM v_new THEN
    RETURN NEW;
  END IF;
  INSERT INTO cfg.config_audit (key, old_value, new_value, changed_by)
  VALUES (NEW.key, v_old, v_new, session_user);
  RETURN NEW;
END
$body$;
ALTER FUNCTION cfg.fn_config_audit_trg() OWNER TO audit_owner;
CREATE TRIGGER trg_config_audit AFTER INSERT OR UPDATE ON cfg.app_config
  FOR EACH ROW EXECUTE FUNCTION cfg.fn_config_audit_trg();

-- 2. SECURITY INVOKER audit trigger; the caller lacks INSERT on cfg.flag_audit
CREATE FUNCTION cfg.fn_flag_audit_trg() RETURNS trigger
LANGUAGE plpgsql AS $body$
BEGIN
  INSERT INTO cfg.flag_audit (name, enabled, changed_by)
  VALUES (NEW.name, NEW.enabled, current_user);
  RETURN NEW;
END
$body$;
ALTER FUNCTION cfg.fn_flag_audit_trg() OWNER TO cfg_owner;
CREATE TRIGGER trg_flag_audit BEFORE INSERT OR UPDATE ON cfg.feature_flags
  FOR EACH ROW EXECUTE FUNCTION cfg.fn_flag_audit_trg();
CREATE TRIGGER trg_flag_audit_old AFTER DELETE ON cfg.feature_flags
  FOR EACH ROW EXECUTE FUNCTION cfg.fn_flag_audit_trg();
ALTER TABLE cfg.feature_flags DISABLE TRIGGER trg_flag_audit_old;

-- 3. SECURITY DEFINER; the owner gets cfg access only through a NOINHERIT membership
CREATE FUNCTION cfg.fn_log_change(p_msg text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $body$
BEGIN
  INSERT INTO cfg.change_log (msg) VALUES (p_msg);
END
$body$;
ALTER FUNCTION cfg.fn_log_change(text) OWNER TO noinh_owner;

-- 4. SECURITY DEFINER without a pinned search_path; 7. a sequence via nextval
CREATE FUNCTION cfg.fn_next_change_id() RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER AS $body$
DECLARE
  v_id bigint;
BEGIN
  v_id := nextval('cfg.change_seq');
  PERFORM 1 FROM app_config LIMIT 1;
  RETURN v_id;
END
$body$;
ALTER FUNCTION cfg.fn_next_change_id() OWNER TO cfg_owner;

-- 5. dynamic SQL
CREATE FUNCTION cfg.fn_purge(p_table text) RETURNS void
LANGUAGE plpgsql AS $body$
BEGIN
  EXECUTE format('DELETE FROM cfg.%I', p_table);
END
$body$;

-- 6. unqualified names resolved through the pinned search_path
CREATE FUNCTION cfg.fn_count_flags() RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = cfg, pg_temp AS $body$
DECLARE
  v integer;
BEGIN
  SELECT count(*) INTO v FROM feature_flags;
  PERFORM fn_log_change('counted flags');
  RETURN v;
END
$body$;
ALTER FUNCTION cfg.fn_count_flags() OWNER TO cfg_owner;

-- 8. SQL-language function (errors say: SQL function "..." statement N)
CREATE FUNCTION cfg.fn_sql_counts() RETURNS bigint
LANGUAGE sql AS $body$
  SELECT count(*) FROM cfg.feature_flags;
  SELECT count(*) FROM cfg.change_log;
$body$;

-- access_report: 3-level chain with a second path, ownership, column and PUBLIC grants
-- acme_clerk → acme_rw → acme_ro, and acme_clerk → acme_ro directly
CREATE ROLE acme_ro NOLOGIN;
CREATE ROLE acme_rw NOLOGIN;     GRANT acme_ro TO acme_rw;
CREATE ROLE acme_clerk LOGIN;    GRANT acme_rw TO acme_clerk;  GRANT acme_ro TO acme_clerk;
CREATE ROLE billing_owner NOLOGIN;
GRANT CONNECT ON DATABASE inspector_test TO acme_ro;
GRANT TEMP ON DATABASE inspector_test TO acme_rw;
CREATE SCHEMA billing AUTHORIZATION billing_owner;
CREATE SCHEMA billing_arch AUTHORIZATION billing_owner;
GRANT USAGE ON SCHEMA billing, billing_arch TO acme_ro;
GRANT CREATE ON SCHEMA billing TO acme_rw;
SET ROLE billing_owner;
CREATE TABLE billing.invoices (id serial PRIMARY KEY, account_no text, amount numeric);
CREATE TABLE billing.clients (id integer, name text, tax_id text);
CREATE TABLE billing.rates (code text, rate numeric);
CREATE TABLE billing_arch.old_invoices (id integer, amount numeric);
GRANT SELECT ON billing.invoices TO acme_ro, acme_clerk;
GRANT INSERT, UPDATE ON billing.invoices TO acme_rw;
GRANT USAGE ON SEQUENCE billing.invoices_id_seq TO acme_rw;
GRANT SELECT (id, name) ON billing.clients TO acme_ro;
GRANT SELECT ON billing.rates TO PUBLIC;
GRANT SELECT ON billing_arch.old_invoices TO acme_ro;
CREATE FUNCTION billing.fn_invoice_total(p_id integer) RETURNS numeric LANGUAGE sql STABLE
  AS 'SELECT amount FROM billing.invoices WHERE id = p_id';
REVOKE EXECUTE ON FUNCTION billing.fn_invoice_total(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION billing.fn_invoice_total(integer) TO acme_rw;
RESET ROLE;
-- owned directly by the clerk, and owned by a group it inherits
SET ROLE acme_clerk;
CREATE TABLE billing.clerk_notes (note text);
RESET ROLE;
SET ROLE acme_rw;
CREATE VIEW billing.invoice_summary AS SELECT count(*) AS n FROM billing.invoices;
RESET ROLE;
\if :pg16
-- PG16+: an INHERIT FALSE grant (SET ROLE only)
CREATE ROLE acme_admin NOLOGIN CREATEDB;
GRANT acme_admin TO acme_clerk WITH INHERIT FALSE, SET TRUE;
GRANT SELECT ON billing.clients TO acme_admin;
\endif
