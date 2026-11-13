-- pg-access-inspector 1.0.0 -- install.sql
--
-- Read-only PostgreSQL access troubleshooting functions.
-- Installs into the public schema; every object is named access_* (helpers
-- are access__*). Every function is STABLE, SECURITY INVOKER, pins
-- search_path = pg_catalog, pg_temp, and only reads system catalogs and calls
-- has_*_privilege() / pg_has_role(). Nothing here writes data or runs DDL.
--
-- Install:   psql -X -v ON_ERROR_STOP=1 -d <db> -f install.sql
-- Remove:    psql -X -v ON_ERROR_STOP=1 -d <db> -f uninstall.sql
-- Supported: PostgreSQL / Aurora PostgreSQL 14, 15, 16, 17.

BEGIN;

-- ---------------------------------------------------------------------------
-- Internal helpers (access__*)
-- ---------------------------------------------------------------------------

-- Role name -> oid. Accepts exact, "quoted" or unquoted-lowercased names.
CREATE OR REPLACE FUNCTION public.access__role(p_role text)
RETURNS oid
LANGUAGE plpgsql STABLE SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  v_oid oid;
BEGIN
  IF p_role IS NULL OR btrim(p_role) = '' THEN
    RAISE EXCEPTION 'pg-access-inspector: a role name is required';
  END IF;
  SELECT r.oid INTO v_oid FROM pg_roles r WHERE r.rolname = p_role;
  IF v_oid IS NULL AND p_role ~ '^".*"$' THEN
    SELECT r.oid INTO v_oid FROM pg_roles r
     WHERE r.rolname = replace(substr(p_role, 2, length(p_role) - 2), '""', '"');
  END IF;
  IF v_oid IS NULL THEN
    SELECT r.oid INTO v_oid FROM pg_roles r WHERE r.rolname = lower(p_role);
  END IF;
  IF v_oid IS NULL THEN
    RAISE EXCEPTION 'pg-access-inspector: role "%" does not exist', p_role
      USING HINT = 'Role names are case-sensitive. List roles with \du.';
  END IF;
  RETURN v_oid;
END
$fn$;

-- One row per (member, group) membership with its effective options.
-- PG16+ has per-grant inherit_option / set_option columns; older versions
-- inherit when the member role is INHERIT and always allow SET ROLE.
-- to_jsonb() reads the PG16 columns when they exist without naming them, so
-- the same body works on 14-17 with no dynamic SQL.
-- The database owner is implicitly a member of pg_database_owner.
CREATE OR REPLACE FUNCTION public.access__edges()
RETURNS TABLE(member oid, roleid oid, inherit_option boolean, set_option boolean,
              admin_option boolean, granted_by text)
LANGUAGE sql STABLE SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $fn$
  SELECT m.member, m.roleid,
         bool_or(COALESCE((to_jsonb(m) ->> 'inherit_option')::boolean, mr.rolinherit)),
         bool_or(COALESCE((to_jsonb(m) ->> 'set_option')::boolean, true)),
         bool_or(m.admin_option),
         string_agg(DISTINCT COALESCE(g.rolname::text, m.grantor::text), ', ')
    FROM pg_auth_members m
    JOIN pg_roles mr ON mr.oid = m.member
    LEFT JOIN pg_roles g ON g.oid = m.grantor
   GROUP BY m.member, m.roleid
  UNION ALL
  SELECT d.datdba, o.oid, true, true, false, '(implicit: owns this database)'
    FROM pg_database d
    JOIN pg_roles o ON o.rolname = 'pg_database_owner'
   WHERE d.datname = current_database()
$fn$;

-- Every membership path from a role. direction 'up' = groups it belongs to,
-- 'down' = roles that belong to it. Cycles are marked and not followed.
CREATE OR REPLACE FUNCTION public.access__walk(p_role oid, p_direction text DEFAULT 'up')
RETURNS TABLE(roleid oid, depth integer, path oid[], path_text text,
              inherits boolean, settable boolean, hop_inherit boolean,
              hop_set boolean, hop_admin boolean, granted_by text, is_cycle boolean)
LANGUAGE sql STABLE SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $fn$
  WITH RECURSIVE ed AS (
    SELECT CASE WHEN p_direction = 'down' THEN e.roleid ELSE e.member END AS src,
           CASE WHEN p_direction = 'down' THEN e.member ELSE e.roleid END AS dst,
           e.inherit_option, e.set_option, e.admin_option, e.granted_by
      FROM public.access__edges() e
  ), w(roleid, depth, path, inherits, settable, hop_inherit, hop_set, hop_admin, granted_by, is_cycle) AS (
    SELECT p_role, 0, ARRAY[p_role], true, true,
           NULL::boolean, NULL::boolean, NULL::boolean, NULL::text, false
    UNION ALL
    SELECT ed.dst, w.depth + 1, w.path || ed.dst,
           w.inherits AND ed.inherit_option, w.settable AND ed.set_option,
           ed.inherit_option, ed.set_option, ed.admin_option, ed.granted_by,
           ed.dst = ANY (w.path)
      FROM w JOIN ed ON ed.src = w.roleid
     WHERE NOT w.is_cycle AND w.depth < 64
  )
  SELECT w.roleid, w.depth, w.path,
         (SELECT string_agg(COALESCE(r.rolname::text, x.id::text), ' → ' ORDER BY x.n)
            FROM unnest(w.path) WITH ORDINALITY AS x(id, n)
            LEFT JOIN pg_roles r ON r.oid = x.id),
         w.inherits, w.settable, w.hop_inherit, w.hop_set, w.hop_admin,
         w.granted_by, w.is_cycle
    FROM w
$fn$;

-- One row per role reachable from p_role (including itself at depth 0):
-- inherits = some path passes privileges automatically,
-- settable = some path allows SET ROLE to it.
CREATE OR REPLACE FUNCTION public.access__reach(p_role oid)
RETURNS TABLE(roleid oid, role_name text, depth integer, path oid[], path_text text,
              inherits boolean, settable boolean)
LANGUAGE sql STABLE SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $fn$
  SELECT DISTINCT ON (w.roleid)
         w.roleid, r.rolname::text, w.depth, w.path, w.path_text,
         bool_or(w.inherits) OVER (PARTITION BY w.roleid),
         bool_or(w.settable) OVER (PARTITION BY w.roleid)
    FROM public.access__walk(p_role, 'up') w
    JOIN pg_roles r ON r.oid = w.roleid
   WHERE NOT w.is_cycle
   ORDER BY w.roleid, w.inherits DESC, w.settable DESC, w.depth, w.path_text
$fn$;

-- First hop on a path that does not inherit: returns 'member|group'.
CREATE OR REPLACE FUNCTION public.access__break(p_path oid[])
RETURNS text
LANGUAGE sql STABLE SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $fn$
  SELECT mr.rolname || '|' || gr.rolname
    FROM generate_subscripts(p_path, 1) AS i
    JOIN public.access__edges() e ON e.member = p_path[i] AND e.roleid = p_path[i + 1]
    JOIN pg_roles mr ON mr.oid = e.member
    JOIN pg_roles gr ON gr.oid = e.roleid
   WHERE NOT e.inherit_option
   ORDER BY i
   LIMIT 1
$fn$;

CREATE OR REPLACE FUNCTION public.access__kind_matches(p_kind text, p_filter text)
RETURNS boolean
LANGUAGE sql IMMUTABLE SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $fn$
  SELECT CASE lower(btrim(COALESCE(p_filter, '')))
           WHEN '' THEN true
           WHEN 'table' THEN p_kind IN ('table', 'partitioned table')
           WHEN 'relation' THEN p_kind IN ('table', 'partitioned table', 'view',
                                           'materialized view', 'sequence', 'foreign table')
           WHEN 'matview' THEN p_kind = 'materialized view'
           WHEN 'function' THEN p_kind IN ('function', 'procedure', 'aggregate', 'window function')
           WHEN 'routine' THEN p_kind IN ('function', 'procedure', 'aggregate', 'window function')
           ELSE p_kind = lower(btrim(p_filter))
         END
$fn$;

CREATE OR REPLACE FUNCTION public.access__valid_privs(p_kind text)
RETURNS text[]
LANGUAGE sql STABLE SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $fn$
  SELECT CASE
           WHEN p_kind IN ('table', 'partitioned table', 'view', 'materialized view', 'foreign table') THEN
             ARRAY['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER']
             || CASE WHEN current_setting('server_version_num')::int >= 170000
                     THEN ARRAY['MAINTAIN'] ELSE ARRAY[]::text[] END
           WHEN p_kind = 'sequence' THEN ARRAY['USAGE', 'SELECT', 'UPDATE']
           WHEN p_kind IN ('function', 'procedure', 'aggregate', 'window function') THEN ARRAY['EXECUTE']
           WHEN p_kind = 'schema' THEN ARRAY['USAGE', 'CREATE']
           WHEN p_kind = 'database' THEN ARRAY['CONNECT', 'CREATE', 'TEMPORARY']
           ELSE ARRAY[]::text[]
         END
$fn$;

-- The object keyword used in GRANT / ALTER statements.
CREATE OR REPLACE FUNCTION public.access__keyword(p_kind text, p_for_alter boolean DEFAULT false)
RETURNS text
LANGUAGE sql IMMUTABLE SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $fn$
  SELECT CASE
           WHEN p_kind IN ('table', 'partitioned table') THEN 'TABLE'
           WHEN p_kind IN ('view', 'materialized view', 'foreign table') THEN
             CASE WHEN p_for_alter THEN upper(p_kind) ELSE 'TABLE' END
           WHEN p_kind = 'sequence' THEN 'SEQUENCE'
           WHEN p_kind = 'procedure' THEN 'PROCEDURE'
           WHEN p_kind = 'function' THEN 'FUNCTION'
           WHEN p_kind IN ('aggregate', 'window function') THEN 'ROUTINE'
           WHEN p_kind = 'schema' THEN 'SCHEMA'
           WHEN p_kind = 'database' THEN 'DATABASE'
         END
$fn$;

-- Resolve an object name to catalog rows. Accepts schema.name, name,
-- "Quoted".names, db.schema.name (current db only) and func(argtypes).
-- Unqualified names are looked up in every non-system schema, so a name that
-- exists in two schemas returns two rows.
CREATE OR REPLACE FUNCTION public.access__objects(p_object text, p_type text DEFAULT NULL)
RETURNS TABLE(kind text, obj_oid oid, display text, schema_oid oid, schema_name text,
              owner_oid oid, acl aclitem[])
LANGUAGE plpgsql STABLE SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $fn$
#variable_conflict use_column
DECLARE
  v_text   text := btrim(COALESCE(p_object, ''));
  v_args   text;
  v_parts  text[];
  v_raw    text[];
  v_try    text[];
  v_schema text;
  v_name   text;
  v_procs  oid[];
  v_p      oid;
  v_nsp    text;
  i        integer;
BEGIN
  IF v_text = '' THEN
    RETURN;
  END IF;
  IF position('(' IN v_text) > 0 THEN
    v_args := substr(v_text, position('(' IN v_text));
    v_text := btrim(left(v_text, position('(' IN v_text) - 1));
  END IF;
  BEGIN
    v_parts := parse_ident(v_text);
  EXCEPTION WHEN others THEN
    v_parts := string_to_array(v_text, '.');
  END;
  v_raw := string_to_array(replace(v_text, '"', ''), '.');
  FOR i IN 1 .. 2 LOOP
    v_try := CASE WHEN i = 1 THEN v_parts ELSE v_raw END;
    CONTINUE WHEN i = 2 AND v_raw = v_parts;
    IF array_length(v_try, 1) = 3 THEN
      CONTINUE WHEN v_try[1] <> current_database();
      v_try := v_try[2:3];
    END IF;
    CONTINUE WHEN array_length(v_try, 1) NOT IN (1, 2);
    IF array_length(v_try, 1) = 2 THEN
      v_schema := v_try[1]; v_name := v_try[2];
    ELSE
      v_schema := NULL; v_name := v_try[1];
    END IF;
    -- func(argtypes): resolve the exact signature in each schema that has it
    v_procs := NULL;
    IF v_args IS NOT NULL THEN
      v_procs := ARRAY[]::oid[];
      FOR v_nsp IN SELECT DISTINCT n.nspname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
                    WHERE p.proname = v_name AND (v_schema IS NULL OR n.nspname = v_schema) LOOP
        BEGIN
          v_p := to_regprocedure(format('%I.%I', v_nsp, v_name) || v_args);
        EXCEPTION WHEN others THEN
          v_p := NULL;
        END;
        IF v_p IS NOT NULL THEN
          v_procs := v_procs || v_p;
        END IF;
      END LOOP;
    END IF;

    RETURN QUERY
    SELECT x.kind, x.obj_oid, x.display, x.schema_oid, x.schema_name, x.owner_oid, x.acl
      FROM (
        SELECT CASE c.relkind WHEN 'r' THEN 'table' WHEN 'p' THEN 'partitioned table'
                              WHEN 'v' THEN 'view' WHEN 'm' THEN 'materialized view'
                              WHEN 'S' THEN 'sequence' WHEN 'f' THEN 'foreign table' END AS kind,
               c.oid AS obj_oid, format('%I.%I', n.nspname, c.relname) AS display,
               n.oid AS schema_oid, n.nspname::text AS schema_name, c.relowner AS owner_oid,
               COALESCE(c.relacl, acldefault(CASE WHEN c.relkind = 'S' THEN 's' ELSE 'r' END::"char",
                                              c.relowner)) AS acl
          FROM pg_class c
          JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE v_args IS NULL
           AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
           AND c.relname = v_name
           AND CASE WHEN v_schema IS NULL
                    THEN n.nspname NOT IN ('pg_catalog', 'information_schema')
                         AND n.nspname !~ '^pg_(toast|temp_|toast_temp_)'
                    ELSE n.nspname = v_schema END
        UNION ALL
        SELECT CASE p.prokind WHEN 'p' THEN 'procedure' WHEN 'a' THEN 'aggregate'
                              WHEN 'w' THEN 'window function' ELSE 'function' END,
               p.oid,
               p.oid::regprocedure::text,
               n.oid, n.nspname::text, p.proowner,
               COALESCE(p.proacl, acldefault('f', p.proowner))
          FROM pg_proc p
          JOIN pg_namespace n ON n.oid = p.pronamespace
         WHERE p.proname = v_name
           AND CASE WHEN v_schema IS NULL
                    THEN n.nspname NOT IN ('pg_catalog', 'information_schema')
                         AND n.nspname !~ '^pg_(toast|temp_|toast_temp_)'
                    ELSE n.nspname = v_schema END
           AND (v_args IS NULL OR p.oid = ANY (v_procs))
        UNION ALL
        SELECT 'schema', n.oid, quote_ident(n.nspname), NULL::oid, NULL::text, n.nspowner,
               COALESCE(n.nspacl, acldefault('n', n.nspowner))
          FROM pg_namespace n
         WHERE v_schema IS NULL AND v_args IS NULL AND n.nspname = v_name
        UNION ALL
        SELECT 'database', d.oid, quote_ident(d.datname), NULL::oid, NULL::text, d.datdba,
               COALESCE(d.datacl, acldefault('d', d.datdba))
          FROM pg_database d
         WHERE v_schema IS NULL AND v_args IS NULL AND d.datname = v_name
      ) x
     WHERE public.access__kind_matches(x.kind, p_type)
     ORDER BY x.display, x.kind;
    IF FOUND THEN
      RETURN;
    END IF;
  END LOOP;
END
$fn$;

-- Does the role effectively hold the privilege? (the server's own answer)
CREATE OR REPLACE FUNCTION public.access__has(p_role oid, p_kind text, p_oid oid, p_priv text)
RETURNS boolean
LANGUAGE sql STABLE SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $fn$
  SELECT CASE
           WHEN NOT (p_priv = ANY (public.access__valid_privs(p_kind))) THEN NULL
           WHEN p_kind IN ('table', 'partitioned table', 'view', 'materialized view', 'foreign table')
             THEN has_table_privilege(p_role, p_oid, p_priv)
           WHEN p_kind = 'sequence' THEN has_sequence_privilege(p_role, p_oid, p_priv)
           WHEN p_kind IN ('function', 'procedure', 'aggregate', 'window function')
             THEN has_function_privilege(p_role, p_oid, p_priv)
           WHEN p_kind = 'schema' THEN has_schema_privilege(p_role, p_oid, p_priv)
           WHEN p_kind = 'database' THEN has_database_privilege(p_role, p_oid, p_priv)
         END
$fn$;

-- Which grants could give p_role the privilege, and how each reaches it.
CREATE OR REPLACE FUNCTION public.access__sources(p_role oid, p_acl aclitem[], p_priv text,
                                                  p_owner oid, p_kind text)
RETURNS TABLE(source_role text, how text, via text, usable boolean, grantable boolean, path oid[])
LANGUAGE sql STABLE SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $fn$
  WITH r AS (SELECT * FROM public.access__reach(p_role)),
  a AS (
    SELECT x.grantee, bool_or(x.is_grantable) AS grantable
      FROM aclexplode(p_acl) x
     WHERE x.privilege_type = p_priv
     GROUP BY x.grantee
  ),
  s AS (
    SELECT CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE r.role_name END AS source_role,
           CASE WHEN a.grantee = 0 THEN 'PUBLIC'
                WHEN r.depth = 0 AND a.grantee = p_owner THEN 'owner'
                WHEN r.depth = 0 THEN 'direct grant'
                WHEN r.inherits AND a.grantee = p_owner THEN 'inherited from owner'
                WHEN r.inherits THEN 'inherited'
                WHEN r.settable THEN 'needs SET ROLE'
                ELSE 'not usable' END AS how,
           CASE WHEN a.grantee = 0 THEN NULL ELSE r.path_text END AS via,
           (a.grantee = 0 OR r.inherits) AS usable,
           a.grantable,
           r.path
      FROM a
      LEFT JOIN r ON r.roleid = a.grantee
     WHERE a.grantee = 0 OR r.roleid IS NOT NULL
    UNION ALL
    SELECT r.role_name,
           CASE WHEN r.inherits THEN 'predefined role' WHEN r.settable THEN 'needs SET ROLE'
                ELSE 'not usable' END,
           r.path_text, r.inherits, false, r.path
      FROM r
     WHERE (r.role_name = 'pg_read_all_data'
            AND ((p_priv = 'SELECT' AND p_kind IN ('table', 'partitioned table', 'view',
                   'materialized view', 'foreign table', 'sequence'))
                 OR (p_priv = 'USAGE' AND p_kind = 'schema')))
        OR (r.role_name = 'pg_write_all_data'
            AND ((p_priv IN ('INSERT', 'UPDATE', 'DELETE') AND p_kind IN ('table', 'partitioned table',
                   'view', 'materialized view', 'foreign table', 'sequence'))
                 OR (p_priv = 'USAGE' AND p_kind = 'schema')))
        OR (r.role_name = 'pg_maintain' AND p_priv = 'MAINTAIN')
    UNION ALL
    SELECT rr.rolname::text, 'superuser', NULL::text, true, true, ARRAY[p_role]
      FROM pg_roles rr
     WHERE rr.oid = p_role AND rr.rolsuper
    UNION ALL
    -- SUPERUSER is an attribute, never inherited: a member must SET ROLE to use it
    SELECT r.role_name, 'needs SET ROLE', r.path_text, false, true, r.path
      FROM r JOIN pg_roles rr ON rr.oid = r.roleid
     WHERE r.depth > 0 AND rr.rolsuper AND r.settable
  )
  SELECT s.source_role, s.how, s.via, s.usable, s.grantable, s.path
    FROM s
   ORDER BY NOT s.usable, s.how = 'not usable', s.source_role
$fn$;

-- "app_read [inherited: app_user → app_rw → app_read]"
CREATE OR REPLACE FUNCTION public.access__fmt(p_source text, p_how text, p_via text)
RETURNS text
LANGUAGE sql IMMUTABLE SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $fn$
  SELECT CASE
           WHEN p_source = 'PUBLIC' THEN 'PUBLIC [every role]'
           WHEN p_via IS NULL OR p_via = p_source THEN format('%s [%s]', p_source, p_how)
           ELSE format('%s [%s: %s]', p_source, p_how, p_via)
         END
$fn$;

CREATE OR REPLACE FUNCTION public.access__is_system_schema(p_name name)
RETURNS boolean
LANGUAGE sql IMMUTABLE SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $fn$
  SELECT p_name IN ('pg_catalog', 'information_schema')
      OR p_name ~ '^pg_(toast|temp_|toast_temp_)'
$fn$;

-- ---------------------------------------------------------------------------
-- 1. access_chain(role): every role it belongs to, with the path
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.access_chain(p_role text)
RETURNS TABLE(depth integer, member_of text, path text, access text,
              hop_inherit boolean, hop_set boolean, hop_admin boolean,
              granted_by text, server_confirms boolean)
LANGUAGE sql STABLE SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $fn$
  SELECT w.depth,
         COALESCE(r.rolname::text, w.roleid::text),
         w.path_text,
         CASE WHEN w.is_cycle THEN 'CYCLE: stops here'
              WHEN w.inherits THEN 'inherited'
              WHEN w.settable THEN 'needs SET ROLE'
              ELSE 'not usable (no INHERIT, no SET)' END,
         w.hop_inherit, w.hop_set, w.hop_admin, w.granted_by,
         pg_has_role(w.path[1], w.roleid, 'USAGE')
    FROM public.access__walk(public.access__role(p_role), 'up') w
    LEFT JOIN pg_roles r ON r.oid = w.roleid
   WHERE w.depth > 0
   ORDER BY w.path_text
$fn$;

-- ---------------------------------------------------------------------------
-- 2. access_why(role, object, action [, object_type])
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.access_why(p_role text, p_object text, p_action text,
                                             p_object_type text DEFAULT NULL)
RETURNS TABLE(object text, step integer, check_name text, result text, detail text,
              suggested_fix text)
LANGUAGE plpgsql STABLE SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $fn$
#variable_conflict use_column
DECLARE
  v_role     oid := public.access__role(p_role);
  rl         record;
  o          record;
  v_priv     text := upper(btrim(COALESCE(p_action, '')));
  v_rname    text;
  v_pg16     boolean := current_setting('server_version_num')::int >= 160000;
  v_found    boolean := false;
  v_valid    text[];
  v_db       record;
  -- per-object results
  v_role_res text; v_role_det text;
  v_conn     boolean; v_conn_det text; v_conn_fix text;
  v_usage    boolean; v_usage_det text; v_usage_fix text; v_usage_set text;
  v_has      boolean; v_priv_res text; v_priv_det text; v_priv_fix text;
  v_set_role text; v_set_path oid[]; v_break text;
  v_cols     text; v_cols_fix text;
  v_rls_res  text; v_rls_det text; v_rls_fix text;
  v_cmd      text;
  v_owner    text; v_is_owner boolean;
  v_answer   text; v_ans_det text; v_ans_fix text;
  v_relkind  "char"; v_rls boolean; v_force boolean;
  v_perm     text; v_restr text; v_npol integer;
BEGIN
  SELECT * INTO rl FROM pg_roles WHERE oid = v_role;
  v_rname := quote_ident(rl.rolname);
  IF v_priv = 'TEMP' THEN v_priv := 'TEMPORARY'; END IF;

  v_role_det := concat_ws(', ',
      CASE WHEN rl.rolcanlogin THEN 'LOGIN' ELSE 'NOLOGIN (group role: members get what is shown)' END,
      CASE WHEN rl.rolsuper THEN 'SUPERUSER' END,
      CASE WHEN NOT rl.rolinherit THEN 'NOINHERIT' END,
      CASE WHEN rl.rolbypassrls THEN 'BYPASSRLS' END,
      CASE WHEN rl.rolvaliduntil < now() THEN 'password EXPIRED (VALID UNTIL ' || rl.rolvaliduntil || ')' END,
      CASE WHEN rl.rolconnlimit = 0 THEN 'CONNECTION LIMIT 0' END);
  v_role_res := CASE WHEN rl.rolcanlogin AND (rl.rolvaliduntil < now() OR rl.rolconnlimit = 0) THEN 'FAIL'
                     WHEN NOT rl.rolcanlogin THEN 'INFO' ELSE 'PASS' END;

  SELECT d.oid, d.datname, d.datdba, COALESCE(d.datacl, acldefault('d', d.datdba)) AS acl
    INTO v_db FROM pg_database d WHERE d.datname = current_database();

  FOR o IN SELECT * FROM public.access__objects(p_object, p_object_type) LOOP
    v_found := true;
    v_valid := public.access__valid_privs(o.kind);
    IF NOT (v_priv = ANY (v_valid)) THEN
      object := o.display; step := 0; check_name := 'action'; result := 'ERROR';
      detail := format('%s is not a privilege on a %s. Valid: %s', v_priv, o.kind,
                       array_to_string(v_valid, ', '));
      suggested_fix := NULL;
      RETURN NEXT;
      CONTINUE;
    END IF;

    -- database CONNECT (not needed when the object is a database)
    v_conn := NULL; v_conn_det := NULL; v_conn_fix := NULL;
    IF o.kind <> 'database' THEN
      v_conn := has_database_privilege(v_role, v_db.oid, 'CONNECT');
      SELECT string_agg(public.access__fmt(s.source_role, s.how, s.via), '; ')
        INTO v_conn_det
        FROM public.access__sources(v_role, v_db.acl, 'CONNECT', v_db.datdba, 'database') s
       WHERE s.usable = v_conn OR NOT v_conn;
      v_conn_det := CASE WHEN v_conn THEN 'granted by ' || COALESCE(v_conn_det, 'superuser')
                         ELSE format('no usable CONNECT on database %I', v_db.datname)
                              || COALESCE(' (found: ' || v_conn_det || ')', '') END;
      IF NOT v_conn THEN
        v_conn_fix := format('GRANT CONNECT ON DATABASE %I TO %s;', v_db.datname, v_rname);
      END IF;
    END IF;

    -- schema USAGE
    v_usage := NULL; v_usage_det := NULL; v_usage_fix := NULL; v_usage_set := NULL;
    IF o.schema_oid IS NOT NULL THEN
      v_usage := has_schema_privilege(v_role, o.schema_oid, 'USAGE');
      SELECT s.source_role INTO v_usage_set
        FROM public.access__sources(v_role,
               (SELECT COALESCE(n.nspacl, acldefault('n', n.nspowner)) FROM pg_namespace n WHERE n.oid = o.schema_oid),
               'USAGE', (SELECT n.nspowner FROM pg_namespace n WHERE n.oid = o.schema_oid), 'schema') s
       WHERE NOT v_usage AND s.how = 'needs SET ROLE'
       ORDER BY array_length(s.path, 1)
       LIMIT 1;
      SELECT string_agg(public.access__fmt(s.source_role, s.how, s.via), '; ')
        INTO v_usage_det
        FROM public.access__sources(v_role,
               (SELECT COALESCE(n.nspacl, acldefault('n', n.nspowner)) FROM pg_namespace n WHERE n.oid = o.schema_oid),
               'USAGE', (SELECT n.nspowner FROM pg_namespace n WHERE n.oid = o.schema_oid), 'schema') s
       WHERE s.usable = v_usage OR NOT v_usage;
      v_usage_det := CASE WHEN v_usage THEN 'granted by ' || COALESCE(v_usage_det, 'superuser')
                          ELSE format('no usable USAGE on schema %I: the role cannot even see objects in it', o.schema_name)
                               || COALESCE(' (found: ' || v_usage_det || ')', '') END;
      IF NOT v_usage AND v_usage_set IS NOT NULL THEN
        v_usage_det := format('USAGE on schema %I is held by %s, which is not inherited: SET ROLE %s first',
                              o.schema_name, v_usage_set, v_usage_set);
        v_usage_fix := format('SET ROLE %I;', v_usage_set);
      ELSIF NOT v_usage THEN
        v_usage_fix := format('GRANT USAGE ON SCHEMA %I TO %s;', o.schema_name, v_rname);
      END IF;
    END IF;

    -- the privilege itself
    v_has := public.access__has(v_role, o.kind, o.obj_oid, v_priv);
    v_set_role := NULL; v_set_path := NULL; v_priv_fix := NULL;
    IF v_has THEN
      SELECT string_agg(public.access__fmt(s.source_role, s.how, s.via), '; ')
        INTO v_priv_det
        FROM public.access__sources(v_role, o.acl, v_priv, o.owner_oid, o.kind) s
       WHERE s.usable;
      v_priv_res := 'PASS';
      v_priv_det := 'granted by ' || COALESCE(v_priv_det, 'a role it inherits');
    ELSE
      SELECT s.source_role, s.path INTO v_set_role, v_set_path
        FROM public.access__sources(v_role, o.acl, v_priv, o.owner_oid, o.kind) s
       WHERE s.how = 'needs SET ROLE'
       ORDER BY array_length(s.path, 1)
       LIMIT 1;
      IF v_set_role IS NOT NULL THEN
        v_break := public.access__break(v_set_path);
        v_priv_res := 'WARN';
        v_priv_det := CASE WHEN v_break IS NULL
          THEN format('%s is a SUPERUSER role reachable through %s; superuser is an attribute and is never inherited: SET ROLE %s first',
                      v_set_role,
                      (SELECT w.path_text FROM public.access__walk(v_role, 'up') w WHERE w.path = v_set_path LIMIT 1),
                      v_set_role)
          ELSE format('granted to %s (path %s), but %s does not inherit from %s: SET ROLE %s first',
                      v_set_role,
                      (SELECT w.path_text FROM public.access__walk(v_role, 'up') w WHERE w.path = v_set_path LIMIT 1),
                      split_part(v_break, '|', 1), split_part(v_break, '|', 2), v_set_role) END;
        v_priv_fix := format('SET ROLE %I;', v_set_role)
          || CASE WHEN v_break IS NULL THEN ''
                  WHEN v_pg16
                  THEN format('  -- or inherit it: GRANT %I TO %I WITH INHERIT TRUE;',
                              split_part(v_break, '|', 2), split_part(v_break, '|', 1))
                  ELSE format('  -- or inherit it: ALTER ROLE %I INHERIT;', split_part(v_break, '|', 1)) END;
      ELSE
        v_priv_res := 'FAIL';
        v_priv_det := format('no %s grant to %s, to any role it inherits, or to PUBLIC', v_priv, rl.rolname);
        v_priv_fix := format('GRANT %s ON %s %s TO %s;', v_priv, public.access__keyword(o.kind), o.display, v_rname);
      END IF;
    END IF;

    -- column-level grants (only relevant when the table-level check fails)
    v_cols := NULL; v_cols_fix := NULL;
    IF NOT v_has AND o.kind IN ('table', 'partitioned table', 'view', 'materialized view', 'foreign table')
       AND v_priv IN ('SELECT', 'INSERT', 'UPDATE', 'REFERENCES') THEN
      SELECT string_agg(quote_ident(a.attname), ', ' ORDER BY a.attnum)
        INTO v_cols
        FROM pg_attribute a
       WHERE a.attrelid = o.obj_oid AND a.attnum > 0 AND NOT a.attisdropped
         AND has_column_privilege(v_role, o.obj_oid, a.attnum, v_priv);
      IF v_cols IS NOT NULL THEN
        v_cols_fix := format('-- either use only the granted columns (%s), or: GRANT %s ON TABLE %s TO %s;',
                             v_cols, v_priv, o.display, v_rname);
      END IF;
    END IF;

    -- row level security
    v_rls_res := NULL; v_rls_det := NULL; v_rls_fix := NULL;
    v_cmd := CASE v_priv WHEN 'SELECT' THEN 'r' WHEN 'INSERT' THEN 'a' WHEN 'UPDATE' THEN 'w'
                         WHEN 'DELETE' THEN 'd' END;
    IF o.kind IN ('table', 'partitioned table') AND v_cmd IS NOT NULL THEN
      SELECT c.relrowsecurity, c.relforcerowsecurity INTO v_rls, v_force
        FROM pg_class c WHERE c.oid = o.obj_oid;
      v_is_owner := pg_has_role(v_role, o.owner_oid, 'USAGE');
      IF NOT v_rls THEN
        v_rls_res := 'PASS'; v_rls_det := 'row level security is not enabled on this table';
      ELSIF rl.rolsuper OR rl.rolbypassrls THEN
        v_rls_res := 'PASS';
        v_rls_det := 'RLS is enabled but ignored: role is ' || CASE WHEN rl.rolsuper THEN 'SUPERUSER' ELSE 'BYPASSRLS' END;
      ELSIF v_is_owner AND NOT v_force THEN
        v_rls_res := 'PASS';
        v_rls_det := 'RLS is enabled but ignored: role is (or inherits) the table owner and FORCE ROW LEVEL SECURITY is off';
      ELSE
        WITH r AS (SELECT * FROM public.access__reach(v_role) WHERE inherits),
        pol AS (
          SELECT p.polname, p.polpermissive,
                 pg_get_expr(p.polqual, p.polrelid) AS using_expr,
                 pg_get_expr(p.polwithcheck, p.polrelid) AS check_expr
            FROM pg_policy p
           WHERE p.polrelid = o.obj_oid
             AND p.polcmd IN (v_cmd::"char", '*')
             AND (0::oid = ANY (p.polroles) OR EXISTS (SELECT 1 FROM r WHERE r.roleid = ANY (p.polroles)))
        )
        SELECT count(*) FILTER (WHERE pol.polpermissive),
               string_agg(format('%I%s%s', pol.polname,
                                 COALESCE(' USING (' || pol.using_expr || ')', ''),
                                 COALESCE(' WITH CHECK (' || pol.check_expr || ')', '')), '; ')
                 FILTER (WHERE pol.polpermissive),
               string_agg(format('%I%s', pol.polname, COALESCE(' USING (' || pol.using_expr || ')', '')), '; ')
                 FILTER (WHERE NOT pol.polpermissive)
          INTO v_npol, v_perm, v_restr
          FROM pol;
        IF v_npol = 0 THEN
          v_rls_res := 'FAIL';
          v_rls_det := format('RLS is enabled%s and no permissive %s policy applies to this role: %s',
                              CASE WHEN v_force THEN ' (FORCED, applies to the owner too)' ELSE '' END,
                              v_priv,
                              CASE WHEN v_priv = 'INSERT' THEN 'every new row is rejected'
                                   ELSE 'it sees / affects zero rows (no error is raised)' END);
          v_rls_fix := format('CREATE POLICY <policy_name> ON %s FOR %s TO %s %s (<condition>);',
                              o.display, v_priv, v_rname,
                              CASE WHEN v_priv = 'INSERT' THEN 'WITH CHECK' ELSE 'USING' END);
        ELSE
          v_rls_res := 'WARN';
          v_rls_det := 'RLS is enabled: rows are limited to policies ' || v_perm
                       || COALESCE('; restricted further by ' || v_restr, '');
        END IF;
      END IF;
    END IF;

    -- ownership
    SELECT rolname INTO v_owner FROM pg_roles WHERE oid = o.owner_oid;
    v_is_owner := pg_has_role(v_role, o.owner_oid, 'USAGE');

    -- answer
    v_ans_fix := NULL;
    IF rl.rolsuper THEN
      v_answer := 'YES';
      v_ans_det := 'superuser: bypasses every privilege check and RLS';
    ELSIF v_has AND COALESCE(v_conn, true) AND COALESCE(v_usage, true) THEN
      v_answer := CASE WHEN v_rls_res = 'FAIL' THEN 'YES, BUT RLS BLOCKS ALL ROWS'
                       WHEN v_rls_res = 'WARN' THEN 'YES, RLS FILTERS ROWS'
                       ELSE 'YES' END;
      v_ans_det := format('%s can %s %s', rl.rolname, v_priv, o.display);
      v_ans_fix := v_rls_fix;
    ELSE
      v_answer := CASE WHEN (v_has OR v_set_role IS NOT NULL) AND (v_set_role IS NOT NULL OR v_usage_set IS NOT NULL)
                            AND COALESCE(v_conn, true) AND (COALESCE(v_usage, true) OR v_usage_set IS NOT NULL)
                         THEN 'ONLY AFTER SET ROLE'
                       WHEN v_cols IS NOT NULL AND COALESCE(v_conn, true) AND COALESCE(v_usage, true)
                         THEN 'COLUMNS ONLY'
                       ELSE 'NO' END;
      v_ans_det := 'missing: ' || concat_ws(', ',
                     CASE WHEN v_conn IS FALSE THEN format('CONNECT on database %I', v_db.datname) END,
                     CASE WHEN v_usage IS FALSE THEN format('USAGE on schema %I', o.schema_name)
                                                     || CASE WHEN v_usage_set IS NOT NULL
                                                             THEN format(' (held by %s, not inherited)', v_usage_set) ELSE '' END END,
                     CASE WHEN NOT v_has THEN
                       format('%s on %s', v_priv, o.display)
                       || CASE WHEN v_set_role IS NOT NULL THEN format(' (held by %s, not inherited)', v_set_role)
                               WHEN v_cols IS NOT NULL THEN format(' (only columns %s)', v_cols)
                               ELSE '' END
                     END);
      v_ans_fix := CASE WHEN v_answer = 'ONLY AFTER SET ROLE'
                        THEN concat_ws(E'\n', v_conn_fix,
                               CASE WHEN v_usage_set IS DISTINCT FROM v_set_role OR v_set_role IS NULL THEN v_usage_fix END,
                               v_priv_fix)
                        ELSE concat_ws(E'\n', v_conn_fix, v_usage_fix, v_priv_fix) END;
    END IF;

    object := o.display;
    step := 0; check_name := 'answer'; result := v_answer; detail := v_ans_det;
    suggested_fix := NULLIF(v_ans_fix, ''); RETURN NEXT;
    step := 1; check_name := 'role'; result := v_role_res;
    detail := rl.rolname || ': ' || v_role_det;
    suggested_fix := CASE WHEN v_role_res = 'FAIL' THEN
                       concat_ws(E'\n',
                         CASE WHEN rl.rolvaliduntil < now() THEN format('ALTER ROLE %s VALID UNTIL ''infinity'';', v_rname) END,
                         CASE WHEN rl.rolconnlimit = 0 THEN format('ALTER ROLE %s CONNECTION LIMIT -1;', v_rname) END)
                     END;
    RETURN NEXT;
    IF v_conn IS NOT NULL THEN
      step := 2; check_name := 'database CONNECT'; result := CASE WHEN v_conn THEN 'PASS' ELSE 'FAIL' END;
      detail := v_conn_det; suggested_fix := v_conn_fix; RETURN NEXT;
    END IF;
    IF v_usage IS NOT NULL THEN
      step := 3; check_name := 'schema USAGE';
      result := CASE WHEN v_usage THEN 'PASS' WHEN v_usage_set IS NOT NULL THEN 'WARN' ELSE 'FAIL' END;
      detail := v_usage_det; suggested_fix := v_usage_fix; RETURN NEXT;
    END IF;
    step := 4; check_name := v_priv || ' privilege'; result := v_priv_res;
    detail := v_priv_det; suggested_fix := v_priv_fix; RETURN NEXT;
    IF v_cols IS NOT NULL THEN
      step := 5; check_name := 'column grants'; result := 'WARN';
      detail := format('%s is granted on columns %s only; SELECT * and unlisted columns fail', v_priv, v_cols);
      suggested_fix := v_cols_fix; RETURN NEXT;
    END IF;
    IF v_rls_res IS NOT NULL THEN
      step := 6; check_name := 'row level security'; result := v_rls_res;
      detail := v_rls_det; suggested_fix := v_rls_fix; RETURN NEXT;
    END IF;
    step := 7; check_name := 'owner'; result := 'INFO';
    detail := format('%s is owned by %s%s', o.display, v_owner,
                     CASE WHEN o.owner_oid = v_role THEN ' (this role)'
                          WHEN v_is_owner THEN ' (this role inherits the owner)' ELSE '' END);
    suggested_fix := NULL; RETURN NEXT;
  END LOOP;

  IF NOT v_found THEN
    object := p_object; step := 0; check_name := 'object'; result := 'ERROR';
    detail := format('no %s named %s found in database %s (schema-qualify the name, or pass object_type)',
                     COALESCE(p_object_type, 'table, view, sequence, function, schema or database'),
                     p_object, current_database());
    suggested_fix := NULL;
    RETURN NEXT;
  END IF;
END
$fn$;

-- ---------------------------------------------------------------------------
-- 3. access_privileges(role [, include_public]): everything the role can use
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.access_privileges(p_role text, p_include_public boolean DEFAULT true)
RETURNS TABLE(object_type text, object_name text, privilege text, how text,
              source_role text, via text, grantable boolean)
LANGUAGE sql STABLE SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $fn$
  WITH me AS (SELECT public.access__role(p_role) AS id),
  r AS (SELECT x.* FROM me, public.access__reach(me.id) x),
  objs AS (
    SELECT 1 AS ord, 'database'::text AS t, quote_ident(d.datname) AS nm, d.datdba AS own,
           COALESCE(d.datacl, acldefault('d', d.datdba)) AS acl
      FROM pg_database d
     WHERE NOT d.datistemplate
    UNION ALL
    SELECT 2, 'schema', quote_ident(n.nspname), n.nspowner, COALESCE(n.nspacl, acldefault('n', n.nspowner))
      FROM pg_namespace n
     WHERE NOT public.access__is_system_schema(n.nspname)
    UNION ALL
    SELECT 3, CASE c.relkind WHEN 'r' THEN 'table' WHEN 'p' THEN 'partitioned table' WHEN 'v' THEN 'view'
                             WHEN 'm' THEN 'materialized view' WHEN 'S' THEN 'sequence'
                             WHEN 'f' THEN 'foreign table' END,
           format('%I.%I', n.nspname, c.relname), c.relowner,
           COALESCE(c.relacl, acldefault(CASE WHEN c.relkind = 'S' THEN 's' ELSE 'r' END::"char", c.relowner))
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
       AND NOT public.access__is_system_schema(n.nspname)
    UNION ALL
    SELECT 4, 'column', format('%I.%I.%I', n.nspname, c.relname, a.attname), c.relowner, a.attacl
      FROM pg_attribute a
      JOIN pg_class c ON c.oid = a.attrelid
      JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE a.attacl IS NOT NULL AND a.attnum > 0 AND NOT a.attisdropped
       AND NOT public.access__is_system_schema(n.nspname)
    UNION ALL
    SELECT 5, CASE p.prokind WHEN 'p' THEN 'procedure' WHEN 'a' THEN 'aggregate'
                             WHEN 'w' THEN 'window function' ELSE 'function' END,
           p.oid::regprocedure::text,
           p.proowner, COALESCE(p.proacl, acldefault('f', p.proowner))
      FROM pg_proc p
      JOIN pg_namespace n ON n.oid = p.pronamespace
     WHERE NOT public.access__is_system_schema(n.nspname)
       AND COALESCE(obj_description(p.oid, 'pg_proc'), '') NOT LIKE 'pg-access-inspector:%'
  ),
  x AS (
    SELECT o.ord, o.t, o.nm, o.own, e.grantee, e.privilege_type, bool_or(e.is_grantable) AS grantable
      FROM objs o, aclexplode(o.acl) e
     GROUP BY o.ord, o.t, o.nm, o.own, e.grantee, e.privilege_type
  ),
  rows AS (
    SELECT x.ord, x.t, x.nm, x.privilege_type AS priv,
           CASE WHEN x.grantee = 0 THEN 'PUBLIC'
                WHEN r.depth = 0 AND x.grantee = x.own THEN 'owner'
                WHEN r.depth = 0 THEN 'direct grant'
                WHEN r.inherits AND x.grantee = x.own THEN 'inherited from owner'
                WHEN r.inherits THEN 'inherited'
                WHEN r.settable THEN 'needs SET ROLE'
                ELSE 'not usable' END AS how,
           CASE WHEN x.grantee = 0 THEN 'PUBLIC' ELSE r.role_name END AS src,
           CASE WHEN x.grantee = 0 THEN NULL ELSE r.path_text END AS via,
           x.grantable
      FROM x
      LEFT JOIN r ON r.roleid = x.grantee
     WHERE (x.grantee = 0 AND p_include_public) OR r.roleid IS NOT NULL
    UNION ALL
    SELECT 6, 'all relations', '*', p.priv,
           CASE WHEN r.inherits THEN 'predefined role' WHEN r.settable THEN 'needs SET ROLE' ELSE 'not usable' END,
           r.role_name, r.path_text, false
      FROM r
      JOIN (VALUES ('pg_read_all_data', 'SELECT'), ('pg_write_all_data', 'INSERT'),
                   ('pg_write_all_data', 'UPDATE'), ('pg_write_all_data', 'DELETE'),
                   ('pg_maintain', 'MAINTAIN')) AS p(role_name, priv)
        ON p.role_name = r.role_name
    UNION ALL
    SELECT 6, 'all schemas', '*', 'USAGE',
           CASE WHEN r.inherits THEN 'predefined role' WHEN r.settable THEN 'needs SET ROLE' ELSE 'not usable' END,
           r.role_name, r.path_text, false
      FROM r
     WHERE r.role_name IN ('pg_read_all_data', 'pg_write_all_data')
    UNION ALL
    SELECT 0, 'everything', '*', 'ALL', 'superuser', rr.rolname::text, NULL::text, true
      FROM me JOIN pg_roles rr ON rr.oid = me.id
     WHERE rr.rolsuper
  )
  SELECT rows.t, rows.nm, rows.priv, rows.how, rows.src, rows.via, rows.grantable
    FROM rows
   ORDER BY rows.ord, rows.nm, rows.priv, rows.how = 'PUBLIC', rows.src
$fn$;

-- ---------------------------------------------------------------------------
-- 4. access_default_privileges(role [, schema]): what NEW objects will give it
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.access_default_privileges(p_role text, p_schema text DEFAULT NULL)
RETURNS TABLE(creator_role text, schema_name text, object_type text, privileges text,
              grantee text, how text, note text)
LANGUAGE sql STABLE SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $fn$
  WITH me AS (SELECT public.access__role(p_role) AS id),
  myname AS (SELECT rr.rolname::text AS nm FROM me JOIN pg_roles rr ON rr.oid = me.id),
  r AS (SELECT x.* FROM me, public.access__reach(me.id) x),
  d AS (
    SELECT da.defaclrole, da.defaclnamespace, da.defaclobjtype, e.grantee, e.privilege_type
      FROM pg_default_acl da, aclexplode(da.defaclacl) e
  ),
  entries AS (
    SELECT COALESCE(cr.rolname::text, format('(dropped role oid %s)', d.defaclrole)) AS creator,
           CASE WHEN d.defaclnamespace = 0 THEN '(all schemas)' ELSE n.nspname::text END AS sch,
           CASE d.defaclobjtype WHEN 'r' THEN 'tables' WHEN 'S' THEN 'sequences' WHEN 'f' THEN 'functions'
                                WHEN 'T' THEN 'types' WHEN 'n' THEN 'schemas' ELSE d.defaclobjtype::text END AS otype,
           string_agg(d.privilege_type, ', ' ORDER BY d.privilege_type) AS privs,
           CASE WHEN d.grantee = 0 THEN 'PUBLIC' ELSE r.role_name END AS grantee,
           CASE WHEN d.grantee = 0 THEN 'PUBLIC'
                WHEN r.depth = 0 THEN 'direct'
                WHEN r.inherits THEN 'inherited'
                WHEN r.settable THEN 'needs SET ROLE'
                ELSE 'not usable' END AS how,
           CASE WHEN d.grantee = 0 OR r.depth = 0 THEN NULL ELSE 'via ' || r.path_text END AS note
      FROM d
      LEFT JOIN r ON r.roleid = d.grantee
      LEFT JOIN pg_roles cr ON cr.oid = d.defaclrole
      LEFT JOIN pg_namespace n ON n.oid = d.defaclnamespace
     WHERE (d.grantee = 0 OR r.roleid IS NOT NULL)
       AND (p_schema IS NULL OR d.defaclnamespace = 0 OR n.nspname = p_schema)
     GROUP BY 1, 2, 3, 5, 6, 7
  ),
  -- Gaps: schemas where the role already reads some table (so it is expected to
  -- read new ones), and a table owner there whose default privileges do not give
  -- the role (or a role it inherits) SELECT on new tables.
  readable AS (
    SELECT DISTINCT c.relnamespace AS nsp
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
      CROSS JOIN me
     WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f')
       AND NOT public.access__is_system_schema(n.nspname)
       AND has_schema_privilege(me.id, n.oid, 'USAGE')
       AND has_table_privilege(me.id, c.oid, 'SELECT')
       AND NOT pg_has_role(me.id, c.relowner, 'USAGE')
       AND NOT EXISTS (SELECT 1 FROM aclexplode(c.relacl) e WHERE e.grantee = 0 AND e.privilege_type = 'SELECT')
  ),
  gaps AS (
    SELECT DISTINCT ow.rolname::text AS creator, n.nspname::text AS sch, n.oid AS nsp
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
      JOIN pg_roles ow ON ow.oid = c.relowner
      CROSS JOIN me
     WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f')
       AND c.relnamespace IN (SELECT nsp FROM readable)
       AND (p_schema IS NULL OR n.nspname = p_schema)
       AND NOT pg_has_role(me.id, c.relowner, 'USAGE')
       AND NOT EXISTS (
             SELECT 1
               FROM pg_default_acl da, aclexplode(da.defaclacl) e
              WHERE da.defaclrole = c.relowner
                AND da.defaclobjtype = 'r'
                AND da.defaclnamespace IN (0, n.oid)
                AND e.privilege_type = 'SELECT'
                AND (e.grantee = 0 OR e.grantee IN (SELECT r.roleid FROM r WHERE r.inherits)))
       AND NOT EXISTS (SELECT 1 FROM me JOIN pg_roles s ON s.oid = me.id WHERE s.rolsuper)
  ),
  -- suggest granting to the role in the chain that already holds SELECT on most tables there
  best AS (
    SELECT DISTINCT ON (g.nsp) g.nsp, r.role_name
      FROM (SELECT DISTINCT nsp FROM gaps) g
      JOIN pg_class c ON c.relnamespace = g.nsp AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
      CROSS JOIN LATERAL aclexplode(c.relacl) e
      JOIN r ON r.roleid = e.grantee AND r.inherits
     WHERE e.privilege_type = 'SELECT'
     GROUP BY g.nsp, r.role_name, r.depth
     ORDER BY g.nsp, count(*) DESC, r.depth DESC, r.role_name
  )
  SELECT e.creator, e.sch, e.otype, e.privs, e.grantee, e.how, e.note
    FROM entries e
  UNION ALL
  SELECT g.creator, g.sch, 'tables', NULL, NULL, 'NOT COVERED',
         format('new tables created by %s in %s will NOT be readable by %s. Fix: ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA %I GRANT SELECT ON TABLES TO %I;',
                g.creator, g.sch, (SELECT nm FROM myname), g.creator, g.sch,
                COALESCE(b.role_name, (SELECT nm FROM myname)))
    FROM gaps g
    LEFT JOIN best b ON b.nsp = g.nsp
  ORDER BY 1, 2, 3, 6
$fn$;

-- ---------------------------------------------------------------------------
-- 5. access_who_can(object, action [, object_type]): reverse lookup
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.access_who_can(p_object text, p_action text, p_object_type text DEFAULT NULL,
                                                 p_include_predefined boolean DEFAULT false)
RETURNS TABLE(object text, role_name text, can_login boolean, result text, via text, missing text)
LANGUAGE plpgsql STABLE SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $fn$
#variable_conflict use_column
DECLARE
  o       record;
  rr      record;
  v_priv  text := upper(btrim(COALESCE(p_action, '')));
  v_has   boolean;
  v_schema boolean;
  v_conn  boolean;
  v_via   text;
  v_set   text;
  v_cols  text;
  v_found boolean := false;
BEGIN
  IF v_priv = 'TEMP' THEN v_priv := 'TEMPORARY'; END IF;
  FOR o IN SELECT * FROM public.access__objects(p_object, p_object_type) LOOP
    v_found := true;
    IF NOT (v_priv = ANY (public.access__valid_privs(o.kind))) THEN
      RAISE EXCEPTION 'pg-access-inspector: % is not a privilege on a % (valid: %)',
        v_priv, o.kind, array_to_string(public.access__valid_privs(o.kind), ', ');
    END IF;
    FOR rr IN SELECT r.oid, r.rolname, r.rolcanlogin, r.rolsuper FROM pg_roles r
               WHERE p_include_predefined OR r.rolname !~ '^pg_'
               ORDER BY r.rolname LOOP
      v_has := public.access__has(rr.oid, o.kind, o.obj_oid, v_priv);
      SELECT string_agg(public.access__fmt(s.source_role, s.how, s.via), '; ') FILTER (WHERE s.usable),
             min(s.source_role) FILTER (WHERE s.how = 'needs SET ROLE')
        INTO v_via, v_set
        FROM public.access__sources(rr.oid, o.acl, v_priv, o.owner_oid, o.kind) s;
      v_cols := NULL;
      IF NOT v_has AND v_set IS NULL
         AND o.kind IN ('table', 'partitioned table', 'view', 'materialized view', 'foreign table')
         AND v_priv IN ('SELECT', 'INSERT', 'UPDATE', 'REFERENCES') THEN
        SELECT string_agg(quote_ident(a.attname), ', ' ORDER BY a.attnum) INTO v_cols
          FROM pg_attribute a
         WHERE a.attrelid = o.obj_oid AND a.attnum > 0 AND NOT a.attisdropped
           AND has_column_privilege(rr.oid, o.obj_oid, a.attnum, v_priv);
      END IF;
      CONTINUE WHEN NOT v_has AND v_set IS NULL AND v_cols IS NULL;
      -- after SET ROLE the target's schema access is what counts
      v_schema := CASE WHEN o.schema_oid IS NULL THEN true
                       WHEN NOT v_has AND v_set IS NOT NULL
                         THEN has_schema_privilege((SELECT x.oid FROM pg_roles x WHERE x.rolname = v_set),
                                                   o.schema_oid, 'USAGE')
                       ELSE has_schema_privilege(rr.oid, o.schema_oid, 'USAGE') END;
      v_conn := CASE WHEN o.kind = 'database' THEN true
                     ELSE has_database_privilege(rr.oid, current_database(), 'CONNECT') END;
      object := o.display;
      role_name := rr.rolname;
      can_login := rr.rolcanlogin;
      result := CASE WHEN v_has AND v_schema AND v_conn THEN 'YES'
                     WHEN v_has THEN 'BLOCKED'
                     WHEN v_set IS NOT NULL THEN 'ONLY AFTER SET ROLE'
                     ELSE 'COLUMNS ONLY' END;
      via := CASE WHEN v_has THEN COALESCE(v_via, 'superuser')
                  WHEN v_set IS NOT NULL THEN format('SET ROLE %I', v_set)
                  ELSE 'column grants: ' || v_cols END;
      missing := NULLIF(concat_ws(', ',
                   CASE WHEN NOT v_schema THEN format('USAGE on schema %I', o.schema_name) END,
                   CASE WHEN NOT v_conn THEN format('CONNECT on database %I', current_database()) END), '');
      RETURN NEXT;
    END LOOP;
  END LOOP;
  IF NOT v_found THEN
    RAISE EXCEPTION 'pg-access-inspector: object "%" not found in database %', p_object, current_database()
      USING HINT = 'Schema-qualify the name or pass object_type.';
  END IF;
END
$fn$;

-- ---------------------------------------------------------------------------
-- 6. access_red_flags([role]): problems with one role (or every role)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.access_red_flags(p_role text DEFAULT NULL)
RETURNS TABLE(role_name text, severity text, flag text, detail text, suggested_fix text)
LANGUAGE plpgsql STABLE SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $fn$
#variable_conflict use_column
DECLARE
  v_one  oid;
  v_pg16 boolean := current_setting('server_version_num')::int >= 160000;
BEGIN
  IF p_role IS NOT NULL THEN
    v_one := public.access__role(p_role);
  END IF;
  RETURN QUERY
  WITH tgt AS (
    SELECT r.* FROM pg_roles r
     WHERE (v_one IS NULL AND r.rolname !~ '^pg_') OR r.oid = v_one
  ),
  w AS (
    SELECT t.oid AS tid, w.*
      FROM tgt t, public.access__walk(t.oid, 'up') w
     WHERE w.depth > 0
  ),
  reach AS (
    SELECT t.oid AS tid, x.*
      FROM tgt t, public.access__reach(t.oid) x
     WHERE x.depth > 0
  ),
  flags AS (
    SELECT t.rolname::text AS rn, CASE WHEN t.oid = 10 THEN 3 ELSE 1 END AS sev, 'SUPERUSER' AS flag,
           'bypasses every privilege check, RLS included'
             || CASE WHEN t.oid = 10 THEN ' (bootstrap superuser, expected)' ELSE '' END AS detail,
           CASE WHEN t.oid <> 10 THEN format('ALTER ROLE %I NOSUPERUSER;', t.rolname) END AS fix
      FROM tgt t WHERE t.rolsuper
    UNION ALL
    SELECT t.rolname, 1, 'superuser via membership',
           format('can SET ROLE %s (a superuser) through %s', rc.role_name, rc.path_text),
           format('REVOKE %I FROM %I;', split_part(rc.path_text, ' → ', 2), t.rolname)
      FROM tgt t JOIN reach rc ON rc.tid = t.oid
      JOIN pg_roles s ON s.oid = rc.roleid
     WHERE s.rolsuper AND rc.settable
    UNION ALL
    SELECT t.rolname, 1, 'rds_superuser in chain',
           format('%s rds_superuser through %s',
                  CASE WHEN rc.inherits THEN 'inherits' ELSE 'can SET ROLE' END, rc.path_text),
           format('REVOKE %I FROM %I;', split_part(rc.path_text, ' → ', 2), t.rolname)
      FROM tgt t JOIN reach rc ON rc.tid = t.oid
     WHERE rc.role_name = 'rds_superuser' AND (rc.inherits OR rc.settable)
    UNION ALL
    SELECT t.rolname, 1, 'membership cycle',
           'roles grant each other in a loop: ' || w.path_text, NULL
      FROM tgt t JOIN w ON w.tid = t.oid
     WHERE w.is_cycle
    UNION ALL
    SELECT t.rolname, 2, 'NOINHERIT breaks the chain',
           format('privileges of %s are not inherited (path %s); they apply only after SET ROLE %s',
                  rc.role_name, rc.path_text, rc.role_name),
           CASE WHEN v_pg16
                THEN format('GRANT %I TO %I WITH INHERIT TRUE;  -- at the hop that does not inherit',
                            split_part(public.access__break(rc.path), '|', 2), split_part(public.access__break(rc.path), '|', 1))
                ELSE format('ALTER ROLE %I INHERIT;', split_part(public.access__break(rc.path), '|', 1)) END
      FROM tgt t JOIN reach rc ON rc.tid = t.oid
     WHERE NOT rc.inherits AND rc.settable
    UNION ALL
    SELECT t.rolname, 2, 'membership grants nothing',
           format('member of %s with neither INHERIT nor SET (path %s)', rc.role_name, rc.path_text),
           format('GRANT %I TO %I WITH INHERIT TRUE;  -- or SET TRUE, or REVOKE it',
                  split_part(public.access__break(rc.path), '|', 2), split_part(public.access__break(rc.path), '|', 1))
      FROM tgt t JOIN reach rc ON rc.tid = t.oid
     WHERE NOT rc.inherits AND NOT rc.settable
    UNION ALL
    SELECT t.rolname, 1, 'cannot CONNECT',
           format('login role without CONNECT on database %I', current_database()),
           format('GRANT CONNECT ON DATABASE %I TO %I;', current_database(), t.rolname)
      FROM tgt t
     WHERE t.rolcanlogin AND NOT t.rolsuper AND NOT has_database_privilege(t.oid, current_database(), 'CONNECT')
    UNION ALL
    SELECT t.rolname, 1, 'password expired',
           format('VALID UNTIL %s is in the past: password logins fail', t.rolvaliduntil),
           format('ALTER ROLE %I VALID UNTIL ''infinity'';', t.rolname)
      FROM tgt t WHERE t.rolcanlogin AND t.rolvaliduntil < now()
    UNION ALL
    SELECT t.rolname, 2, 'password expires soon',
           format('VALID UNTIL %s is within 14 days', t.rolvaliduntil), NULL
      FROM tgt t WHERE t.rolcanlogin AND t.rolvaliduntil >= now() AND t.rolvaliduntil < now() + interval '14 days'
    UNION ALL
    SELECT t.rolname, 1, 'connection limit 0', 'CONNECTION LIMIT 0: every login is refused',
           format('ALTER ROLE %I CONNECTION LIMIT -1;', t.rolname)
      FROM tgt t WHERE t.rolcanlogin AND t.rolconnlimit = 0
    UNION ALL
    SELECT t.rolname, 3, 'NOLOGIN',
           CASE WHEN EXISTS (SELECT 1 FROM pg_auth_members m WHERE m.roleid = t.oid)
                THEN 'group role: nobody logs in as it; its members use its privileges'
                ELSE 'NOLOGIN and no members: grants to it reach nobody (expected for an owner-only role)' END,
           NULL
      FROM tgt t
     WHERE NOT t.rolcanlogin
       AND (v_one IS NOT NULL OR NOT EXISTS (SELECT 1 FROM pg_auth_members m WHERE m.roleid = t.oid))
    UNION ALL
    SELECT t.rolname, CASE WHEN t.rolname IN ('rds_superuser', 'rdsadmin') THEN 3 ELSE 2 END, 'BYPASSRLS',
           'ignores every row level security policy'
             || CASE WHEN t.rolname IN ('rds_superuser', 'rdsadmin') THEN ' (managed by AWS RDS)' ELSE '' END,
           CASE WHEN t.rolname NOT IN ('rds_superuser', 'rdsadmin') THEN format('ALTER ROLE %I NOBYPASSRLS;', t.rolname) END
      FROM tgt t WHERE t.rolbypassrls AND NOT t.rolsuper
    UNION ALL
    SELECT t.rolname, CASE WHEN t.rolname IN ('rds_superuser', 'rdsadmin') THEN 3 ELSE 2 END, 'CREATEROLE',
           'can create roles (and before PG16, grant itself almost any role)'
             || CASE WHEN t.rolname IN ('rds_superuser', 'rdsadmin') THEN ' (managed by AWS RDS)' ELSE '' END,
           CASE WHEN t.rolname NOT IN ('rds_superuser', 'rdsadmin') THEN format('ALTER ROLE %I NOCREATEROLE;', t.rolname) END
      FROM tgt t WHERE t.rolcreaterole AND NOT t.rolsuper
    UNION ALL
    SELECT t.rolname, 2, 'reads/writes all data',
           format('%s %s through %s', CASE WHEN rc.inherits THEN 'inherits' ELSE 'can SET ROLE' END, rc.role_name, rc.path_text),
           NULL
      FROM tgt t JOIN reach rc ON rc.tid = t.oid
     WHERE rc.role_name IN ('pg_read_all_data', 'pg_write_all_data') AND (rc.inherits OR rc.settable)
  )
  SELECT f.rn,
         CASE f.sev WHEN 1 THEN 'HIGH' WHEN 2 THEN 'MEDIUM' ELSE 'INFO' END,
         f.flag, f.detail, f.fix
    FROM flags f
   ORDER BY f.sev, f.rn, f.flag, f.detail;
  IF NOT FOUND AND v_one IS NOT NULL THEN
    role_name := p_role; severity := 'OK'; flag := 'no red flags'; detail := NULL; suggested_fix := NULL;
    RETURN NEXT;
  END IF;
END
$fn$;

-- ---------------------------------------------------------------------------
-- 7. access_explain_error(error_text [, role [, action]])
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.access_explain_error(p_error text, p_role text DEFAULT current_user,
                                                       p_action text DEFAULT NULL)
RETURNS TABLE(step integer, finding text, detail text, suggested_fix text)
LANGUAGE plpgsql STABLE SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $fn$
#variable_conflict use_column
DECLARE
  v_role    oid := public.access__role(p_role);
  v_rname   text;
  v_pg16    boolean := current_setting('server_version_num')::int >= 160000;
  v_txt     text := regexp_replace(COALESCE(p_error, ''), '\s+', ' ', 'g');
  v_stmt    text;
  v_kw      text;
  m         text[];
  v_mode    text;
  v_word    text;
  v_name    text;
  v_col     text;
  v_type    text;
  v_actions text[];
  v_lacking text[];
  v_note    text;
  v_n       integer := 0;
  v_fixes   text[] := ARRAY[]::text[];
  o         record;
  w         record;
  v_objs    integer;
  v_names   text;
  v_qn      text := '("(?:[^"]|"")+"|[^ ,;]+)';
  v_ambig   boolean;
  v_held    text;
  v_missing text[];
BEGIN
  SELECT quote_ident(rolname) INTO v_rname FROM pg_roles WHERE oid = v_role;
  v_stmt := substring(v_txt FROM '(?i)STATEMENT: ?(.*)$');
  v_kw := upper(substring(COALESCE(v_stmt, '') FROM '^[ (]*([A-Za-z]+)'));

  m := regexp_match(v_txt, 'permission denied for column ' || v_qn || ' of (?:relation|table) ' || v_qn, 'i');
  IF m IS NOT NULL THEN
    v_mode := 'privilege'; v_word := 'column'; v_col := m[1]; v_name := m[2];
  END IF;
  IF v_mode IS NULL THEN
    m := regexp_match(v_txt, 'permission denied for (table|relation|view|materialized view|sequence|schema|database|function|procedure|routine|aggregate|foreign table) ' || v_qn, 'i');
    IF m IS NOT NULL THEN v_mode := 'privilege'; v_word := lower(m[1]); v_name := m[2]; END IF;
  END IF;
  IF v_mode IS NULL THEN
    m := regexp_match(v_txt, 'must be (?:the )?owner of (table|relation|view|materialized view|sequence|schema|database|function|procedure|routine|aggregate|foreign table) ' || v_qn, 'i');
    IF m IS NOT NULL THEN v_mode := 'owner'; v_word := lower(m[1]); v_name := m[2]; END IF;
  END IF;
  IF v_mode IS NULL THEN
    m := regexp_match(v_txt, 'permission denied to set role ' || v_qn, 'i');
    IF m IS NOT NULL THEN v_mode := 'setrole'; v_name := m[1]; END IF;
  END IF;
  IF v_mode IS NULL THEN
    m := regexp_match(v_txt, 'new row violates row-level security policy (?:"[^"]*" )?for table ' || v_qn, 'i');
    IF m IS NOT NULL THEN v_mode := 'rls'; v_word := 'table'; v_name := m[1]; END IF;
  END IF;

  IF v_mode IS NULL THEN
    step := 1; finding := 'error not recognised';
    detail := 'supported: "permission denied for <table|view|sequence|schema|database|function|column ...> <name>", '
              || '"must be owner of <type> <name>", "permission denied to set role <name>", '
              || '"new row violates row-level security policy for table <name>"';
    suggested_fix := NULL;
    RETURN NEXT;
    RETURN;
  END IF;

  v_name := regexp_replace(v_name, '[.:]+$', '');
  IF v_col IS NOT NULL THEN v_col := btrim(v_col, '"'); END IF;
  v_type := CASE v_word
              WHEN 'table' THEN 'relation' WHEN 'relation' THEN 'relation' WHEN 'column' THEN 'relation'
              WHEN 'function' THEN 'function' WHEN 'procedure' THEN 'function' WHEN 'routine' THEN 'function'
              WHEN 'aggregate' THEN 'function'
              ELSE v_word END;

  v_n := v_n + 1; step := v_n; finding := 'parsed';
  detail := format('%s on %s %s%s, checked for role %s',
                   CASE v_mode WHEN 'privilege' THEN 'missing privilege' WHEN 'owner' THEN 'needs ownership'
                               WHEN 'setrole' THEN 'SET ROLE refused' ELSE 'row level security rejected a row' END,
                   COALESCE(v_word, 'role'), v_name, COALESCE(' column ' || v_col, ''), v_rname);
  suggested_fix := NULL;
  RETURN NEXT;

  -- SET ROLE refused: membership question, no object to resolve
  IF v_mode = 'setrole' THEN
    v_name := btrim(v_name, '"');
    v_n := v_n + 1; step := v_n;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = v_name) THEN
      finding := 'role not found'; detail := format('role %s does not exist', v_name); suggested_fix := NULL;
    ELSIF pg_has_role(v_role, (SELECT oid FROM pg_roles WHERE rolname = v_name), 'MEMBER') THEN
      finding := 'member without SET';
      detail := format('%s is a member of %s, but the membership chain does not allow SET ROLE (PG16+ SET FALSE)', v_rname, v_name);
      suggested_fix := format('GRANT %I TO %s WITH SET TRUE;', v_name, v_rname);
    ELSE
      finding := 'not a member';
      detail := format('%s is not a member of %s, directly or through any role', v_rname, v_name);
      suggested_fix := format('GRANT %I TO %s%s;', v_name, v_rname, CASE WHEN v_pg16 THEN ' WITH SET TRUE' ELSE '' END);
    END IF;
    RETURN NEXT;
    RETURN;
  END IF;

  SELECT count(*), string_agg(x.display || ' (' || x.kind || ')', ', ')
    INTO v_objs, v_names
    FROM public.access__objects(v_name, v_type) x;
  v_n := v_n + 1; step := v_n; finding := 'object';
  detail := CASE WHEN v_objs = 0 THEN format('no %s named %s in database %s: the error may come from another database, or the object was renamed/dropped',
                                             COALESCE(v_word, 'object'), v_name, current_database())
                 WHEN v_objs = 1 THEN v_names
                 ELSE 'name matches several objects, all checked: ' || v_names END;
  suggested_fix := NULL;
  RETURN NEXT;
  IF v_objs = 0 THEN
    RETURN;
  END IF;

  -- ownership
  IF v_mode = 'owner' THEN
    FOR o IN SELECT * FROM public.access__objects(v_name, v_type) LOOP
      v_n := v_n + 1; step := v_n;
      IF pg_has_role(v_role, o.owner_oid, 'USAGE') THEN
        finding := 'already acts as owner';
        detail := format('%s inherits the owner %s of %s; the failing session probably used another role',
                         v_rname, (SELECT rolname FROM pg_roles WHERE oid = o.owner_oid), o.display);
        suggested_fix := NULL;
      ELSE
        finding := 'not the owner';
        detail := format('%s is owned by %s; ALTER, DROP and similar commands need ownership (or inheriting the owner role)',
                         o.display, (SELECT rolname FROM pg_roles WHERE oid = o.owner_oid));
        suggested_fix := format('GRANT %I TO %s;  -- act as the owner role', (SELECT rolname FROM pg_roles WHERE oid = o.owner_oid), v_rname)
                         || E'\n' || format('ALTER %s %s OWNER TO %s;  -- or transfer ownership',
                                            public.access__keyword(o.kind, true), o.display, v_rname);
        v_fixes := v_fixes || suggested_fix;
      END IF;
      RETURN NEXT;
    END LOOP;
    v_n := v_n + 1; step := v_n; finding := 'fix (review, then run it yourself)';
    detail := NULL; suggested_fix := NULLIF(array_to_string(v_fixes, E'\n'), '');
    RETURN NEXT;
    RETURN;
  END IF;

  -- which action?
  IF p_action IS NOT NULL THEN
    v_actions := ARRAY[upper(btrim(p_action))];
    v_note := 'given by the caller';
  ELSIF v_mode = 'rls' THEN
    v_actions := ARRAY[CASE WHEN v_kw = 'UPDATE' THEN 'UPDATE' ELSE 'INSERT' END];
    v_note := 'new rows are checked on ' || v_actions[1];
  ELSIF v_word = 'database' THEN
    v_note := CASE WHEN v_txt ~* 'CONNECT privilege' THEN 'from the DETAIL line' END;
    v_actions := CASE WHEN v_txt ~* 'CONNECT privilege' THEN ARRAY['CONNECT']
                      WHEN v_kw = 'CREATE' AND v_stmt ~* '\mTEMP(ORARY)?\M' THEN ARRAY['TEMPORARY']
                      WHEN v_kw = 'CREATE' THEN ARRAY['CREATE']
                      ELSE ARRAY['CONNECT', 'CREATE', 'TEMPORARY'] END;
  ELSIF v_word = 'schema' THEN
    v_actions := CASE WHEN v_kw IN ('CREATE', 'ALTER') THEN ARRAY['CREATE']
                      WHEN v_kw IS NOT NULL THEN ARRAY['USAGE']
                      ELSE ARRAY['USAGE', 'CREATE'] END;
  ELSIF v_word = 'sequence' THEN
    v_actions := CASE WHEN v_stmt ~* 'setval' THEN ARRAY['UPDATE']
                      WHEN v_stmt ~* 'nextval|INSERT' THEN ARRAY['USAGE']
                      WHEN v_stmt ~* 'currval|SELECT' THEN ARRAY['SELECT']
                      ELSE ARRAY['USAGE', 'SELECT', 'UPDATE'] END;
  ELSIF v_type = 'function' THEN
    v_actions := ARRAY['EXECUTE'];
  ELSE
    v_actions := CASE
                   WHEN v_kw IN ('SELECT', 'TABLE', 'WITH') THEN ARRAY['SELECT']
                   WHEN v_kw IN ('INSERT', 'UPDATE', 'DELETE', 'TRUNCATE') THEN ARRAY[v_kw]
                   WHEN v_kw = 'COPY' AND v_stmt ~* '\mFROM\M' THEN ARRAY['INSERT']
                   WHEN v_kw = 'COPY' THEN ARRAY['SELECT']
                   WHEN v_kw = 'LOCK' THEN ARRAY['UPDATE', 'DELETE', 'TRUNCATE']
                   WHEN v_col IS NOT NULL THEN ARRAY['SELECT', 'INSERT', 'UPDATE', 'REFERENCES']
                   ELSE ARRAY['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER'] END;
  END IF;
  IF v_note IS NULL THEN
    v_note := CASE WHEN array_length(v_actions, 1) = 1 AND v_stmt IS NOT NULL THEN 'taken from the STATEMENT'
                   WHEN array_length(v_actions, 1) = 1 THEN 'the only privilege for this object type'
                   ELSE NULL END;
  END IF;

  -- keep only actions the role really lacks on at least one matching object
  SELECT array_agg(a ORDER BY ord) INTO v_lacking
    FROM unnest(v_actions) WITH ORDINALITY AS u(a, ord)
   WHERE EXISTS (SELECT 1 FROM public.access__objects(v_name, v_type) x
                  WHERE a = ANY (public.access__valid_privs(x.kind))
                    AND (public.access__has(v_role, x.kind, x.obj_oid, a) IS NOT TRUE
                         OR (x.schema_oid IS NOT NULL AND NOT has_schema_privilege(v_role, x.schema_oid, 'USAGE'))
                         OR v_mode = 'rls'));

  v_ambig := array_length(v_lacking, 1) > 1 AND v_note IS NULL;
  SELECT string_agg(DISTINCT a, ', '), NULL INTO v_held, v_missing
    FROM unnest(v_actions) AS a
   WHERE EXISTS (SELECT 1 FROM public.access__objects(v_name, v_type) x
                  WHERE a = ANY (public.access__valid_privs(x.kind))
                    AND public.access__has(v_role, x.kind, x.obj_oid, a));
  SELECT array_agg(a ORDER BY ord) INTO v_missing
    FROM unnest(v_lacking) WITH ORDINALITY AS u(a, ord)
   WHERE EXISTS (SELECT 1 FROM public.access__objects(v_name, v_type) x
                  WHERE a = ANY (public.access__valid_privs(x.kind))
                    AND public.access__has(v_role, x.kind, x.obj_oid, a) IS NOT TRUE);

  v_n := v_n + 1; step := v_n; finding := 'action'; suggested_fix := NULL;
  IF v_lacking IS NULL THEN
    detail := format('%s already has %s here; the failing session likely ran as a different role (check current_user, SET ROLE, or a SECURITY DEFINER function)',
                     v_rname, array_to_string(v_actions, '/'));
    RETURN NEXT;
    RETURN;
  ELSIF v_note IS NOT NULL THEN
    detail := array_to_string(v_lacking, ', ') || ' (' || v_note || ')';
  ELSE
    detail := format('ambiguous: the message does not name the action. %s%s lacks: %s. Pass the action as the 3rd argument, or include the STATEMENT: line, to narrow it down',
                     COALESCE(v_rname || ' has: ' || v_held || '; ', ''), v_rname,
                     COALESCE(array_to_string(v_missing, ', '), 'none of them (see the checks below)'));
  END IF;
  RETURN NEXT;

  -- causes: every failing check of access_why, de-duplicated across actions
  FOR w IN
    SELECT DISTINCT ON (q.check_name, q.detail) q.*
      FROM (
        SELECT x.display, a.act, y.step AS wstep, y.check_name, y.result, y.detail, y.suggested_fix, a.ord
          FROM public.access__objects(v_name, v_type) x
          CROSS JOIN unnest(v_lacking) WITH ORDINALITY AS a(act, ord)
          CROSS JOIN LATERAL public.access_why(p_role, x.display, a.act, x.kind) y
         WHERE a.act = ANY (public.access__valid_privs(x.kind))
           AND y.check_name <> 'answer'
           AND (y.result IN ('FAIL', 'WARN', 'ERROR') OR (v_mode = 'rls' AND y.check_name = 'row level security'))
           -- RLS never raises "permission denied"; it matters only for RLS errors
           AND (y.check_name <> 'row level security' OR v_mode = 'rls')
           -- for an ambiguous action, one combined GRANT line replaces the per-action ones
           AND NOT (v_ambig AND y.check_name LIKE '% privilege' AND y.result = 'FAIL')
      ) q
     ORDER BY q.check_name, q.detail, q.ord
  LOOP
    v_n := v_n + 1; step := v_n;
    finding := CASE WHEN w.check_name LIKE '% privilege' OR w.check_name IN ('column grants', 'row level security')
                    THEN w.check_name || ' on ' || w.display ELSE w.check_name END
               || ': ' || w.result;
    detail := w.detail;
    suggested_fix := w.suggested_fix;
    IF w.suggested_fix IS NOT NULL AND NOT (w.suggested_fix = ANY (v_fixes)) THEN
      v_fixes := v_fixes || w.suggested_fix;
    END IF;
    RETURN NEXT;
  END LOOP;

  IF v_ambig AND v_missing IS NOT NULL THEN
    FOR o IN SELECT * FROM public.access__objects(v_name, v_type) LOOP
      v_fixes := v_fixes || format('GRANT %s ON %s %s TO %s;  -- keep only the action the statement needs',
                                   array_to_string(v_missing, ' | '), public.access__keyword(o.kind), o.display, v_rname);
    END LOOP;
  END IF;
  v_n := v_n + 1; step := v_n; finding := 'fix (review, then run it yourself)';
  detail := CASE WHEN v_ambig THEN 'the action is a guess list: pick one before running' ELSE NULL END;
  suggested_fix := NULLIF(array_to_string(v_fixes, E'\n'), '');
  RETURN NEXT;
END
$fn$;

-- ---------------------------------------------------------------------------
-- 8. access_compare(role_a, role_b [, object]): what one has and the other lacks
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.access_compare(p_role_a text, p_role_b text, p_object text DEFAULT NULL)
RETURNS TABLE(category text, item text, role_a text, role_b text)
LANGUAGE sql STABLE SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $fn$
  WITH ids AS (SELECT public.access__role(p_role_a) AS a, public.access__role(p_role_b) AS b),
  ma AS (SELECT x.role_name, x.path_text,
                CASE WHEN x.inherits THEN 'inherited' WHEN x.settable THEN 'SET ROLE only' ELSE 'member, unusable' END AS m
           FROM ids, public.access__reach(ids.a) x WHERE x.depth > 0),
  mb AS (SELECT x.role_name, x.path_text,
                CASE WHEN x.inherits THEN 'inherited' WHEN x.settable THEN 'SET ROLE only' ELSE 'member, unusable' END AS m
           FROM ids, public.access__reach(ids.b) x WHERE x.depth > 0),
  mem AS (
    SELECT 1 AS ord, 'membership'::text AS category, COALESCE(ma.role_name, mb.role_name) AS item,
           COALESCE(ma.m || ' (' || ma.path_text || ')', '-') AS role_a,
           COALESCE(mb.m || ' (' || mb.path_text || ')', '-') AS role_b
      FROM ma FULL JOIN mb ON mb.role_name = ma.role_name
     WHERE ma.m IS DISTINCT FROM mb.m
  ),
  attrs AS (
    SELECT 0 AS ord, 'attribute'::text AS category, k.key AS item, k.va AS role_a, k.vb AS role_b
      FROM ids
      JOIN pg_roles ra ON ra.oid = ids.a
      JOIN pg_roles rb ON rb.oid = ids.b
      CROSS JOIN LATERAL (VALUES
        ('LOGIN', ra.rolcanlogin::text, rb.rolcanlogin::text),
        ('SUPERUSER', ra.rolsuper::text, rb.rolsuper::text),
        ('INHERIT', ra.rolinherit::text, rb.rolinherit::text),
        ('CREATEROLE', ra.rolcreaterole::text, rb.rolcreaterole::text),
        ('CREATEDB', ra.rolcreatedb::text, rb.rolcreatedb::text),
        ('BYPASSRLS', ra.rolbypassrls::text, rb.rolbypassrls::text),
        ('CONNECTION LIMIT', ra.rolconnlimit::text, rb.rolconnlimit::text),
        ('VALID UNTIL', COALESCE(ra.rolvaliduntil::text, 'never'), COALESCE(rb.rolvaliduntil::text, 'never'))
      ) AS k(key, va, vb)
     WHERE k.va IS DISTINCT FROM k.vb
  ),
  want_obj AS (
    SELECT x.display AS nm FROM public.access__objects(p_object) x WHERE p_object IS NOT NULL
  ),
  want AS (
    SELECT nm FROM want_obj
    UNION
    SELECT quote_ident(x.schema_name) FROM public.access__objects(p_object) x
     WHERE p_object IS NOT NULL AND x.schema_name IS NOT NULL
    UNION
    SELECT quote_ident(current_database()) WHERE p_object IS NOT NULL
  ),
  pa AS (
    SELECT p.object_type, p.object_name, p.privilege,
           CASE WHEN bool_or(p.how NOT IN ('needs SET ROLE', 'not usable')) THEN 'yes' ELSE 'after SET ROLE' END AS lvl,
           string_agg(DISTINCT p.source_role || ' [' || p.how || ']', ', ') AS src
      FROM public.access_privileges(p_role_a, true) p
     WHERE p.how <> 'not usable'
       AND (p_object IS NULL OR p.object_name IN (SELECT nm FROM want) OR p.object_name LIKE ANY (SELECT nm || '.%' FROM want_obj))
     GROUP BY 1, 2, 3
  ),
  pb AS (
    SELECT p.object_type, p.object_name, p.privilege,
           CASE WHEN bool_or(p.how NOT IN ('needs SET ROLE', 'not usable')) THEN 'yes' ELSE 'after SET ROLE' END AS lvl,
           string_agg(DISTINCT p.source_role || ' [' || p.how || ']', ', ') AS src
      FROM public.access_privileges(p_role_b, true) p
     WHERE p.how <> 'not usable'
       AND (p_object IS NULL OR p.object_name IN (SELECT nm FROM want) OR p.object_name LIKE ANY (SELECT nm || '.%' FROM want_obj))
     GROUP BY 1, 2, 3
  ),
  privs AS (
    SELECT 2 AS ord, 'privilege'::text AS category,
           COALESCE(pa.privilege, pb.privilege) || ' on ' || COALESCE(pa.object_type, pb.object_type) || ' '
             || COALESCE(pa.object_name, pb.object_name) AS item,
           COALESCE(pa.lvl || ' via ' || pa.src, '-') AS role_a,
           COALESCE(pb.lvl || ' via ' || pb.src, '-') AS role_b
      FROM pa FULL JOIN pb
        ON pb.object_type = pa.object_type AND pb.object_name = pa.object_name AND pb.privilege = pa.privilege
     WHERE pa.lvl IS DISTINCT FROM pb.lvl
  )
  SELECT u.category, u.item, u.role_a, u.role_b
    FROM (SELECT * FROM attrs UNION ALL SELECT * FROM mem UNION ALL SELECT * FROM privs) u
   ORDER BY u.ord, u.item
$fn$;

-- ---------------------------------------------------------------------------
-- 9. access_tree(role [, direction]) and access_tree_mermaid(role [, direction])
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.access__tree_lines(p_node oid, p_direction text, p_prefix text, p_visited oid[])
RETURNS SETOF text
LANGUAGE plpgsql STABLE SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  c      record;
  v_n    integer;
  v_i    integer := 0;
  v_last boolean;
  v_flags text;
BEGIN
  SELECT count(*) INTO v_n FROM public.access__edges() e
   WHERE CASE WHEN p_direction = 'down' THEN e.roleid ELSE e.member END = p_node;
  FOR c IN
    SELECT CASE WHEN p_direction = 'down' THEN e.member ELSE e.roleid END AS child,
           e.inherit_option, e.set_option, e.admin_option, r.rolname, r.rolcanlogin, r.rolsuper, r.rolbypassrls
      FROM public.access__edges() e
      JOIN pg_roles r ON r.oid = CASE WHEN p_direction = 'down' THEN e.member ELSE e.roleid END
     WHERE CASE WHEN p_direction = 'down' THEN e.roleid ELSE e.member END = p_node
     ORDER BY r.rolname
  LOOP
    v_i := v_i + 1;
    v_last := v_i = v_n;
    v_flags := concat_ws(', ',
                 CASE WHEN NOT c.inherit_option AND NOT c.set_option THEN 'no INHERIT, no SET: grants nothing'
                      WHEN NOT c.inherit_option THEN 'NOINHERIT: needs SET ROLE'
                      WHEN NOT c.set_option THEN 'no SET ROLE' END,
                 CASE WHEN c.admin_option THEN 'ADMIN' END,
                 CASE WHEN p_direction = 'down' AND c.rolcanlogin THEN 'login' END,
                 CASE WHEN c.rolsuper THEN 'SUPERUSER' END,
                 CASE WHEN c.rolbypassrls THEN 'BYPASSRLS' END,
                 CASE WHEN c.rolname = 'rds_superuser' THEN 'RDS SUPERUSER' END);
    IF c.child = ANY (p_visited) THEN
      RETURN NEXT p_prefix || CASE WHEN v_last THEN '└── ' ELSE '├── ' END || c.rolname || '  (CYCLE: stops here)';
      CONTINUE;
    END IF;
    RETURN NEXT p_prefix || CASE WHEN v_last THEN '└── ' ELSE '├── ' END || c.rolname
                || CASE WHEN v_flags <> '' THEN '  [' || v_flags || ']' ELSE '' END;
    IF array_length(p_visited, 1) < 64 THEN
      RETURN QUERY SELECT * FROM public.access__tree_lines(c.child, p_direction,
                                    p_prefix || CASE WHEN v_last THEN '    ' ELSE '│   ' END,
                                    p_visited || c.child);
    END IF;
  END LOOP;
END
$fn$;

CREATE OR REPLACE FUNCTION public.access_tree(p_role text, p_direction text DEFAULT 'up')
RETURNS TABLE(tree text)
LANGUAGE plpgsql STABLE SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $fn$
#variable_conflict use_column
DECLARE
  v_role oid := public.access__role(p_role);
  v_dir  text := lower(COALESCE(p_direction, 'up'));
  rl     record;
BEGIN
  IF v_dir NOT IN ('up', 'down') THEN
    RAISE EXCEPTION 'pg-access-inspector: direction must be up (what it belongs to) or down (who is under it)';
  END IF;
  SELECT * INTO rl FROM pg_roles WHERE oid = v_role;
  tree := rl.rolname || '  ('
          || concat_ws(', ', CASE WHEN rl.rolcanlogin THEN 'LOGIN' ELSE 'NOLOGIN' END,
                       CASE WHEN rl.rolsuper THEN 'SUPERUSER' END,
                       CASE WHEN NOT rl.rolinherit THEN 'NOINHERIT' END,
                       CASE WHEN v_dir = 'up' THEN 'member of ↓' ELSE 'members ↓' END) || ')';
  RETURN NEXT;
  RETURN QUERY SELECT * FROM public.access__tree_lines(v_role, v_dir, '', ARRAY[v_role]);
END
$fn$;

CREATE OR REPLACE FUNCTION public.access_tree_mermaid(p_role text, p_direction text DEFAULT 'up')
RETURNS text
LANGUAGE sql STABLE SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $fn$
  WITH root AS (SELECT public.access__role(p_role) AS id,
                       CASE WHEN lower(COALESCE(p_direction, 'up')) = 'down' THEN 'down' ELSE 'up' END AS dir),
  nodes AS (
    SELECT DISTINCT w.roleid FROM root, public.access__walk(root.id, root.dir) w
  ),
  edges AS (
    SELECT DISTINCT e.member, e.roleid, e.inherit_option, e.set_option
      FROM public.access__edges() e
     WHERE e.member IN (SELECT roleid FROM nodes) AND e.roleid IN (SELECT roleid FROM nodes)
  ),
  lines AS (
    SELECT 1 AS ord, format('    r%s["%s"]', r.oid, replace(r.rolname, '"', '#quot;')) AS line, r.rolname::text AS k
      FROM nodes n JOIN pg_roles r ON r.oid = n.roleid
    UNION ALL
    SELECT 2, format('    r%s %s r%s', e.member,
                     CASE WHEN e.inherit_option THEN '-->'
                          WHEN e.set_option THEN '-. "SET ROLE" .->'
                          ELSE '-. "no INHERIT/SET" .->' END,
                     e.roleid), mr.rolname || '>' || gr.rolname
      FROM edges e JOIN pg_roles mr ON mr.oid = e.member JOIN pg_roles gr ON gr.oid = e.roleid
    UNION ALL
    SELECT 3, format('    class r%s %s', r.oid,
                     CASE WHEN r.rolsuper OR r.rolname = 'rds_superuser' THEN 'danger'
                          WHEN r.oid = (SELECT id FROM root) THEN 'start'
                          WHEN r.rolcanlogin THEN 'login' ELSE 'grp' END), r.rolname
      FROM nodes n JOIN pg_roles r ON r.oid = n.roleid
  )
  SELECT 'graph BT' || E'\n'
         || string_agg(l.line, E'\n' ORDER BY l.ord, l.k) || E'\n'
         || '    classDef start fill:#fff3bf,stroke:#e8a400,stroke-width:2px' || E'\n'
         || '    classDef login fill:#e7f5ff,stroke:#1c7ed6' || E'\n'
         || '    classDef grp fill:#f1f3f5,stroke:#868e96' || E'\n'
         || '    classDef danger fill:#ffe3e3,stroke:#e03131,stroke-width:2px'
    FROM lines l
$fn$;

-- ---------------------------------------------------------------------------
-- 10. access_risky([max_depth]): database-wide risky access finder
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.access_risky(p_max_depth integer DEFAULT 5)
RETURNS TABLE(severity text, category text, name text, detail text, suggested_fix text)
LANGUAGE sql STABLE SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $fn$
  WITH rel AS (
    SELECT c.oid, c.relkind, format('%I.%I', n.nspname, c.relname) AS nm, c.relacl,
           EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid
                                             AND d.deptype = 'e') AS ext
      FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f') AND c.relacl IS NOT NULL
       AND NOT public.access__is_system_schema(n.nspname)
  ),
  edges AS (SELECT e.member, e.roleid FROM public.access__edges() e),
  cyc AS (
    WITH RECURSIVE w(start, cur, path, closed) AS (
      SELECT e.member, e.roleid, ARRAY[e.member, e.roleid], e.member = e.roleid FROM edges e
      UNION ALL
      SELECT w.start, e.roleid, w.path || e.roleid, e.roleid = w.start
        FROM w JOIN edges e ON e.member = w.cur
       WHERE NOT w.closed AND NOT (e.roleid = ANY (w.path[2:])) AND array_length(w.path, 1) < 64
    )
    SELECT DISTINCT ON (w.start) w.start, w.path FROM w WHERE w.closed ORDER BY w.start, array_length(w.path, 1)
  ),
  findings AS (
    -- PUBLIC grants on relations
    SELECT CASE WHEN rel.ext THEN 3 WHEN a.privilege_type = 'SELECT' THEN 2 ELSE 1 END AS sev,
           'PUBLIC grant' AS category, rel.nm AS name,
           format('PUBLIC (every role) has %s on %s %s%s', string_agg(a.privilege_type, ', ' ORDER BY a.privilege_type),
                  CASE rel.relkind WHEN 'S' THEN 'sequence' WHEN 'v' THEN 'view' WHEN 'm' THEN 'materialized view'
                                   WHEN 'f' THEN 'foreign table' ELSE 'table' END, rel.nm,
                  CASE WHEN rel.ext THEN ' (owned by an extension)' ELSE '' END) AS detail,
           format('REVOKE %s ON %s %s FROM PUBLIC;', string_agg(a.privilege_type, ', ' ORDER BY a.privilege_type),
                  CASE rel.relkind WHEN 'S' THEN 'SEQUENCE' ELSE 'TABLE' END, rel.nm) AS fix
      FROM rel, aclexplode(rel.relacl) a
     WHERE a.grantee = 0
     GROUP BY rel.nm, rel.relkind, rel.ext, (a.privilege_type = 'SELECT')
    UNION ALL
    -- PUBLIC CREATE / USAGE on schemas
    SELECT CASE WHEN a.privilege_type = 'CREATE' THEN 1 ELSE 3 END, 'PUBLIC grant', quote_ident(n.nspname),
           format('PUBLIC has %s on schema %I%s', a.privilege_type, n.nspname,
                  CASE WHEN a.privilege_type = 'CREATE' THEN ': any role can create objects here (PG14 default for public)' ELSE '' END),
           format('REVOKE %s ON SCHEMA %I FROM PUBLIC;', a.privilege_type, n.nspname)
      FROM pg_namespace n, aclexplode(n.nspacl) a
     WHERE a.grantee = 0 AND NOT public.access__is_system_schema(n.nspname)
       AND NOT (n.nspname = 'public' AND a.privilege_type = 'USAGE')
    UNION ALL
    -- PUBLIC CREATE on databases (CONNECT/TEMP to PUBLIC is the default and not flagged)
    SELECT 2, 'PUBLIC grant', quote_ident(d.datname),
           format('PUBLIC has CREATE on database %I: any role can create schemas', d.datname),
           format('REVOKE CREATE ON DATABASE %I FROM PUBLIC;', d.datname)
      FROM pg_database d, aclexplode(d.datacl) a
     WHERE a.grantee = 0 AND a.privilege_type = 'CREATE'
    UNION ALL
    -- SECURITY DEFINER functions anyone can run
    SELECT CASE WHEN ext.e THEN 3 ELSE 1 END, 'PUBLIC grant',
           p.oid::regprocedure::text,
           format('SECURITY DEFINER function owned by %s is executable by PUBLIC%s', o.rolname,
                  CASE WHEN ext.e THEN ' (owned by an extension)' ELSE '' END),
           format('REVOKE EXECUTE ON FUNCTION %s FROM PUBLIC;', p.oid::regprocedure)
      FROM pg_proc p
      JOIN pg_namespace n ON n.oid = p.pronamespace
      JOIN pg_roles o ON o.oid = p.proowner
      CROSS JOIN LATERAL (SELECT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_proc'::regclass
                                           AND d.objid = p.oid AND d.deptype = 'e') AS e) ext
     WHERE p.prosecdef AND NOT public.access__is_system_schema(n.nspname)
       AND EXISTS (SELECT 1 FROM aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) a
                    WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE')
    UNION ALL
    -- powerful role attributes
    SELECT CASE WHEN r.oid = 10 OR r.rolname IN ('rdsadmin', 'rds_superuser') THEN 4
                WHEN k.attr IN ('SUPERUSER') THEN 1 WHEN k.attr = 'CREATEDB' THEN 3 ELSE 2 END,
           'role attribute', r.rolname::text,
           format('%s%s%s', k.attr, CASE WHEN r.rolcanlogin THEN ' (login role)' ELSE '' END,
                  CASE WHEN r.oid = 10 THEN ' - bootstrap superuser, expected'
                       WHEN r.rolname IN ('rdsadmin', 'rds_superuser') THEN ' - managed by AWS RDS' ELSE '' END),
           CASE WHEN r.oid <> 10 AND r.rolname NOT IN ('rdsadmin', 'rds_superuser')
                THEN format('ALTER ROLE %I NO%s;', r.rolname, k.attr) END
      FROM pg_roles r
      CROSS JOIN LATERAL (VALUES ('SUPERUSER', r.rolsuper), ('CREATEROLE', r.rolcreaterole),
                                 ('CREATEDB', r.rolcreatedb), ('BYPASSRLS', r.rolbypassrls),
                                 ('REPLICATION', r.rolreplication)) AS k(attr, has)
     WHERE k.has AND r.rolname !~ '^pg_' AND (r.oid <> 10 OR k.attr = 'SUPERUSER')
    UNION ALL
    -- members of rds_superuser (direct or nested)
    SELECT 1, 'rds_superuser member', w.member_name,
           format('%s rds_superuser: %s', CASE WHEN w.inherits THEN 'inherits' ELSE 'can SET ROLE' END,
                  (SELECT string_agg(u.x, ' → ' ORDER BY u.n DESC)
                     FROM unnest(string_to_array(w.path_text, ' → ')) WITH ORDINALITY AS u(x, n))),
           NULL
      FROM pg_roles s
      CROSS JOIN LATERAL (
        SELECT DISTINCT ON (x.roleid) r.rolname::text AS member_name, x.inherits, x.path_text
          FROM public.access__walk(s.oid, 'down') x JOIN pg_roles r ON r.oid = x.roleid
         WHERE x.depth > 0 AND NOT x.is_cycle
         ORDER BY x.roleid, x.depth
      ) w
     WHERE s.rolname = 'rds_superuser'
    UNION ALL
    -- default privileges that can never fire
    SELECT CASE WHEN cr.oid IS NULL THEN 1 ELSE 3 END, 'default privileges',
           COALESCE(cr.rolname::text, format('(role oid %s)', da.defaclrole)),
           CASE WHEN cr.oid IS NULL
                THEN format('default privileges in %s belong to a role that no longer exists',
                            COALESCE(quote_ident(n.nspname), 'all schemas'))
                ELSE format('creator %s owns no %s in %s yet, so these defaults have not applied to anything: check the right role creates objects',
                            cr.rolname,
                            CASE da.defaclobjtype WHEN 'r' THEN 'tables' WHEN 'S' THEN 'sequences' WHEN 'f' THEN 'functions'
                                                  WHEN 'T' THEN 'types' ELSE 'schemas' END,
                            COALESCE(quote_ident(n.nspname), 'any schema')) END,
           NULL
      FROM pg_default_acl da
      LEFT JOIN pg_roles cr ON cr.oid = da.defaclrole
      LEFT JOIN pg_namespace n ON n.oid = da.defaclnamespace
     WHERE cr.oid IS NULL
        OR (da.defaclobjtype = 'r' AND NOT EXISTS (SELECT 1 FROM pg_class c WHERE c.relowner = da.defaclrole
                                                  AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
                                                  AND (da.defaclnamespace = 0 OR c.relnamespace = da.defaclnamespace)))
        OR (da.defaclobjtype = 'S' AND NOT EXISTS (SELECT 1 FROM pg_class c WHERE c.relowner = da.defaclrole
                                                  AND c.relkind = 'S'
                                                  AND (da.defaclnamespace = 0 OR c.relnamespace = da.defaclnamespace)))
        OR (da.defaclobjtype = 'f' AND NOT EXISTS (SELECT 1 FROM pg_proc p WHERE p.proowner = da.defaclrole
                                                  AND (da.defaclnamespace = 0 OR p.pronamespace = da.defaclnamespace)))
    UNION ALL
    -- deep chains
    SELECT 3, 'deep chain', r.rolname::text,
           format('membership chain is %s levels deep (limit %s): %s', d.depth, p_max_depth, d.path_text),
           NULL
      FROM pg_roles r
      CROSS JOIN LATERAL (
        SELECT x.depth, x.path_text FROM public.access__walk(r.oid, 'up') x
         WHERE NOT x.is_cycle ORDER BY x.depth DESC, x.path_text LIMIT 1
      ) d
     WHERE r.rolcanlogin AND r.rolname !~ '^pg_' AND d.depth > p_max_depth
    UNION ALL
    -- cycles
    SELECT 1, 'membership cycle', r.rolname::text,
           'roles grant each other in a loop: '
             || (SELECT string_agg(COALESCE(x.rolname::text, u.id::text), ' → ' ORDER BY u.n)
                   FROM unnest(c.path) WITH ORDINALITY AS u(id, n) LEFT JOIN pg_roles x ON x.oid = u.id),
           NULL
      FROM cyc c JOIN pg_roles r ON r.oid = c.start
    UNION ALL
    SELECT 4, 'unused login roles', '(skipped)',
           'PostgreSQL does not record last login time; use log_connections, pgAudit or CloudWatch logs (RDS) to find unused logins',
           NULL
  )
  SELECT CASE f.sev WHEN 1 THEN 'HIGH' WHEN 2 THEN 'MEDIUM' WHEN 3 THEN 'LOW' ELSE 'INFO' END,
         f.category, f.name, f.detail, f.fix
    FROM findings f
   ORDER BY f.sev, f.category, f.name, f.detail
$fn$;

-- ---------------------------------------------------------------------------
-- access_help(): what is installed
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.access_help()
RETURNS TABLE(function_name text, purpose text, example text)
LANGUAGE sql IMMUTABLE SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $fn$
  VALUES
    ('access_why', 'can role X do ACTION on OBJECT, which grant gives it, what blocks it', 'SELECT * FROM access_why(''app_user'', ''sales.orders'', ''SELECT'');'),
    ('access_explain_error', 'turn a permission-denied message into the missing grant and a fix', 'SELECT * FROM access_explain_error(''ERROR: permission denied for table orders'', ''app_user'');'),
    ('access_chain', 'every role a role belongs to, with the full path and INHERIT/SET per hop', 'SELECT * FROM access_chain(''app_user'');'),
    ('access_tree', 'indented membership tree (up = belongs to, down = members)', 'SELECT * FROM access_tree(''app_user'');'),
    ('access_tree_mermaid', 'the same tree as a Mermaid graph', 'SELECT access_tree_mermaid(''app_user'');'),
    ('access_privileges', 'everything a role can use, and which role it comes from', 'SELECT * FROM access_privileges(''app_user'', false);'),
    ('access_who_can', 'reverse lookup: roles that can do ACTION on OBJECT', 'SELECT * FROM access_who_can(''sales.orders'', ''SELECT'');'),
    ('access_default_privileges', 'what NEW objects will grant the role, per creator and schema', 'SELECT * FROM access_default_privileges(''app_user'');'),
    ('access_compare', 'what one role has and the other lacks', 'SELECT * FROM access_compare(''app_user'', ''app_user2'');'),
    ('access_red_flags', 'problems with one role (or every role)', 'SELECT * FROM access_red_flags(''app_user'');'),
    ('access_risky', 'database-wide risky access finder', 'SELECT * FROM access_risky();')
$fn$;

-- ---------------------------------------------------------------------------
-- Comments: also the marker uninstall.sql and access_privileges() use
-- ---------------------------------------------------------------------------
COMMENT ON FUNCTION public.access__role(text) IS 'pg-access-inspector: internal';
COMMENT ON FUNCTION public.access__edges() IS 'pg-access-inspector: internal';
COMMENT ON FUNCTION public.access__walk(oid, text) IS 'pg-access-inspector: internal';
COMMENT ON FUNCTION public.access__reach(oid) IS 'pg-access-inspector: internal';
COMMENT ON FUNCTION public.access__break(oid[]) IS 'pg-access-inspector: internal';
COMMENT ON FUNCTION public.access__kind_matches(text, text) IS 'pg-access-inspector: internal';
COMMENT ON FUNCTION public.access__valid_privs(text) IS 'pg-access-inspector: internal';
COMMENT ON FUNCTION public.access__keyword(text, boolean) IS 'pg-access-inspector: internal';
COMMENT ON FUNCTION public.access__objects(text, text) IS 'pg-access-inspector: internal';
COMMENT ON FUNCTION public.access__has(oid, text, oid, text) IS 'pg-access-inspector: internal';
COMMENT ON FUNCTION public.access__sources(oid, aclitem[], text, oid, text) IS 'pg-access-inspector: internal';
COMMENT ON FUNCTION public.access__fmt(text, text, text) IS 'pg-access-inspector: internal';
COMMENT ON FUNCTION public.access__is_system_schema(name) IS 'pg-access-inspector: internal';
COMMENT ON FUNCTION public.access__tree_lines(oid, text, text, oid[]) IS 'pg-access-inspector: internal';
COMMENT ON FUNCTION public.access_chain(text) IS 'pg-access-inspector: every role a role belongs to, with path and INHERIT/SET per hop';
COMMENT ON FUNCTION public.access_why(text, text, text, text) IS 'pg-access-inspector: can a role do an action on an object, and why (not)';
COMMENT ON FUNCTION public.access_privileges(text, boolean) IS 'pg-access-inspector: effective privileges of a role with their source';
COMMENT ON FUNCTION public.access_default_privileges(text, text) IS 'pg-access-inspector: default privileges that apply to a role, and gaps';
COMMENT ON FUNCTION public.access_who_can(text, text, text, boolean) IS 'pg-access-inspector: roles that can do an action on an object';
COMMENT ON FUNCTION public.access_red_flags(text) IS 'pg-access-inspector: problems with one role or every role';
COMMENT ON FUNCTION public.access_explain_error(text, text, text) IS 'pg-access-inspector: explain a permission-denied error and suggest a fix';
COMMENT ON FUNCTION public.access_compare(text, text, text) IS 'pg-access-inspector: differences between two roles';
COMMENT ON FUNCTION public.access_tree(text, text) IS 'pg-access-inspector: indented membership tree';
COMMENT ON FUNCTION public.access_tree_mermaid(text, text) IS 'pg-access-inspector: membership graph as Mermaid';
COMMENT ON FUNCTION public.access_risky(integer) IS 'pg-access-inspector: database-wide risky access finder';
COMMENT ON FUNCTION public.access_help() IS 'pg-access-inspector: list of functions with examples';

COMMIT;
