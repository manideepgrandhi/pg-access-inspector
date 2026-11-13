-- pg-access-inspector -- no-install checks for psql
--
-- For databases where you cannot create functions. Creates nothing, writes
-- nothing: plain catalog queries, safe in a READ ONLY transaction.
--
--   psql -X -d mydb -v role=app_user -v object=sales.orders -v action=SELECT \
--        -f psql/access_checks.sql
--
-- Variables (all optional):
--   role    role to check                      (default: the connected user)
--   object  table/view/sequence, schema or db   (default: skip sections 2 and 5)
--   action  SELECT, INSERT, USAGE, CONNECT, ... (default: SELECT)
--   function  schema.name or schema.name(argtypes): who runs it, and what
--             that role can reach (section 7; role = the caller)
--   table   schema.table: its triggers and who each one runs as (section 8)
--   report  any value: full access report for the role (section 9), same rows
--           as access_report(); optional schema=<name> limits schema and
--           object rows, include_public=off drops PUBLIC rows
-- Unqualified table names follow your search_path (to_regclass).
-- Works on PostgreSQL / Aurora PostgreSQL 14-17; PG16 grant options are read
-- with to_jsonb(), so the same file runs on every version.

\set QUIET on
\pset null '-'
\if :{?role}
\else
  \set role :USER
\endif
\if :{?action}
\else
  \set action SELECT
\endif
SELECT upper(:'action') AS action \gset
\set QUIET off

\echo
\echo '== 1. Membership chain of' :role '(every role it belongs to, with the path)'
WITH RECURSIVE edges AS (
  SELECT m.member, m.roleid,
         bool_or(COALESCE((to_jsonb(m) ->> 'inherit_option')::boolean, mr.rolinherit)) AS inh,
         bool_or(COALESCE((to_jsonb(m) ->> 'set_option')::boolean, true)) AS sett,
         bool_or(m.admin_option) AS adm
    FROM pg_auth_members m JOIN pg_roles mr ON mr.oid = m.member
   GROUP BY m.member, m.roleid
  UNION ALL
  SELECT d.datdba, o.oid, true, true, false
    FROM pg_database d JOIN pg_roles o ON o.rolname = 'pg_database_owner'
   WHERE d.datname = current_database()
), w(roleid, depth, path, inh, sett, hop_inh, hop_set, hop_adm, cyc) AS (
  SELECT r.oid, 0, ARRAY[r.oid], true, true, NULL::boolean, NULL::boolean, NULL::boolean, false
    FROM pg_roles r WHERE r.rolname = :'role'
  UNION ALL
  SELECT e.roleid, w.depth + 1, w.path || e.roleid, w.inh AND e.inh, w.sett AND e.sett,
         e.inh, e.sett, e.adm, e.roleid = ANY (w.path)
    FROM w JOIN edges e ON e.member = w.roleid
   WHERE NOT w.cyc AND w.depth < 64
)
SELECT w.depth,
       (SELECT string_agg(r.rolname, ' → ' ORDER BY x.n)
          FROM unnest(w.path) WITH ORDINALITY x(id, n) JOIN pg_roles r ON r.oid = x.id) AS path,
       CASE WHEN w.cyc THEN 'CYCLE: stops here' WHEN w.inh THEN 'inherited'
            WHEN w.sett THEN 'needs SET ROLE' ELSE 'not usable' END AS access,
       w.hop_inh AS hop_inherit, w.hop_set, w.hop_adm AS hop_admin
  FROM w
 WHERE w.depth > 0
 ORDER BY path;

\if :{?object}
\echo
\echo '== 2. Can' :role 'do' :action 'on' :object '?'
WITH RECURSIVE edges AS (
  SELECT m.member, m.roleid,
         bool_or(COALESCE((to_jsonb(m) ->> 'inherit_option')::boolean, mr.rolinherit)) AS inh,
         bool_or(COALESCE((to_jsonb(m) ->> 'set_option')::boolean, true)) AS sett
    FROM pg_auth_members m JOIN pg_roles mr ON mr.oid = m.member
   GROUP BY m.member, m.roleid
  UNION ALL
  SELECT d.datdba, o.oid, true, true
    FROM pg_database d JOIN pg_roles o ON o.rolname = 'pg_database_owner'
   WHERE d.datname = current_database()
), w(roleid, depth, path, inh, sett) AS (
  SELECT r.oid, 0, ARRAY[r.oid], true, true FROM pg_roles r WHERE r.rolname = :'role'
  UNION ALL
  SELECT e.roleid, w.depth + 1, w.path || e.roleid, w.inh AND e.inh, w.sett AND e.sett
    FROM w JOIN edges e ON e.member = w.roleid
   WHERE NOT e.roleid = ANY (w.path)
), chain AS (
  SELECT w.roleid, bool_or(w.inh) AS inh, bool_or(w.sett) AS sett, min(w.depth) AS depth FROM w GROUP BY w.roleid
), me AS (
  SELECT r.* FROM pg_roles r WHERE r.rolname = :'role'
), obj AS (
  SELECT 'relation'::text AS k, c.oid, c.relkind, c.relnamespace AS nsp, c.relowner AS own,
         format('%I.%I', n.nspname, c.relname) AS nm,
         COALESCE(c.relacl, acldefault(CASE WHEN c.relkind = 'S' THEN 's' ELSE 'r' END::"char", c.relowner)) AS acl
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
   WHERE c.oid = to_regclass(:'object')
  UNION ALL
  SELECT 'schema', n.oid, NULL, NULL, n.nspowner, quote_ident(n.nspname), COALESCE(n.nspacl, acldefault('n', n.nspowner))
    FROM pg_namespace n WHERE n.nspname = :'object'
  UNION ALL
  SELECT 'database', d.oid, NULL, NULL, d.datdba, quote_ident(d.datname), COALESCE(d.datacl, acldefault('d', d.datdba))
    FROM pg_database d WHERE d.datname = :'object'
), src AS (
  SELECT o.nm, string_agg(CASE WHEN a.grantee = 0 THEN 'PUBLIC'
                               ELSE r.rolname || CASE WHEN c.depth = 0 THEN ' [direct]'
                                                      WHEN c.inh THEN ' [inherited]'
                                                      WHEN c.sett THEN ' [needs SET ROLE]'
                                                      ELSE ' [not usable]' END END, ', ') AS who
    FROM obj o, aclexplode(o.acl) a
    LEFT JOIN chain c ON c.roleid = a.grantee
    LEFT JOIN pg_roles r ON r.oid = a.grantee
   WHERE a.privilege_type = upper(:'action') AND (a.grantee = 0 OR c.roleid IS NOT NULL)
   GROUP BY o.nm
)
SELECT o.nm AS object, x.check_name, x.result, x.detail
  FROM obj o
  CROSS JOIN me
  CROSS JOIN LATERAL (VALUES
    (1, 'privilege ' || upper(:'action'),
        CASE WHEN me.rolsuper THEN 'YES (superuser)'
             WHEN CASE o.k WHEN 'database' THEN has_database_privilege(me.oid, o.oid, upper(:'action'))
                           WHEN 'schema' THEN has_schema_privilege(me.oid, o.oid, upper(:'action'))
                           ELSE CASE WHEN o.relkind = 'S' THEN has_sequence_privilege(me.oid, o.oid, upper(:'action'))
                                     ELSE has_table_privilege(me.oid, o.oid, upper(:'action')) END END
             THEN 'YES' ELSE 'NO' END,
        'grants found: ' || COALESCE((SELECT s.who FROM src s WHERE s.nm = o.nm), 'none for this role, its chain, or PUBLIC')),
    (2, 'schema USAGE',
        CASE WHEN o.nsp IS NULL THEN 'n/a' WHEN has_schema_privilege(me.oid, o.nsp, 'USAGE') THEN 'YES' ELSE 'NO' END,
        CASE WHEN o.nsp IS NULL THEN NULL ELSE 'schema ' || (SELECT quote_ident(nspname) FROM pg_namespace WHERE oid = o.nsp) END),
    (3, 'database CONNECT',
        CASE WHEN has_database_privilege(me.oid, current_database(), 'CONNECT') THEN 'YES' ELSE 'NO' END,
        'database ' || quote_ident(current_database())),
    (4, 'column grants',
        CASE WHEN o.k <> 'relation' OR o.relkind = 'S' THEN 'n/a'
             ELSE COALESCE((SELECT string_agg(quote_ident(a.attname), ', ' ORDER BY a.attnum)
                              FROM pg_attribute a
                             WHERE a.attrelid = o.oid AND a.attnum > 0 AND NOT a.attisdropped
                               AND upper(:'action') IN ('SELECT', 'INSERT', 'UPDATE', 'REFERENCES')
                               AND has_column_privilege(me.oid, o.oid, a.attnum, upper(:'action'))), 'none') END,
        'columns the role can use with this action'),
    (5, 'row level security',
        CASE WHEN o.k <> 'relation' OR NOT (SELECT relrowsecurity FROM pg_class WHERE oid = o.oid) THEN 'off'
             WHEN me.rolsuper OR me.rolbypassrls THEN 'bypassed (SUPERUSER/BYPASSRLS)'
             WHEN pg_has_role(me.oid, o.own, 'USAGE') AND NOT (SELECT relforcerowsecurity FROM pg_class WHERE oid = o.oid)
               THEN 'bypassed (owner, not FORCED)'
             ELSE 'ON' END,
        CASE WHEN o.k = 'relation' AND (SELECT relrowsecurity FROM pg_class WHERE oid = o.oid) THEN
        (SELECT 'policies for this role: ' || COALESCE(string_agg(p.polname || ' USING (' || COALESCE(pg_get_expr(p.polqual, p.polrelid), 'true') || ')', '; '), 'NONE: zero rows visible')
           FROM pg_policy p
          WHERE o.k = 'relation' AND p.polrelid = o.oid AND p.polpermissive
            AND p.polcmd IN ('*', CASE upper(:'action') WHEN 'SELECT' THEN 'r' WHEN 'INSERT' THEN 'a'
                                                          WHEN 'UPDATE' THEN 'w' WHEN 'DELETE' THEN 'd' END)
            AND (0 = ANY (p.polroles) OR EXISTS (SELECT 1 FROM chain c WHERE c.inh AND c.roleid = ANY (p.polroles))))
        END),
    (6, 'role', CASE WHEN me.rolcanlogin THEN 'LOGIN' ELSE 'NOLOGIN' END,
        concat_ws(', ', CASE WHEN me.rolsuper THEN 'SUPERUSER' END, CASE WHEN NOT me.rolinherit THEN 'NOINHERIT' END,
                  CASE WHEN me.rolvaliduntil < now() THEN 'password EXPIRED' END,
                  CASE WHEN me.rolconnlimit = 0 THEN 'CONNECTION LIMIT 0' END))
  ) AS x(ord, check_name, result, detail)
 ORDER BY o.nm, x.ord;
\endif

\echo
\echo '== 3. Privileges' :role 'can use (tables, views, sequences, schemas, functions; PUBLIC excluded)'
WITH RECURSIVE edges AS (
  SELECT m.member, m.roleid,
         bool_or(COALESCE((to_jsonb(m) ->> 'inherit_option')::boolean, mr.rolinherit)) AS inh,
         bool_or(COALESCE((to_jsonb(m) ->> 'set_option')::boolean, true)) AS sett
    FROM pg_auth_members m JOIN pg_roles mr ON mr.oid = m.member
   GROUP BY m.member, m.roleid
  UNION ALL
  SELECT d.datdba, o.oid, true, true
    FROM pg_database d JOIN pg_roles o ON o.rolname = 'pg_database_owner'
   WHERE d.datname = current_database()
), w(roleid, depth, path, inh, sett) AS (
  SELECT r.oid, 0, ARRAY[r.oid], true, true FROM pg_roles r WHERE r.rolname = :'role'
  UNION ALL
  SELECT e.roleid, w.depth + 1, w.path || e.roleid, w.inh AND e.inh, w.sett AND e.sett
    FROM w JOIN edges e ON e.member = w.roleid
   WHERE NOT e.roleid = ANY (w.path)
), chain AS (
  SELECT w.roleid, bool_or(w.inh) AS inh, bool_or(w.sett) AS sett, min(w.depth) AS depth FROM w GROUP BY w.roleid
), objs AS (
  SELECT CASE c.relkind WHEN 'r' THEN 'table' WHEN 'p' THEN 'table' WHEN 'v' THEN 'view' WHEN 'm' THEN 'matview'
                        WHEN 'S' THEN 'sequence' WHEN 'f' THEN 'foreign table' END AS t,
         format('%I.%I', n.nspname, c.relname) AS nm, c.relowner AS own,
         COALESCE(c.relacl, acldefault(CASE WHEN c.relkind = 'S' THEN 's' ELSE 'r' END::"char", c.relowner)) AS acl
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
   WHERE c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
     AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname !~ '^pg_(toast|temp_)'
  UNION ALL
  SELECT 'schema', quote_ident(n.nspname), n.nspowner, COALESCE(n.nspacl, acldefault('n', n.nspowner))
    FROM pg_namespace n
   WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname !~ '^pg_(toast|temp_)'
  UNION ALL
  SELECT 'function', p.oid::regprocedure::text, p.proowner, COALESCE(p.proacl, acldefault('f', p.proowner))
    FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
   WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
     AND COALESCE(obj_description(p.oid, 'pg_proc'), '') NOT LIKE 'pg-access-inspector:%'
)
SELECT o.t AS object_type, o.nm AS object_name,
       string_agg(DISTINCT a.privilege_type, ', ') AS privileges,
       r.rolname AS source_role,
       CASE WHEN c.depth = 0 AND a.grantee = o.own THEN 'owner' WHEN c.depth = 0 THEN 'direct'
            WHEN c.inh THEN 'inherited' WHEN c.sett THEN 'needs SET ROLE' ELSE 'not usable' END AS how
  FROM objs o, aclexplode(o.acl) a
  JOIN chain c ON c.roleid = a.grantee
  JOIN pg_roles r ON r.oid = a.grantee
 GROUP BY o.t, o.nm, r.rolname, 5
 ORDER BY 1, 2, 4;

\echo
\echo '== 4. Default privileges (what NEW objects will grant)' :role 'or its chain'
WITH RECURSIVE edges AS (
  SELECT m.member, m.roleid,
         bool_or(COALESCE((to_jsonb(m) ->> 'inherit_option')::boolean, mr.rolinherit)) AS inh
    FROM pg_auth_members m JOIN pg_roles mr ON mr.oid = m.member
   GROUP BY m.member, m.roleid
), w(roleid, path, inh) AS (
  SELECT r.oid, ARRAY[r.oid], true FROM pg_roles r WHERE r.rolname = :'role'
  UNION ALL
  SELECT e.roleid, w.path || e.roleid, w.inh AND e.inh
    FROM w JOIN edges e ON e.member = w.roleid
   WHERE NOT e.roleid = ANY (w.path)
), chain AS (SELECT roleid, bool_or(inh) AS inh FROM w GROUP BY roleid)
SELECT cr.rolname AS creator_role,
       COALESCE(n.nspname, '(all schemas)') AS schema_name,
       CASE da.defaclobjtype WHEN 'r' THEN 'tables' WHEN 'S' THEN 'sequences' WHEN 'f' THEN 'functions'
                             WHEN 'T' THEN 'types' WHEN 'n' THEN 'schemas' END AS object_type,
       string_agg(a.privilege_type, ', ' ORDER BY a.privilege_type) AS privileges,
       COALESCE(g.rolname, 'PUBLIC') AS grantee,
       CASE WHEN a.grantee = 0 THEN 'PUBLIC' WHEN c.inh THEN 'inherited/direct' ELSE 'needs SET ROLE' END AS how
  FROM pg_default_acl da
  CROSS JOIN LATERAL aclexplode(da.defaclacl) a
  LEFT JOIN chain c ON c.roleid = a.grantee
  LEFT JOIN pg_roles g ON g.oid = a.grantee
  LEFT JOIN pg_roles cr ON cr.oid = da.defaclrole
  LEFT JOIN pg_namespace n ON n.oid = da.defaclnamespace
 WHERE a.grantee = 0 OR c.roleid IS NOT NULL
 GROUP BY 1, 2, 3, 5, 6
 ORDER BY 1, 2, 3;
\echo 'Defaults apply only to objects created BY the creator role. Tables owned by other roles in the same schema get nothing.'

\if :{?object}
\echo
\echo '== 5. Who can' :action 'on' :object '(non-predefined roles; table/view/sequence only)'
SELECT r.rolname AS role_name, r.rolcanlogin AS can_login,
       CASE WHEN has_schema_privilege(r.oid, c.relnamespace, 'USAGE') THEN 'yes' ELSE 'NO' END AS schema_usage,
       CASE WHEN has_database_privilege(r.oid, current_database(), 'CONNECT') THEN 'yes' ELSE 'NO' END AS can_connect
  FROM pg_roles r, pg_class c
 WHERE c.oid = to_regclass(:'object')
   AND r.rolname !~ '^pg_'
   AND CASE WHEN c.relkind = 'S' THEN has_sequence_privilege(r.oid, c.oid, upper(:'action'))
            ELSE has_table_privilege(r.oid, c.oid, upper(:'action')) END
 ORDER BY r.rolname;
\endif

\echo
\echo '== 6. Red flags for' :role
WITH RECURSIVE edges AS (
  SELECT m.member, m.roleid,
         bool_or(COALESCE((to_jsonb(m) ->> 'inherit_option')::boolean, mr.rolinherit)) AS inh,
         bool_or(COALESCE((to_jsonb(m) ->> 'set_option')::boolean, true)) AS sett
    FROM pg_auth_members m JOIN pg_roles mr ON mr.oid = m.member
   GROUP BY m.member, m.roleid
), w(roleid, depth, path, inh, sett, cyc) AS (
  SELECT r.oid, 0, ARRAY[r.oid], true, true, false FROM pg_roles r WHERE r.rolname = :'role'
  UNION ALL
  SELECT e.roleid, w.depth + 1, w.path || e.roleid, w.inh AND e.inh, w.sett AND e.sett, e.roleid = ANY (w.path)
    FROM w JOIN edges e ON e.member = w.roleid
   WHERE NOT w.cyc AND w.depth < 64
), me AS (SELECT r.* FROM pg_roles r WHERE r.rolname = :'role')
SELECT f.severity, f.flag, f.detail FROM (
  SELECT 1 AS o, 'HIGH' AS severity, 'SUPERUSER' AS flag, 'bypasses every check' AS detail FROM me WHERE me.rolsuper
  UNION ALL
  SELECT 1, 'HIGH', 'superuser/rds_superuser in chain', r.rolname
    FROM w JOIN pg_roles r ON r.oid = w.roleid
   WHERE w.depth > 0 AND NOT w.cyc AND (r.rolsuper OR r.rolname = 'rds_superuser') AND (w.inh OR w.sett)
  UNION ALL
  SELECT 1, 'HIGH', 'membership cycle', 'loop back to ' || r.rolname FROM w JOIN pg_roles r ON r.oid = w.roleid WHERE w.cyc
  UNION ALL
  SELECT 2, 'MEDIUM', 'NOINHERIT breaks the chain', 'privileges of ' || r.rolname || ' need SET ROLE'
    FROM w JOIN pg_roles r ON r.oid = w.roleid
   WHERE w.depth > 0 AND NOT w.cyc AND NOT w.inh AND w.sett
     AND NOT EXISTS (SELECT 1 FROM w w2 WHERE w2.roleid = w.roleid AND w2.inh)
  UNION ALL
  SELECT 1, 'HIGH', 'cannot CONNECT', 'no CONNECT on ' || current_database()
    FROM me WHERE me.rolcanlogin AND NOT has_database_privilege(me.oid, current_database(), 'CONNECT')
  UNION ALL
  SELECT 1, 'HIGH', 'password expired', 'VALID UNTIL ' || me.rolvaliduntil FROM me WHERE me.rolvaliduntil < now()
  UNION ALL
  SELECT 1, 'HIGH', 'connection limit 0', 'every login is refused' FROM me WHERE me.rolcanlogin AND me.rolconnlimit = 0
  UNION ALL
  SELECT 3, 'INFO', 'NOLOGIN', 'group role: nobody logs in as it' FROM me WHERE NOT me.rolcanlogin
  UNION ALL
  SELECT 2, 'MEDIUM', 'BYPASSRLS', 'ignores row level security' FROM me WHERE me.rolbypassrls AND NOT me.rolsuper
) f
ORDER BY f.o, f.flag, f.detail;

\if :{?function}
\echo
\echo '== 7. Function' :function 'called by' :role ': whose privileges count inside it'
SELECT format('%I.%I(%s)', n.nspname, p.proname, oidvectortypes(p.proargtypes)) AS function,
       CASE WHEN p.prosecdef THEN 'SECURITY DEFINER' ELSE 'SECURITY INVOKER' END AS security,
       CASE WHEN p.prosecdef THEN pg_get_userbyid(p.proowner) ELSE :'role' END AS runs_as,
       pg_get_userbyid(p.proowner) || CASE WHEN o.rolcanlogin THEN '' ELSE ' (NOLOGIN)' END AS owner,
       has_schema_privilege(p.proowner, n.oid, 'USAGE') AS owner_usage_on_own_schema,
       COALESCE((SELECT substr(c, 13) FROM unnest(p.proconfig) c WHERE c LIKE 'search_path=%'),
                CASE WHEN p.prosecdef THEN 'NOT PINNED (security risk)' ELSE 'not pinned' END) AS search_path,
       l.lanname AS language
  FROM pg_proc p
  JOIN pg_namespace n ON n.oid = p.pronamespace
  JOIN pg_language l ON l.oid = p.prolang
  JOIN pg_roles o ON o.oid = p.proowner
 WHERE n.nspname || '.' || p.proname = :'function'
    OR format('%s.%s(%s)', n.nspname, p.proname, oidvectortypes(p.proargtypes)) = :'function';
\echo 'Schema-qualified tables and nextval() sequences named in the body, checked for the role it runs as.'
\echo 'Rough text scan: comments and strings are not skipped and there are no line numbers; access_function_check() in install.sql is more thorough.'
WITH f AS (
  SELECT p.prosrc,
         CASE WHEN p.prosecdef THEN p.proowner ELSE (SELECT r.oid FROM pg_roles r WHERE r.rolname = :'role') END AS eff
    FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
   WHERE n.nspname || '.' || p.proname = :'function'
      OR format('%s.%s(%s)', n.nspname, p.proname, oidvectortypes(p.proargtypes)) = :'function'
), refs AS (
  SELECT DISTINCT f.eff,
         CASE WHEN m[2] IS NOT NULL THEN 'USAGE'
              WHEN m[1] ~* '^insert' THEN 'INSERT' WHEN m[1] ~* '^update' THEN 'UPDATE'
              WHEN m[1] ~* '^delete' THEN 'DELETE' WHEN m[1] ~* '^truncate' THEN 'TRUNCATE'
              ELSE 'SELECT' END AS action,
         lower(m[3]) AS sch, lower(m[4]) AS rel
    FROM f, regexp_matches(f.prosrc,
           '(?:\m(insert\s+into|update|delete\s+from|from|join|truncate(?:\s+table)?)\s+(?:only\s+)?|\m(nextval)\s*\(\s*'')([a-z_][a-z0-9_$]*)\.([a-z_][a-z0-9_$]*)', 'gi') AS m
)
SELECT refs.action, format('%I.%I', refs.sch, refs.rel) AS object, pg_get_userbyid(refs.eff) AS checked_as,
       CASE WHEN c.oid IS NULL THEN 'not found' ELSE has_schema_privilege(refs.eff, c.relnamespace, 'USAGE')::text END AS schema_usage,
       CASE WHEN c.oid IS NULL THEN 'not found'
            WHEN c.relkind = 'S' THEN has_sequence_privilege(refs.eff, c.oid, refs.action)::text
            ELSE has_table_privilege(refs.eff, c.oid, refs.action)::text END AS privilege,
       CASE WHEN c.oid IS NULL THEN NULL
            ELSE concat_ws(' ',
                   CASE WHEN NOT has_schema_privilege(refs.eff, c.relnamespace, 'USAGE')
                        THEN format('GRANT USAGE ON SCHEMA %I TO %I;', refs.sch, pg_get_userbyid(refs.eff)) END,
                   CASE WHEN NOT CASE WHEN c.relkind = 'S' THEN has_sequence_privilege(refs.eff, c.oid, refs.action)
                                      ELSE has_table_privilege(refs.eff, c.oid, refs.action) END
                        THEN format('GRANT %s ON %s %I.%I TO %I;', refs.action,
                                    CASE WHEN c.relkind = 'S' THEN 'SEQUENCE' ELSE 'TABLE' END,
                                    refs.sch, refs.rel, pg_get_userbyid(refs.eff)) END) END AS suggested_fix
  FROM refs
  LEFT JOIN pg_namespace n ON n.nspname = refs.sch
  LEFT JOIN pg_class c ON c.relnamespace = n.oid AND c.relname = refs.rel AND c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
 WHERE refs.sch NOT IN ('new', 'old', 'excluded')
 ORDER BY 2, 1;
\endif

\if :{?table}
\echo
\echo '== 8. Triggers on' :table 'and the role each trigger function runs as'
SELECT t.tgname AS trigger,
       CASE WHEN t.tgtype::int & 2 <> 0 THEN 'BEFORE' WHEN t.tgtype::int & 64 <> 0 THEN 'INSTEAD OF' ELSE 'AFTER' END
       || CASE WHEN t.tgtype::int & 1 <> 0 THEN ' ROW' ELSE ' STATEMENT' END AS timing,
       concat_ws(' OR ', CASE WHEN t.tgtype::int & 4 <> 0 THEN 'INSERT' END, CASE WHEN t.tgtype::int & 16 <> 0 THEN 'UPDATE' END,
                 CASE WHEN t.tgtype::int & 8 <> 0 THEN 'DELETE' END, CASE WHEN t.tgtype::int & 32 <> 0 THEN 'TRUNCATE' END) AS events,
       CASE t.tgenabled WHEN 'D' THEN 'disabled' WHEN 'R' THEN 'replica only' WHEN 'A' THEN 'always' ELSE 'enabled' END AS enabled,
       format('%I.%I(%s)', n.nspname, p.proname, oidvectortypes(p.proargtypes)) AS function,
       CASE WHEN p.prosecdef THEN pg_get_userbyid(p.proowner) || ' (owner, SECURITY DEFINER)'
            ELSE :'role' || ' (caller, SECURITY INVOKER)' END AS runs_as
  FROM pg_trigger t
  JOIN pg_proc p ON p.oid = t.tgfoid
  JOIN pg_namespace n ON n.oid = p.pronamespace
 WHERE t.tgrelid = to_regclass(:'table') AND NOT t.tgisinternal
 ORDER BY t.tgname;
\echo 'Run section 7 for each function above: -v function=<function> -v role=<the role that runs the statement>'
\endif

\if :{?report}
\echo
\echo '== 9. Full access report for' :role '(role, database, schema and object level; one row per path)'
\if :{?schema}
\else
  \set schema ''
\endif
\if :{?include_public}
\else
  \set include_public on
\endif
WITH RECURSIVE edges AS (
  SELECT m.member, m.roleid,
         bool_or(COALESCE((to_jsonb(m) ->> 'inherit_option')::boolean, mr.rolinherit)) AS inh,
         bool_or(COALESCE((to_jsonb(m) ->> 'set_option')::boolean, true)) AS sett,
         bool_or(m.admin_option) AS adm
    FROM pg_auth_members m JOIN pg_roles mr ON mr.oid = m.member
   GROUP BY m.member, m.roleid
  UNION ALL
  SELECT d.datdba, o.oid, true, true, false
    FROM pg_database d JOIN pg_roles o ON o.rolname = 'pg_database_owner'
   WHERE d.datname = current_database()
), w(roleid, depth, path, inh, sett, adm) AS (
  SELECT r.oid, 0, ARRAY[r.oid], true, true, false FROM pg_roles r WHERE r.rolname = :'role'
  UNION ALL
  SELECT e.roleid, w.depth + 1, w.path || e.roleid, w.inh AND e.inh, w.sett AND e.sett, e.adm
    FROM w JOIN edges e ON e.member = w.roleid
   WHERE NOT e.roleid = ANY (w.path) AND w.depth < 64
), p AS (
  SELECT w.roleid, w.depth, w.adm,
         (SELECT string_agg(r.rolname, ' → ' ORDER BY x.n)
            FROM unnest(w.path) WITH ORDINALITY x(id, n) JOIN pg_roles r ON r.oid = x.id) AS path_text,
         CASE WHEN w.inh THEN 0 WHEN w.sett THEN 1 ELSE 2 END AS state
    FROM w
), me AS (
  SELECT r.* FROM pg_roles r WHERE r.rolname = :'role'
), objs AS (
  SELECT 2 AS lvl, 'database'::text AS t, quote_ident(d.datname) AS nm, d.datdba AS own,
         COALESCE(d.datacl, acldefault('d', d.datdba)) AS acl
    FROM pg_database d WHERE NOT d.datistemplate
  UNION ALL
  SELECT 3, 'schema', quote_ident(n.nspname), n.nspowner, COALESCE(n.nspacl, acldefault('n', n.nspowner))
    FROM pg_namespace n
   WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname !~ '^pg_(toast|temp_|toast_temp_)'
     AND (:'schema' = '' OR n.nspname = :'schema')
  UNION ALL
  SELECT 4, CASE c.relkind WHEN 'r' THEN 'table' WHEN 'p' THEN 'partitioned table' WHEN 'v' THEN 'view'
                           WHEN 'm' THEN 'materialized view' WHEN 'S' THEN 'sequence' WHEN 'f' THEN 'foreign table' END,
         format('%I.%I', n.nspname, c.relname), c.relowner,
         COALESCE(c.relacl, acldefault(CASE WHEN c.relkind = 'S' THEN 's' ELSE 'r' END::"char", c.relowner))
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
   WHERE c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
     AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname !~ '^pg_(toast|temp_|toast_temp_)'
     AND (:'schema' = '' OR n.nspname = :'schema')
  UNION ALL
  SELECT 4, 'column', format('%I.%I.%I', n.nspname, c.relname, a.attname), c.relowner, a.attacl
    FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace
   WHERE a.attacl IS NOT NULL AND a.attnum > 0 AND NOT a.attisdropped
     AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname !~ '^pg_(toast|temp_|toast_temp_)'
     AND (:'schema' = '' OR n.nspname = :'schema')
  UNION ALL
  SELECT 4, CASE pr.prokind WHEN 'p' THEN 'procedure' WHEN 'a' THEN 'aggregate' WHEN 'w' THEN 'window function'
                            ELSE 'function' END,
         pr.oid::regprocedure::text, pr.proowner, COALESCE(pr.proacl, acldefault('f', pr.proowner))
    FROM pg_proc pr JOIN pg_namespace n ON n.oid = pr.pronamespace
   WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname !~ '^pg_(toast|temp_|toast_temp_)'
     AND (:'schema' = '' OR n.nspname = :'schema')
     AND COALESCE(obj_description(pr.oid, 'pg_proc'), '') NOT LIKE 'pg-access-inspector:%'
), acl AS (
  SELECT o.lvl, o.t, o.nm, o.own, e.grantee, e.privilege_type AS priv, bool_or(e.is_grantable) AS grantable
    FROM objs o, aclexplode(o.acl) e
   GROUP BY o.lvl, o.t, o.nm, o.own, e.grantee, e.privilege_type
), rows AS (
  SELECT 1 AS lvl, 'attribute'::text AS t, me.rolname::text AS nm, a.attr AS priv, 'direct'::text AS via,
         false AS grantable, 0 AS state
    FROM me CROSS JOIN LATERAL (VALUES (me.rolsuper, 'SUPERUSER'), (me.rolcreaterole, 'CREATEROLE'),
                                       (me.rolcreatedb, 'CREATEDB'), (me.rolbypassrls, 'BYPASSRLS'),
                                       (me.rolcanlogin, 'LOGIN'), (me.rolreplication, 'REPLICATION')) a(isset, attr)
   WHERE a.isset
  UNION ALL
  SELECT 1, 'superuser', '*', 'ALL',
         'SUPERUSER attribute: bypasses every privilege check (database, schema and object rows are not listed)', true, 0
    FROM me WHERE me.rolsuper
  UNION ALL
  SELECT 1, 'attribute', r.rolname::text, a.attr,
         CASE WHEN p.state < 2 THEN 'needs SET ROLE: ' ELSE 'not usable (no INHERIT, no SET): ' END || p.path_text,
         false, CASE WHEN p.state < 2 THEN 1 ELSE 2 END
    FROM p JOIN pg_roles r ON r.oid = p.roleid
    CROSS JOIN LATERAL (VALUES (r.rolsuper, 'SUPERUSER'), (r.rolcreaterole, 'CREATEROLE'), (r.rolcreatedb, 'CREATEDB'),
                               (r.rolbypassrls, 'BYPASSRLS'), (r.rolreplication, 'REPLICATION')) a(isset, attr)
   WHERE p.depth > 0 AND a.isset
  UNION ALL
  SELECT 1, CASE WHEN r.rolname ~ '^(pg|rds)_' THEN 'predefined role' ELSE 'member of' END, r.rolname::text,
         CASE r.rolname
           WHEN 'pg_read_all_data'  THEN 'SELECT on all tables, views and sequences; USAGE on all schemas'
           WHEN 'pg_write_all_data' THEN 'INSERT, UPDATE, DELETE on all tables, views and sequences; USAGE on all schemas'
           WHEN 'pg_maintain'       THEN 'VACUUM, ANALYZE, REINDEX, REFRESH, CLUSTER, LOCK on all relations'
           WHEN 'pg_database_owner' THEN 'owner of the current database'
           WHEN 'rds_superuser'     THEN 'RDS/Aurora admin role (not a real superuser)'
           ELSE 'MEMBER' END,
         CASE p.state WHEN 0 THEN '' WHEN 1 THEN 'needs SET ROLE: ' ELSE 'not usable (no INHERIT, no SET): ' END || p.path_text,
         p.adm, p.state
    FROM p JOIN pg_roles r ON r.oid = p.roleid
   WHERE p.depth > 0
  UNION ALL
  SELECT a.lvl, a.t, a.nm, a.priv,
         CASE WHEN a.grantee = 0 THEN 'PUBLIC' WHEN p.depth = 0 THEN 'direct'
              ELSE CASE p.state WHEN 0 THEN '' WHEN 1 THEN 'needs SET ROLE: '
                                ELSE 'not usable (no INHERIT, no SET): ' END || p.path_text END,
         a.grantable, COALESCE(p.state, 0)
    FROM acl a LEFT JOIN p ON p.roleid = a.grantee
   WHERE ((a.grantee = 0 AND :'include_public'::boolean) OR p.roleid IS NOT NULL) AND a.grantee <> a.own
  UNION ALL
  SELECT o.lvl, o.t, o.nm, 'OWNER',
         CASE WHEN p.depth = 0 THEN 'owner'
              ELSE CASE p.state WHEN 0 THEN '' WHEN 1 THEN 'needs SET ROLE: '
                                ELSE 'not usable (no INHERIT, no SET): ' END || p.path_text || ' (owner)' END,
         true, p.state
    FROM objs o JOIN p ON p.roleid = o.own
   WHERE o.t <> 'column'
)
SELECT CASE rows.lvl WHEN 1 THEN 'role' WHEN 2 THEN 'database' WHEN 3 THEN 'schema' ELSE 'object' END AS level,
       rows.t AS object_type, rows.nm AS object_name, rows.priv AS privilege, rows.via, rows.grantable AS grant_option
  FROM rows
 WHERE rows.lvl = 1 OR NOT EXISTS (SELECT 1 FROM me WHERE me.rolsuper)
 ORDER BY rows.lvl, rows.t = 'superuser' DESC, rows.t, rows.nm, rows.priv = 'OWNER' DESC, rows.priv, rows.state,
          CASE WHEN rows.via IN ('direct', 'owner') THEN 0 WHEN rows.via = 'PUBLIC' THEN 2 ELSE 1 END, rows.via;
\endif
