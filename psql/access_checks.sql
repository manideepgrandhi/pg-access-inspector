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
