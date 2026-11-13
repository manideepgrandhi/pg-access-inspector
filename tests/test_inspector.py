"""Behavior tests for pg-access-inspector.

Run through tests/run_tests.sh, which builds a throwaway cluster, loads
tests/fixture.sql and install.sql. Where it can, a test checks the tool's
claim against what PostgreSQL actually does (running the statement as the
role, applying the suggested fix inside a rolled-back transaction).
"""
import os
import subprocess
import unittest
from pathlib import Path

if os.environ.get('PAI_ISOLATED_TEST_CLUSTER') != '1':
    raise SystemExit('Run tests/run_tests.sh; it creates a disposable cluster')

ROOT = Path(os.environ['PAI_ROOT'])
DB = 'inspector_test'
US, RS = '\x1f', '\x1e'


def run(sql, user='postgres', db=DB, check=True, extra_env=None):
    env = dict(os.environ, **(extra_env or {}))
    res = subprocess.run(
        ['psql', '-X', '-q', '-At', '-F', US, '-R', RS, '-v', 'ON_ERROR_STOP=1',
         '-U', user, '-d', db, '-c', sql],
        text=True, capture_output=True, env=env, check=False)
    if check and res.returncode:
        raise AssertionError(f'{sql}\n{res.stderr}')
    return res


def q(sql, **kw):
    out = run(sql, **kw).stdout
    if out.endswith('\n'):
        out = out[:-1]
    return [r.split(US) for r in out.split(RS) if r != ''] if out else []


def q1(sql, **kw):
    rows = q(sql, **kw)
    return rows[0][0] if rows else None


def sql_error(sql, user='postgres'):
    """Run SQL that must fail; return the error text psql printed."""
    res = run(sql, user=user, check=False)
    assert res.returncode != 0, f'expected an error from: {sql}'
    return res.stderr.strip()


def lit(text):
    return "'" + text.replace("'", "''") + "'"


PGV = int(q1("SELECT current_setting('server_version_num')")) // 10000


def why(role, obj, action, otype=None):
    """{check_name: (result, detail, fix)} for one object."""
    t = 'NULL' if otype is None else lit(otype)
    rows = q(f"SELECT check_name, result, detail, coalesce(suggested_fix, '') "
             f"FROM access_why({lit(role)}, {lit(obj)}, {lit(action)}, {t}) ORDER BY object, step")
    return {r[0]: (r[1], r[2], r[3]) for r in rows}


def explain(err, role=None, action=None):
    args = [lit(err)]
    if role is not None or action is not None:
        args.append(lit(role) if role is not None else 'current_user')
    if action is not None:
        args.append(lit(action))
    return q(f"SELECT step, finding, coalesce(detail, ''), coalesce(suggested_fix, '') "
             f"FROM access_explain_error({', '.join(args)}) ORDER BY step")


def fix_works(fix_sql, role, statement):
    """Apply a suggested fix in a transaction that is rolled back, then run the
    statement as the role. True when the statement succeeds."""
    script = f"BEGIN; {fix_sql} SET LOCAL ROLE {role}; {statement}; ROLLBACK;"
    return run(script, check=False).returncode == 0


def works_as(role, statement):
    """Log in as the role itself (SET ROLE checks use the session user)."""
    return run(f'BEGIN; {statement}; ROLLBACK;', user=role, check=False).returncode == 0


# --------------------------------------------------------------------------
class Chain(unittest.TestCase):
    def test_four_level_chain_with_paths(self):
        rows = q("SELECT depth, member_of, path, access, server_confirms FROM access_chain('app_user')")
        by_role = {r[1]: r for r in rows}
        self.assertEqual(set(by_role), {'app_team', 'app_rw', 'app_read', 'app_base'})
        self.assertEqual(by_role['app_base'][0], '4')
        self.assertEqual(by_role['app_base'][2], 'app_user → app_team → app_rw → app_read → app_base')
        for r in rows:
            self.assertEqual(r[3], 'inherited')
            self.assertEqual(r[4], 't', 'pg_has_role must agree privileges flow')

    def test_noinherit_hop_needs_set_role(self):
        rows = q("SELECT member_of, access, hop_inherit, hop_set, server_confirms FROM access_chain('report_user')")
        self.assertEqual(rows, [['reporting', 'needs SET ROLE', 'f', 't', 'f']])

    @unittest.skipIf(PGV < 16, 'per-grant INHERIT/SET options are PG16+')
    def test_pg16_grant_options(self):
        rows = {r[0]: r[1:] for r in q("SELECT member_of, access, hop_inherit, hop_set FROM access_chain('ops_user')")}
        self.assertEqual(rows['ops_admin'], ['needs SET ROLE', 'f', 't'])
        self.assertEqual(rows['vault'], ['inherited', 't', 'f'])
        self.assertEqual(rows['dead_end'], ['not usable (no INHERIT, no SET)', 'f', 'f'])
        # the server agrees: ops_user can SET ROLE ops_admin but not vault
        self.assertTrue(works_as('ops_user', 'SET ROLE ops_admin'))
        self.assertFalse(works_as('ops_user', 'SET ROLE vault'))

    @unittest.skipIf(PGV >= 16, 'before PG16 every membership allows SET ROLE')
    def test_pre16_set_always_allowed(self):
        self.assertEqual({r[0] for r in q("SELECT hop_set FROM access_chain('app_user')")}, {'t'})

    def test_database_owner_implicit_membership(self):
        rows = q("SELECT member_of, granted_by FROM access_chain('db_owner_role')")
        self.assertIn(['pg_database_owner', '(implicit: owns this database)'], rows)

    def test_unknown_role_is_a_clear_error(self):
        res = run("SELECT * FROM access_chain('no_such_role')", check=False)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn('role "no_such_role" does not exist', res.stderr)


# --------------------------------------------------------------------------
class Why(unittest.TestCase):
    def test_inherited_grant_names_source_and_path(self):
        w = why('app_user', 'sales.customers', 'SELECT')
        self.assertEqual(w['answer'][0], 'YES')
        self.assertIn('app_read [inherited: app_user → app_team → app_rw → app_read]', w['SELECT privilege'][1])
        self.assertIn('app_base', w['database CONNECT'][1])
        self.assertTrue(works_as('app_user', 'SELECT * FROM sales.customers'))

    def test_missing_schema_usage_and_fix_works(self):
        w = why('fin_reader', 'finance.ledger', 'SELECT')
        self.assertEqual(w['answer'][0], 'NO')
        self.assertEqual(w['schema USAGE'][0], 'FAIL')
        self.assertEqual(w['SELECT privilege'][0], 'PASS')
        self.assertEqual(w['answer'][2], 'GRANT USAGE ON SCHEMA finance TO fin_reader;')
        self.assertFalse(works_as('fin_reader', 'SELECT * FROM finance.ledger'))
        self.assertTrue(fix_works(w['answer'][2], 'fin_reader', 'SELECT * FROM finance.ledger'))

    def test_noinherit_only_after_set_role(self):
        w = why('report_user', 'finance.ledger', 'SELECT')
        self.assertEqual(w['answer'][0], 'ONLY AFTER SET ROLE')
        self.assertEqual(w['SELECT privilege'][0], 'WARN')
        self.assertTrue(w['answer'][2].startswith('SET ROLE reporting;'))
        self.assertFalse(works_as('report_user', 'SELECT * FROM finance.ledger'))
        self.assertTrue(works_as('report_user', 'SET ROLE reporting; SELECT * FROM finance.ledger'))

    def test_column_grants_only(self):
        w = why('hr_reader', 'hr.employees', 'SELECT')
        self.assertEqual(w['answer'][0], 'COLUMNS ONLY')
        self.assertIn('id, name, dept', w['column grants'][1])
        self.assertTrue(works_as('hr_reader', 'SELECT id, name, dept FROM hr.employees'))
        self.assertFalse(works_as('hr_reader', 'SELECT * FROM hr.employees'))

    def test_rls_without_policy_hides_every_row(self):
        w = why('sales_apac', 'sales.orders', 'SELECT')
        self.assertEqual(w['answer'][0], 'YES, BUT RLS BLOCKS ALL ROWS')
        self.assertEqual(w['row level security'][0], 'FAIL')
        self.assertEqual(q1("SET ROLE sales_apac; SELECT count(*) FROM sales.orders"), '0')

    def test_rls_policy_filters_rows(self):
        w = why('sales_emea', 'orders', 'SELECT')  # unqualified name
        self.assertEqual(w['answer'][0], 'YES, RLS FILTERS ROWS')
        self.assertIn('emea_only', w['row level security'][1])
        self.assertEqual(q1("SET ROLE sales_emea; SELECT count(*) FROM sales.orders"), '2')

    def test_rls_bypass(self):
        self.assertEqual(why('rls_admin', 'sales.orders', 'SELECT')['row level security'][0], 'PASS')
        self.assertIn('BYPASSRLS', why('rls_admin', 'sales.orders', 'SELECT')['row level security'][1])

    def test_predefined_role(self):
        w = why('auditor', 'finance.ledger', 'SELECT')
        self.assertEqual(w['answer'][0], 'YES')
        self.assertIn('pg_read_all_data', w['SELECT privilege'][1])
        self.assertTrue(works_as('auditor', 'SELECT * FROM finance.ledger'))

    def test_superuser_role_needs_set_role(self):
        w = why('legacy_admin', 'hr.employees', 'SELECT')
        self.assertEqual(w['answer'][0], 'ONLY AFTER SET ROLE')
        self.assertIn('never inherited', w['SELECT privilege'][1])
        self.assertFalse(works_as('legacy_admin', 'SELECT * FROM hr.employees'))
        self.assertTrue(works_as('legacy_admin', 'SET ROLE legacy_su; SELECT * FROM hr.employees'))

    def test_quoted_identifier_and_default_privileges_in_action(self):
        w = why('app_user', 'sales."Daily Report"', 'SELECT')
        self.assertEqual(w['answer'][0], 'YES')
        self.assertTrue(works_as('app_user', 'SELECT * FROM sales."Daily Report"'))

    def test_object_kinds(self):
        self.assertEqual(why('app_user', 'sales.calc_total(integer)', 'EXECUTE')['answer'][0], 'YES')
        self.assertEqual(why('app_user2', 'sales.calc_total', 'EXECUTE')['answer'][0], 'NO')
        self.assertEqual(why('app_user', 'sales.orders_id_seq', 'USAGE')['answer'][0], 'YES')
        self.assertEqual(why('app_user2', 'sales.order_summary', 'SELECT')['answer'][0], 'YES')
        self.assertEqual(why('report_user', 'sales.region_totals', 'SELECT')['answer'][0], 'ONLY AFTER SET ROLE')
        self.assertEqual(why('app_user', 'sales.remote_orders', 'SELECT')['answer'][0], 'YES')
        self.assertEqual(why('app_user', 'sales', 'USAGE', 'schema')['answer'][0], 'YES')
        self.assertEqual(why('nocon_user', DB, 'CONNECT')['answer'][0], 'NO')
        self.assertEqual(why('app_user', DB, 'TEMP')['answer'][0], 'YES')

    def test_database_owner_gets_public_schema(self):
        w = why('db_owner_role', 'public', 'CREATE')
        self.assertEqual(w['answer'][0], 'YES')
        if PGV >= 15:
            self.assertIn('pg_database_owner', w['CREATE privilege'][1])

    def test_invalid_action_and_unknown_object(self):
        self.assertEqual(why('app_user', 'sales.orders', 'EXECUTE')['action'][0], 'ERROR')
        self.assertEqual(why('app_user', 'sales.nope', 'SELECT')['object'][0], 'ERROR')

    def test_answer_matches_server_for_every_role_object_privilege(self):
        """Property: the answer is YES exactly when PostgreSQL itself grants the
        privilege, the schema USAGE and the database CONNECT."""
        mismatches = q("""
          WITH roles AS (SELECT rolname FROM pg_roles WHERE rolname !~ '^pg_' AND rolname NOT LIKE 'cyc_%'),
          objs(obj, kind) AS (VALUES
            ('sales.orders', 'r'), ('sales.customers', 'r'), ('sales.order_summary', 'r'),
            ('sales.region_totals', 'r'), ('sales.remote_orders', 'r'), ('finance.ledger', 'r'),
            ('hr.employees', 'r'), ('audit.events', 'r'), ('sales.price_list', 'r'), ('sales.daily_load', 'r'),
            ('sales.orders_id_seq', 'S'), ('sales.calc_total(integer)', 'f'), ('finance', 'n'), ('sales', 'n')),
          privs(kind, priv) AS (VALUES
            ('r', 'SELECT'), ('r', 'INSERT'), ('r', 'UPDATE'), ('r', 'DELETE'), ('r', 'TRUNCATE'),
            ('S', 'USAGE'), ('S', 'SELECT'), ('S', 'UPDATE'), ('f', 'EXECUTE'), ('n', 'USAGE'), ('n', 'CREATE')),
          calls AS (
            SELECT r.rolname, o.obj, o.kind, p.priv, w.result,
                   CASE o.kind
                     WHEN 'r' THEN has_table_privilege(r.rolname, o.obj, p.priv)
                                   AND has_schema_privilege(r.rolname, split_part(o.obj, '.', 1), 'USAGE')
                     WHEN 'S' THEN has_sequence_privilege(r.rolname, o.obj, p.priv)
                                   AND has_schema_privilege(r.rolname, split_part(o.obj, '.', 1), 'USAGE')
                     WHEN 'f' THEN has_function_privilege(r.rolname, o.obj, p.priv)
                                   AND has_schema_privilege(r.rolname, split_part(o.obj, '.', 1), 'USAGE')
                     WHEN 'n' THEN has_schema_privilege(r.rolname, o.obj, p.priv)
                   END AND has_database_privilege(r.rolname, current_database(), 'CONNECT') AS server_says
              FROM roles r CROSS JOIN objs o JOIN privs p ON p.kind = o.kind
              CROSS JOIN LATERAL access_why(r.rolname, o.obj, p.priv) w
             WHERE w.step = 0)
          SELECT rolname, obj, priv, result, server_says FROM calls
           WHERE (result LIKE 'YES%') IS DISTINCT FROM server_says
        """)
        self.assertEqual(mismatches, [])
        self.assertGreater(int(q1("SELECT count(*) FROM pg_roles WHERE rolname !~ '^pg_'")), 25)


# --------------------------------------------------------------------------
class ExplainError(unittest.TestCase):
    def find(self, rows, prefix):
        return [r for r in rows if r[1].startswith(prefix)]

    def fix(self, rows):
        return self.find(rows, 'fix')[0][3]

    def test_schema_error_from_real_session(self):
        err = sql_error('SET ROLE fin_reader; SELECT * FROM finance.ledger')
        self.assertIn('permission denied for schema finance', err)
        rows = explain(err + '\nSTATEMENT:  SELECT * FROM finance.ledger', 'fin_reader')
        self.assertIn('USAGE', self.find(rows, 'action')[0][2])
        fix = self.fix(rows)
        self.assertEqual(fix, 'GRANT USAGE ON SCHEMA finance TO fin_reader;')
        self.assertTrue(fix_works(fix, 'fin_reader', 'SELECT * FROM finance.ledger'))

    def test_table_error_with_statement_and_fix_works(self):
        stmt = "INSERT INTO sales.orders (region, amount) VALUES ('EMEA', 1)"
        err = sql_error(f'SET ROLE app_user2; {stmt}')
        self.assertIn('permission denied for table orders', err)
        rows = explain(f'{err}\nSTATEMENT:  {stmt}', 'app_user2')
        self.assertIn('INSERT (taken from the STATEMENT)', self.find(rows, 'action')[0][2])
        fix = self.fix(rows)
        self.assertEqual(fix, 'GRANT INSERT ON TABLE sales.orders TO app_user2;')
        self.assertTrue(fix_works(fix + ' GRANT USAGE ON SEQUENCE sales.orders_id_seq TO app_user2;',
                                  'app_user2', 'SELECT 1'))

    def test_ambiguous_action_lists_candidates(self):
        rows = explain('ERROR:  permission denied for table orders', 'app_user2')
        action = self.find(rows, 'action')[0][2]
        self.assertIn('ambiguous', action)
        self.assertIn('has: SELECT', action)
        self.assertIn('INSERT', action)
        self.assertIn('GRANT INSERT | UPDATE | DELETE', self.fix(rows))

    def test_explicit_action_argument(self):
        rows = explain('permission denied for table orders', 'app_user2', 'DELETE')
        self.assertEqual(self.fix(rows), 'GRANT DELETE ON TABLE sales.orders TO app_user2;')

    def test_column_select_star(self):
        err = sql_error('SET ROLE hr_reader; SELECT * FROM hr.employees')
        rows = explain(err + '\nSTATEMENT: SELECT * FROM hr.employees', 'hr_reader')
        self.assertTrue(self.find(rows, 'column grants'))
        self.assertIn('GRANT SELECT ON TABLE hr.employees TO hr_reader;', self.fix(rows))

    def test_noinherit_error_suggests_set_role(self):
        err = sql_error('SET ROLE report_user; SELECT * FROM finance.ledger')
        rows = explain(err, 'report_user')
        self.assertIn('SET ROLE reporting;', self.fix(rows))

    def test_function_and_sequence(self):
        err = sql_error('SET ROLE app_user2; SELECT sales.calc_total(1)')
        self.assertIn('permission denied for function calc_total', err)
        rows = explain(err, 'app_user2')
        fix = self.fix(rows)
        self.assertEqual(fix, 'GRANT EXECUTE ON FUNCTION sales.calc_total(integer) TO app_user2;')
        self.assertTrue(fix_works(fix, 'app_user2', 'SELECT sales.calc_total(1)'))
        err = sql_error("SET ROLE app_user2; SELECT nextval('sales.orders_id_seq')")
        rows = explain(err + "\nSTATEMENT: SELECT nextval('sales.orders_id_seq')", 'app_user2')
        fix = self.fix(rows)
        self.assertEqual(fix, 'GRANT USAGE ON SEQUENCE sales.orders_id_seq TO app_user2;')
        self.assertTrue(fix_works(fix, 'app_user2', "SELECT nextval('sales.orders_id_seq')"))

    def test_connect_error_from_real_login(self):
        res = run('SELECT 1', user='nocon_user', check=False)
        self.assertNotEqual(res.returncode, 0)
        rows = explain(res.stderr, 'nocon_user')
        self.assertEqual(self.fix(rows), f'GRANT CONNECT ON DATABASE {DB} TO nocon_user;')

    def test_must_be_owner(self):
        err = sql_error('SET ROLE app_user; ALTER TABLE sales.orders ADD COLUMN note text')
        self.assertIn('must be owner of table orders', err)
        rows = explain(err, 'app_user')
        self.assertTrue(self.find(rows, 'not the owner'))
        self.assertIn('ALTER TABLE sales.orders OWNER TO app_user;', self.fix(rows))

    def test_rls_violation(self):
        err = sql_error("SET ROLE app_user; INSERT INTO sales.orders (region, amount) VALUES ('EMEA', 5)")
        self.assertIn('row-level security', err)
        rows = explain(err, 'app_user')
        self.assertTrue(self.find(rows, 'row level security'))
        self.assertIn('CREATE POLICY', self.fix(rows))

    @unittest.skipIf(PGV < 16, 'SET option is PG16+')
    def test_set_role_refused(self):
        res = run('SET ROLE vault', user='ops_user', check=False)
        self.assertNotEqual(res.returncode, 0)
        err = res.stderr
        rows = explain(err, 'ops_user')
        self.assertEqual(rows[-1][1], 'member without SET')
        self.assertEqual(rows[-1][3], 'GRANT vault TO ops_user WITH SET TRUE;')

    def test_unrecognised_message(self):
        self.assertEqual(explain('ERROR: division by zero')[0][1], 'error not recognised')

    def test_default_role_is_current_user(self):
        rows = q("SET ROLE fin_reader; SELECT detail FROM access_explain_error('permission denied for schema finance') WHERE step = 1")
        self.assertIn('fin_reader', rows[0][0])

    def test_already_has_privilege(self):
        rows = explain('permission denied for table customers', 'app_user', 'SELECT')
        self.assertIn('already has', self.find(rows, 'action')[0][2])



# --------------------------------------------------------------------------
# Functions and triggers. The fixture's cfg schema reproduces a real case:
# an UPDATE fails inside a SECURITY DEFINER audit trigger because the
# function OWNER has no USAGE on the schema (the caller is fine).
def fcheck(func, caller='cfg_user', where=''):
    """[{check_name, line, object, action, result, detail, fix, source_line}] in step order."""
    rows = q(f"SELECT check_name, coalesce(line::text, ''), coalesce(object, ''), coalesce(action, ''), result, "
             f"coalesce(detail, ''), coalesce(suggested_fix, ''), coalesce(source_line, '') "
             f"FROM access_function_check({lit(func)}, {lit(caller)}) {where} ORDER BY function_name, step")
    keys = ('check', 'line', 'object', 'action', 'result', 'detail', 'fix', 'source')
    return [dict(zip(keys, r)) for r in rows]


def by_check(rows, name):
    return [r for r in rows if r['check'] == name]


def login_error(user, statement):
    """Run a statement logged in as the role; return the full error text with
    its LINE / QUERY / CONTEXT lines exactly as psql prints them."""
    res = run(statement, user=user, check=False)
    assert res.returncode != 0, f'expected {user} to fail: {statement}'
    return res.stderr.strip()


def server_agrees(role, obj, action):
    """PostgreSQL's own answer for role/object/action, schema USAGE included."""
    kind = q1(f"SELECT relkind FROM pg_class WHERE oid = to_regclass({lit(obj)})")
    if kind is None:
        return q1(f"SELECT has_function_privilege({lit(role)}, {lit(obj)}, {lit(action)}) AND "
                  f"has_schema_privilege({lit(role)}, (SELECT pronamespace FROM pg_proc WHERE oid = {lit(obj)}::regprocedure), 'USAGE')")
    fn = 'has_sequence_privilege' if kind == 'S' else 'has_table_privilege'
    return q1(f"SELECT {fn}({lit(role)}, {lit(obj)}, {lit(action)}) AND "
              f"has_schema_privilege({lit(role)}, (SELECT relnamespace FROM pg_class WHERE oid = {lit(obj)}::regclass), 'USAGE')")


class FunctionCheck(unittest.TestCase):
    def test_security_definer_owner_lacks_schema_usage(self):
        rows = fcheck('cfg.fn_config_audit_trg()')
        runs_as = by_check(rows, 'runs as')[0]
        self.assertEqual(runs_as['object'], 'audit_owner')
        self.assertIn('SECURITY DEFINER', runs_as['detail'])
        self.assertIn('NOLOGIN (fine', by_check(rows, 'owner')[0]['detail'])
        schema = by_check(rows, 'function schema')[0]
        self.assertEqual(schema['result'], 'FAIL')
        self.assertIn('NO USAGE on its own schema cfg', schema['detail'])
        ref = [r for r in by_check(rows, 'reference') if r['object'] == 'cfg.config_audit'][0]
        self.assertEqual((ref['line'], ref['action'], ref['result']), ('13', 'INSERT', 'NO'))
        self.assertIn('USAGE on schema cfg', ref['detail'])
        self.assertIn('INSERT itself is granted', ref['detail'])
        self.assertTrue(ref['source'].startswith('INSERT INTO cfg.config_audit'))
        seq = [r for r in by_check(rows, 'reference') if r['object'] == 'cfg.config_audit_id_seq'][0]
        self.assertIn('defaults to nextval()', seq['detail'])
        summary = by_check(rows, 'summary')[0]
        self.assertEqual(summary['result'], 'FAIL')
        self.assertEqual(summary['fix'], 'GRANT USAGE ON SCHEMA cfg TO audit_owner;')
        # the server agrees with every YES/NO
        for r in by_check(rows, 'reference'):
            self.assertEqual(server_agrees('audit_owner', r['object'], r['action']) == 't',
                             r['result'].startswith('YES'), r)
        # with the fix applied (rolled back) the check passes and the real UPDATE works
        out = q("BEGIN; GRANT USAGE ON SCHEMA cfg TO audit_owner; "
                "SELECT result FROM access_function_check('cfg.fn_config_audit_trg()', 'cfg_user') "
                "WHERE check_name = 'summary'; ROLLBACK;")
        self.assertEqual(out, [['PASS']])
        self.assertTrue(fix_works(summary['fix'], 'cfg_user', "UPDATE cfg.app_config SET value = '90'"))

    def test_security_invoker_checks_the_caller(self):
        rows = fcheck('cfg.fn_flag_audit_trg()')
        self.assertEqual(by_check(rows, 'runs as')[0]['object'], 'cfg_user')
        ref = by_check(rows, 'reference')[0]
        self.assertEqual((ref['object'], ref['action'], ref['result'], ref['line']),
                         ('cfg.flag_audit', 'INSERT', 'NO', '3'))
        self.assertEqual(ref['fix'], 'GRANT INSERT ON TABLE cfg.flag_audit TO cfg_user;')
        self.assertEqual(server_agrees('cfg_user', 'cfg.flag_audit', 'INSERT'), 'f')
        # a different caller gives a different answer; the owner does not matter
        self.assertEqual(by_check(fcheck('cfg.fn_flag_audit_trg()', 'postgres'), 'reference')[0]['result'], 'YES')

    def test_owner_access_only_through_noinherit(self):
        rows = fcheck('cfg.fn_log_change(text)')
        self.assertEqual(by_check(rows, 'owner NOINHERIT')[0]['result'], 'WARN')
        ref = by_check(rows, 'reference')[0]
        self.assertEqual(ref['result'], 'NO (NOINHERIT)')
        self.assertIn('SET ROLE is not allowed inside a SECURITY DEFINER function', ref['detail'])
        self.assertNotIn('SET ROLE', ref['fix'])
        self.assertIn('GRANT INSERT ON TABLE cfg.change_log TO noinh_owner;', ref['fix'])
        # PostgreSQL agrees: SET ROLE is refused inside SECURITY DEFINER, and the call fails
        self.assertIn('permission denied for schema cfg', login_error('cfg_user', "SELECT cfg.fn_log_change('x')"))
        grants = '\n'.join(l for l in ref['fix'].splitlines() if not l.startswith('--'))
        self.assertTrue(fix_works(grants, 'cfg_user', "SELECT cfg.fn_log_change('x')"))

    def test_definer_without_pinned_search_path_and_nextval(self):
        rows = fcheck('cfg.fn_next_change_id()')
        sp = by_check(rows, 'search_path')[0]
        self.assertEqual(sp['result'], 'WARN')
        self.assertIn('without a pinned search_path', sp['detail'])
        self.assertEqual(sp['fix'], 'ALTER FUNCTION cfg.fn_next_change_id() SET search_path = pg_catalog, cfg, pg_temp;')
        refs = {(r['line'], r['object'], r['action']): r for r in by_check(rows, 'reference')}
        self.assertEqual(refs[('5', 'cfg.change_seq', 'USAGE')]['result'], 'YES')
        unq = refs[('6', 'cfg.app_config', 'SELECT')]
        self.assertIn('assumed to be cfg.app_config', unq['detail'])
        self.assertEqual(by_check(rows, 'summary')[0]['result'], 'WARN')

    def test_unsafe_pinned_search_path(self):
        out = q("""BEGIN;
          CREATE FUNCTION public.tmp_sp() RETURNS int LANGUAGE sql SECURITY DEFINER SET search_path = cfg AS 'SELECT 1';
          CREATE FUNCTION public.tmp_pub() RETURNS int LANGUAGE sql SECURITY DEFINER SET search_path = public, pg_temp AS 'SELECT 1';
          SELECT 'sp', result, detail FROM access_function_check('public.tmp_sp()') WHERE check_name = 'search_path'
          UNION ALL
          SELECT 'pub', result, detail FROM access_function_check('public.tmp_pub()') WHERE check_name = 'search_path';
          ROLLBACK;""")
        res = {r[0]: r[1:] for r in out}
        self.assertEqual(res['sp'][0], 'WARN')
        self.assertIn('pg_temp is not listed last', res['sp'][1])
        if PGV == 14:  # PUBLIC may still CREATE in public
            self.assertEqual(res['pub'][0], 'WARN')
            self.assertIn('writable by PUBLIC', res['pub'][1])
        else:
            self.assertEqual(res['pub'][0], 'PASS')

    def test_dynamic_sql_cannot_verify(self):
        rows = fcheck('cfg.fn_purge(text)')
        dyn = by_check(rows, 'dynamic SQL')[0]
        self.assertEqual((dyn['result'], dyn['line']), ('CANNOT VERIFY', '3'))
        self.assertIn('EXECUTE format', dyn['source'])
        self.assertEqual(by_check(rows, 'summary')[0]['result'], 'CANNOT VERIFY')

    def test_unqualified_names_resolved_through_pinned_search_path(self):
        rows = fcheck('cfg.fn_count_flags()')
        refs = {r['object']: r for r in by_check(rows, 'reference')}
        self.assertIn('pinned search_path to schema cfg', refs['cfg.feature_flags']['detail'])
        self.assertEqual(refs['cfg.fn_log_change(text)']['action'], 'EXECUTE')
        self.assertEqual(by_check(rows, 'search_path')[0]['result'], 'PASS')

    def test_search_path_lookup_skips_schema_without_usage(self):
        create = ("CREATE FUNCTION public.tmp_skip() RETURNS void LANGUAGE plpgsql SECURITY DEFINER "
                  "SET search_path = cfg, pg_temp AS 'BEGIN PERFORM 1 FROM change_log; END'; "
                  "ALTER FUNCTION public.tmp_skip() OWNER TO audit_owner; ")
        rows = q("BEGIN; " + create + "SELECT result, detail, suggested_fix FROM access_function_check('public.tmp_skip()') "
                 "WHERE check_name = 'reference'; ROLLBACK;")
        self.assertEqual(rows[0][0], 'NO')
        self.assertIn('lookup skips it', rows[0][1])
        self.assertEqual(rows[0][2], 'GRANT USAGE ON SCHEMA cfg TO audit_owner;')
        # PostgreSQL agrees: the table is "not found", not "permission denied"
        res = run("BEGIN; " + create + "SET LOCAL ROLE plain_user; SELECT public.tmp_skip(); ROLLBACK;", check=False)
        self.assertIn('relation "change_log" does not exist', res.stderr)

    def test_sql_language_function(self):
        rows = fcheck('cfg.fn_sql_counts()')
        self.assertIn('sql: body scanned', by_check(rows, 'language')[0]['detail'])
        refs = {r['object']: (r['line'], r['result']) for r in by_check(rows, 'reference')}
        self.assertEqual(refs, {'cfg.feature_flags': ('2', 'YES'), 'cfg.change_log': ('3', 'NO')})
        self.assertEqual(by_check(rows, 'caller EXECUTE')[0]['result'], 'YES')

    def test_other_language_is_not_scanned(self):
        rows = fcheck('pg_catalog.now()')
        self.assertIn('not scanned', by_check(rows, 'language')[0]['detail'])
        self.assertEqual(by_check(rows, 'summary')[0]['result'], 'INFO')
        self.assertFalse(by_check(rows, 'reference'))

    def test_scanner_sees_statements_not_comments_or_strings(self):
        body = ("\nBEGIN\n"
                "  -- INSERT INTO fake.commented VALUES (1);\n"
                "  RAISE NOTICE 'DELETE FROM fake.in_a_string';\n"
                "  UPDATE cfg.app_config SET value = 'x' FROM cfg.feature_flags f WHERE f.name = key;\n"
                "  DELETE FROM cfg.flag_audit WHERE name IS DISTINCT FROM 'y';\n"
                "  TRUNCATE cfg.change_log;\n"
                "  PERFORM cfg.fn_purge('t'), currval('cfg.change_seq');\n"
                "  INSERT INTO cfg.nope VALUES (1);\n"
                "END\n")
        rows = q("BEGIN; CREATE FUNCTION public.tmp_scan() RETURNS void LANGUAGE plpgsql AS " + lit(body) + "; "
                 "SELECT line, object, action, result FROM access_function_check('public.tmp_scan()', 'postgres') "
                 "WHERE check_name = 'reference' ORDER BY step; ROLLBACK;")
        self.assertEqual(rows, [
            ['5', 'cfg.app_config', 'UPDATE', 'YES'],
            ['5', 'cfg.feature_flags', 'SELECT', 'YES'],
            ['6', 'cfg.flag_audit', 'DELETE', 'YES'],
            ['7', 'cfg.change_log', 'TRUNCATE', 'YES'],
            ['8', 'cfg.fn_purge(text)', 'EXECUTE', 'YES'],
            ['8', 'cfg.change_seq', 'SELECT', 'YES'],
            ['9', 'cfg.nope', 'INSERT', 'CANNOT VERIFY'],
        ])

    def test_regprocedure_argument_and_unknown_function(self):
        rows = q("SELECT result FROM access_function_check('cfg.fn_log_change(text)'::regprocedure, 'cfg_user') "
                 "WHERE check_name = 'summary'")
        self.assertEqual(rows, [['FAIL']])
        res = run("SELECT * FROM access_function_check('cfg.no_such_fn')", check=False)
        self.assertIn('no function named cfg.no_such_fn', res.stderr)

    def test_every_answer_matches_the_server(self):
        funcs = ['cfg.fn_config_audit_trg()', 'cfg.fn_flag_audit_trg()', 'cfg.fn_log_change(text)',
                 'cfg.fn_next_change_id()', 'cfg.fn_count_flags()', 'cfg.fn_sql_counts()']
        checked = 0
        for caller in ('cfg_user', 'app_user', 'postgres'):
            for f in funcs:
                rows = fcheck(f, caller)
                eff = by_check(rows, 'runs as')[0]['object']
                for r in by_check(rows, 'reference'):
                    if r['result'] == 'CANNOT VERIFY':
                        continue
                    self.assertEqual(server_agrees(eff, r['object'], r['action']) == 't',
                                     r['result'].startswith('YES'), (caller, f, r))
                    checked += 1
        self.assertGreater(checked, 25)


class TriggerCheck(unittest.TestCase):
    def rows(self, table, caller='cfg_user'):
        keys = ('trigger', 'timing', 'events', 'enabled', 'function', 'check', 'line', 'object', 'action', 'result', 'detail', 'fix')
        out = q(f"SELECT coalesce(trigger_name, ''), coalesce(timing, ''), coalesce(events, ''), coalesce(enabled, ''), "
                f"coalesce(function_name, ''), check_name, coalesce(line::text, ''), coalesce(object, ''), "
                f"coalesce(action, ''), result, coalesce(detail, ''), coalesce(suggested_fix, '') "
                f"FROM access_trigger_check({lit(table)}, {lit(caller)}) ORDER BY step")
        return [dict(zip(keys, r)) for r in out]

    def test_definer_audit_trigger(self):
        rows = self.rows('cfg.app_config')
        caller = {r['action']: r['result'] for r in rows if r['check'] == 'caller privilege'}
        self.assertEqual(caller, {'INSERT': 'YES', 'UPDATE': 'YES'})
        trg = [r for r in rows if r['check'] == 'trigger'][0]
        self.assertEqual((trg['trigger'], trg['timing'], trg['events'], trg['enabled'], trg['function']),
                         ('trg_config_audit', 'AFTER ROW', 'INSERT OR UPDATE', 'enabled', 'cfg.fn_config_audit_trg()'))
        self.assertIn('the function owner audit_owner (SECURITY DEFINER)', trg['detail'])
        ref = [r for r in rows if r['check'] == 'reference' and r['object'] == 'cfg.config_audit'][0]
        self.assertEqual((ref['line'], ref['result']), ('13', 'NO'))
        summary = [r for r in rows if r['check'] == 'summary'][0]
        self.assertTrue(fix_works(summary['fix'], 'cfg_user', "INSERT INTO cfg.app_config VALUES ('k', 'v')"))
        self.assertFalse(works_as('cfg_user', "INSERT INTO cfg.app_config VALUES ('k', 'v')"))

    def test_invoker_trigger_and_disabled_trigger(self):
        rows = self.rows('cfg.feature_flags')
        caller = {r['action'] for r in rows if r['check'] == 'caller privilege'}
        self.assertEqual(caller, {'INSERT', 'UPDATE'})  # DELETE only has a disabled trigger
        enabled = {r['trigger']: r['enabled'] for r in rows if r['check'] == 'trigger'}
        self.assertEqual(enabled, {'trg_flag_audit': 'enabled', 'trg_flag_audit_old': 'disabled'})
        ref = [r for r in rows if r['check'] == 'reference' and r['trigger'] == 'trg_flag_audit'][0]
        self.assertIn('as cfg_user', ref['detail'])
        self.assertEqual(ref['fix'], 'GRANT INSERT ON TABLE cfg.flag_audit TO cfg_user;')

    def test_caller_without_table_privilege(self):
        rows = self.rows('cfg.app_config', 'app_user')
        caller = {r['action']: r['result'] for r in rows if r['check'] == 'caller privilege'}
        self.assertEqual(caller, {'INSERT': 'NO', 'UPDATE': 'NO'})

    def test_table_without_triggers(self):
        rows = self.rows('sales.orders')
        self.assertEqual(len(rows), 1)
        self.assertIn('no user-defined triggers', rows[0]['detail'])


class ExplainFunctionError(unittest.TestCase):
    def find(self, rows, prefix):
        return [r for r in rows if r[1].startswith(prefix)]

    def fix(self, rows):
        return self.find(rows, 'fix')[0][3]

    def test_real_case_security_definer_owner_is_blamed(self):
        stmt = "UPDATE cfg.app_config SET value = '60' WHERE key = 'timeout'"
        err = login_error('cfg_user', stmt)
        self.assertIn('permission denied for schema cfg', err)
        self.assertIn('PL/pgSQL function cfg.fn_config_audit_trg() line 13 at SQL statement', err)
        rows = explain(err, 'cfg_user')
        self.assertIn('checked for role audit_owner', rows[0][2])
        self.assertIn('line 13 of cfg.fn_config_audit_trg() (plpgsql, SECURITY DEFINER, owner audit_owner)',
                      self.find(rows, 'raised in')[0][2])
        self.assertIn('13:   INSERT INTO cfg.config_audit', self.find(rows, 'statement at line 13')[0][2])
        self.assertTrue(self.find(rows, 'reference at line 13: INSERT cfg.config_audit: NO'))
        self.assertTrue(self.find(rows, 'whose privilege: OWNER audit_owner'))
        fix = self.fix(rows)
        self.assertEqual(fix, 'GRANT USAGE ON SCHEMA cfg TO audit_owner;')
        self.assertTrue(fix_works(fix, 'cfg_user', stmt))
        # the caller is not the problem: it already has what the statement itself needs
        self.assertEqual(q1("SELECT has_schema_privilege('cfg_user', 'cfg', 'USAGE') "
                            "AND has_table_privilege('cfg_user', 'cfg.app_config', 'UPDATE')"), 't')

    def test_client_where_format(self):
        err = ('SQL Error [42501]: ERROR: permission denied for schema cfg\n'
               '  Where: PL/pgSQL function cfg.fn_config_audit_trg() line 13 at SQL statement')
        rows = explain(err, 'cfg_user')
        self.assertTrue(self.find(rows, 'whose privilege: OWNER audit_owner'))
        self.assertEqual(self.fix(rows), 'GRANT USAGE ON SCHEMA cfg TO audit_owner;')

    def test_security_invoker_caller_is_blamed(self):
        stmt = "INSERT INTO cfg.feature_flags VALUES ('beta', true)"
        err = login_error('cfg_user', stmt)
        self.assertIn('permission denied for table flag_audit', err)
        rows = explain(err, 'cfg_user')
        self.assertTrue(self.find(rows, 'whose privilege: CALLER cfg_user'))
        self.assertEqual(self.find(rows, 'object')[0][2], 'cfg.flag_audit (table)')
        self.assertIn('INSERT (taken from the function body, line 3)', self.find(rows, 'action')[0][2])
        fix = self.fix(rows)
        self.assertEqual(fix, 'GRANT INSERT ON TABLE cfg.flag_audit TO cfg_user;')
        self.assertTrue(fix_works(fix, 'cfg_user', stmt))

    def test_noinherit_owner_gets_direct_grants_not_set_role(self):
        stmt = "SELECT cfg.fn_log_change('hello')"
        rows = explain(login_error('cfg_user', stmt), 'cfg_user')
        self.assertTrue(self.find(rows, 'whose privilege: OWNER noinh_owner'))
        fix = self.fix(rows)
        self.assertNotIn('SET ROLE', fix)
        self.assertIn('GRANT USAGE ON SCHEMA cfg TO noinh_owner;', fix)
        self.assertTrue(fix_works(fix, 'cfg_user', stmt))
        # the SET ROLE that access_why suggests outside functions is refused in here
        res = run("BEGIN; CREATE FUNCTION public.tmp_setrole() RETURNS void LANGUAGE plpgsql SECURITY DEFINER "
                  "AS 'BEGIN SET ROLE cfg_writer; END'; SELECT public.tmp_setrole(); ROLLBACK;", check=False)
        self.assertIn('cannot set parameter "role" within security-definer function', res.stderr)

    def test_nested_call_uses_innermost_security_definer(self):
        stmt = 'SELECT cfg.fn_count_flags()'
        err = login_error('cfg_user', stmt)
        rows = explain(err, 'cfg_user')
        self.assertIn('called from', self.find(rows, 'raised in')[0][2])
        self.assertTrue(self.find(rows, 'whose privilege: OWNER noinh_owner'))
        self.assertTrue(fix_works(self.fix(rows), 'cfg_user', stmt))

    def test_sql_function_statement_number(self):
        stmt = 'SELECT cfg.fn_sql_counts()'
        err = login_error('cfg_user', stmt)
        self.assertIn('SQL function "fn_sql_counts" statement 2', err)
        rows = explain(err, 'cfg_user')
        self.assertIn('cfg.change_log', self.find(rows, 'statement at statement 2')[0][2])
        self.assertTrue(self.find(rows, 'whose privilege: CALLER cfg_user'))
        fix = self.fix(rows)
        self.assertEqual(fix, 'GRANT SELECT ON TABLE cfg.change_log TO cfg_user;')
        self.assertTrue(fix_works(fix, 'cfg_user', stmt))

    def test_unknown_function_in_context(self):
        rows = explain('ERROR: permission denied for schema cfg\nCONTEXT: PL/pgSQL function nowhere.fn() line 2 at SQL statement',
                       'cfg_user')
        self.assertIn('was not found', self.find(rows, 'raised in')[0][2])
        self.assertTrue(self.find(rows, 'whose privilege: CALLER cfg_user (assumed)'))

# --------------------------------------------------------------------------
class Privileges(unittest.TestCase):
    def test_lists_inherited_privileges_with_source(self):
        rows = q("SELECT object_type, object_name, privilege, how, source_role FROM access_privileges('app_user', false)")
        self.assertIn(['table', 'sales.orders', 'INSERT', 'inherited', 'app_rw'], rows)
        self.assertIn(['function', 'sales.calc_total(integer)', 'EXECUTE', 'inherited', 'app_rw'], rows)
        self.assertNotIn('PUBLIC', {r[4] for r in rows})
        self.assertFalse([r for r in rows if r[1].startswith('public.access_')])

    def test_public_rows_on_request(self):
        rows = q("SELECT object_name, privilege, how FROM access_privileges('app_user', true)")
        self.assertIn(['sales.price_list', 'SELECT', 'PUBLIC'], rows)

    def test_predefined_and_superuser(self):
        rows = q("SELECT object_type, privilege, source_role FROM access_privileges('auditor', false)")
        self.assertIn(['all relations', 'SELECT', 'pg_read_all_data'], rows)
        self.assertEqual(q1("SELECT how FROM access_privileges('legacy_su') LIMIT 1"), 'superuser')

    def test_table_privileges_match_server(self):
        """Every usable table privilege listed is real, and every real one is listed."""
        diff = q("""
          WITH listed AS (
            SELECT DISTINCT object_name, privilege FROM access_privileges('app_user', true)
             WHERE object_type IN ('table', 'view', 'materialized view', 'foreign table')
               AND how NOT IN ('needs SET ROLE', 'not usable')),
          real AS (
            SELECT format('%I.%I', n.nspname, c.relname) AS object_name, p.priv AS privilege
              FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
              CROSS JOIN (VALUES ('SELECT'), ('INSERT'), ('UPDATE'), ('DELETE'), ('TRUNCATE'),
                                 ('REFERENCES'), ('TRIGGER')) p(priv)
             WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f') AND n.nspname NOT IN ('pg_catalog', 'information_schema')
               AND has_table_privilege('app_user', c.oid, p.priv))
          (SELECT 'extra', * FROM listed EXCEPT SELECT 'extra', * FROM real)
          UNION ALL
          (SELECT 'missing', * FROM real EXCEPT SELECT 'missing', * FROM listed)
        """)
        self.assertEqual(diff, [])


# --------------------------------------------------------------------------
class DefaultPrivileges(unittest.TestCase):
    def test_covered_and_not_covered_creators(self):
        rows = q("SELECT creator_role, schema_name, privileges, grantee, how, note FROM access_default_privileges('app_user')")
        self.assertIn(['app_owner', 'sales', 'SELECT', 'app_read', 'inherited',
                       'via app_user → app_team → app_rw → app_read'], rows)
        gap = [r for r in rows if r[0] == 'etl_owner']
        self.assertEqual(len(gap), 1)
        self.assertEqual(gap[0][4], 'NOT COVERED')
        self.assertIn('ALTER DEFAULT PRIVILEGES FOR ROLE etl_owner IN SCHEMA sales GRANT SELECT ON TABLES TO app_read;', gap[0][5])

    def test_suggested_default_privilege_fix_works(self):
        fix = 'ALTER DEFAULT PRIVILEGES FOR ROLE etl_owner IN SCHEMA sales GRANT SELECT ON TABLES TO app_read;'
        script = (f"BEGIN; {fix} SET LOCAL ROLE etl_owner; CREATE TABLE sales.new_load (x int); "
                  f"RESET ROLE; SET LOCAL ROLE app_user; SELECT * FROM sales.new_load; ROLLBACK;")
        self.assertEqual(run(script, check=False).returncode, 0)
        script = ("BEGIN; SET LOCAL ROLE etl_owner; CREATE TABLE sales.new_load (x int); "
                  "RESET ROLE; SET LOCAL ROLE app_user; SELECT * FROM sales.new_load; ROLLBACK;")
        self.assertNotEqual(run(script, check=False).returncode, 0)

    def test_schema_filter(self):
        rows = q("SELECT DISTINCT schema_name FROM access_default_privileges('app_user', 'finance')")
        self.assertTrue(all(r[0] in ('finance', '(all schemas)') for r in rows))


# --------------------------------------------------------------------------
class WhoCan(unittest.TestCase):
    def test_reverse_lookup(self):
        rows = {r[0]: r[1:] for r in q("SELECT role_name, result, via, coalesce(missing, '') FROM access_who_can('sales.orders', 'SELECT')")}
        self.assertEqual(rows['app_user'][0], 'YES')
        self.assertIn('app_read', rows['app_user'][1])
        self.assertEqual(rows['rls_admin'][0], 'BLOCKED')
        self.assertIn('USAGE on schema sales', rows['rls_admin'][2])
        self.assertNotIn('fin_reader', rows)

    def test_set_role_and_columns(self):
        rows = {r[0]: r[1] for r in q("SELECT role_name, result FROM access_who_can('finance.ledger', 'SELECT')")}
        self.assertEqual(rows['report_user'], 'ONLY AFTER SET ROLE')
        self.assertEqual(rows['fin_reader'], 'BLOCKED')
        rows = {r[0]: r[1] for r in q("SELECT role_name, result FROM access_who_can('hr.employees', 'SELECT')")}
        self.assertEqual(rows['hr_reader'], 'COLUMNS ONLY')

    def test_yes_matches_server(self):
        wrong = q("""
          SELECT w.role_name FROM access_who_can('sales.orders', 'INSERT') w
           WHERE w.result = 'YES' AND NOT (has_table_privilege(w.role_name, 'sales.orders', 'INSERT')
                                            AND has_schema_privilege(w.role_name, 'sales', 'USAGE'))
          UNION ALL
          SELECT r.rolname FROM pg_roles r
           WHERE r.rolname !~ '^pg_' AND has_table_privilege(r.rolname, 'sales.orders', 'INSERT')
             AND r.rolname NOT IN (SELECT role_name FROM access_who_can('sales.orders', 'INSERT'))
        """)
        self.assertEqual(wrong, [])


# --------------------------------------------------------------------------
class Compare(unittest.TestCase):
    def test_two_app_users(self):
        rows = q("SELECT category, item, role_a, role_b FROM access_compare('app_user', 'app_user2')")
        items = {r[1]: r for r in rows}
        self.assertIn('app_rw', items)
        self.assertEqual(items['app_rw'][3], '-')
        self.assertIn('INSERT on table sales.orders', items)
        self.assertTrue(items['INSERT on table sales.orders'][2].startswith('yes via app_rw'))
        self.assertNotIn('SELECT on table sales.orders', items)  # both have it

    def test_object_filter_and_attributes(self):
        rows = q("SELECT category, item FROM access_compare('app_user', 'app_user2', 'sales.orders')")
        self.assertTrue(all(r[1].endswith(' sales.orders') for r in rows if r[0] == 'privilege'), rows)
        self.assertIn(['privilege', 'INSERT on table sales.orders'], rows)
        self.assertNotIn('EXECUTE on function sales.calc_total(integer)', [r[1] for r in rows])
        rows = q("SELECT item, role_a, role_b FROM access_compare('report_user', 'app_user')")
        self.assertIn(['INHERIT', 'false', 'true'], rows)


# --------------------------------------------------------------------------
class Tree(unittest.TestCase):
    def test_up_tree(self):
        lines = [r[0] for r in q("SELECT tree FROM access_tree('app_user')")]
        self.assertTrue(lines[0].startswith('app_user'))
        self.assertEqual(lines[1:], ['└── app_team', '    └── app_rw', '        └── app_read', '            └── app_base'])

    def test_down_tree_marks_logins(self):
        lines = [r[0] for r in q("SELECT tree FROM access_tree('app_read', 'down')")]
        self.assertIn('└── app_user2  [login]', lines)
        self.assertIn('│       └── app_user  [login]', lines)

    def test_noinherit_flag(self):
        lines = [r[0] for r in q("SELECT tree FROM access_tree('report_user')")]
        self.assertIn('└── reporting  [NOINHERIT: needs SET ROLE]', lines)

    def test_mermaid(self):
        text = q1("SELECT access_tree_mermaid('report_user')")
        self.assertTrue(text.startswith('graph BT'))
        self.assertIn('["reporting"]', text)
        self.assertIn('-. "SET ROLE" .->', text)
        text = q1("SELECT access_tree_mermaid('dba_user')")
        self.assertRegex(text, r'class r\d+ danger')


# --------------------------------------------------------------------------
class RedFlags(unittest.TestCase):
    def flags(self, role=None):
        arg = 'NULL' if role is None else lit(role)
        return {(r[0], r[2]): r[1] for r in q(f"SELECT role_name, severity, flag FROM access_red_flags({arg})")}

    def test_all_roles(self):
        f = self.flags()
        self.assertEqual(f[('old_contractor', 'password expired')], 'HIGH')
        self.assertEqual(f[('locked_user', 'connection limit 0')], 'HIGH')
        self.assertEqual(f[('nocon_user', 'cannot CONNECT')], 'HIGH')
        self.assertEqual(f[('dba_user', 'rds_superuser in chain')], 'HIGH')
        self.assertEqual(f[('legacy_admin', 'superuser via membership')], 'HIGH')
        self.assertEqual(f[('report_user', 'NOINHERIT breaks the chain')], 'MEDIUM')
        self.assertEqual(f[('rls_admin', 'BYPASSRLS')], 'MEDIUM')
        self.assertEqual(f[('auditor', 'reads/writes all data')], 'MEDIUM')
        if PGV >= 16:
            self.assertEqual(f[('ops_user', 'membership grants nothing')], 'MEDIUM')

    def test_clean_role(self):
        self.assertEqual(self.flags('app_user'), {('app_user', 'no red flags'): 'OK'})

    def test_real_login_failures_match(self):
        # trust auth ignores VALID UNTIL (a password setting); these two are enforced:
        self.assertNotEqual(run('SELECT 1', user='locked_user', check=False).returncode, 0)
        self.assertNotEqual(run('SELECT 1', user='nocon_user', check=False).returncode, 0)


# --------------------------------------------------------------------------
class Risky(unittest.TestCase):
    def findings(self, depth=5):
        return {(r[1], r[2]): (r[0], r[3]) for r in q(f"SELECT severity, category, name, detail FROM access_risky({depth})")}

    def test_findings(self):
        f = self.findings()
        self.assertEqual(f[('PUBLIC grant', 'audit.events')][0], 'HIGH')
        self.assertEqual(f[('PUBLIC grant', 'sales.price_list')][0], 'MEDIUM')
        self.assertEqual(f[('PUBLIC grant', 'public.reset_counter()')][0], 'HIGH')
        self.assertEqual(f[('rds_superuser member', 'dba_user')][0], 'HIGH')
        self.assertEqual(f[('role attribute', 'legacy_su')][0], 'HIGH')
        self.assertEqual(f[('default privileges', 'ghost_creator')][0], 'LOW')
        self.assertEqual(f[('unused login roles', '(skipped)')][0], 'INFO')
        self.assertNotIn(('deep chain', 'app_user'), f)
        self.assertFalse([k for k in f if k[1].startswith('public.access_')])
        self.assertEqual(f[('PUBLIC grant', 'cfg.fn_log_change(text)')][0], 'HIGH')
        self.assertNotIn(('PUBLIC grant', 'cfg.fn_config_audit_trg()'), f)  # trigger functions cannot be called
        if PGV == 14:
            self.assertEqual(f[('PUBLIC grant', 'public')][0], 'HIGH')  # PG14 default CREATE on public
        else:
            self.assertNotIn(('PUBLIC grant', 'public'), f)

    def test_depth_limit(self):
        f = self.findings(3)
        self.assertIn('4 levels deep', f[('deep chain', 'app_user')][1])


# --------------------------------------------------------------------------
class Cycles(unittest.TestCase):
    """PostgreSQL refuses circular GRANTs, so the cycle is forced into the
    catalog directly (superuser, disposable cluster) and removed afterwards."""

    @classmethod
    def setUpClass(cls):
        run("CREATE ROLE cyc_a; CREATE ROLE cyc_b; CREATE ROLE cyc_c; GRANT cyc_a TO cyc_b; GRANT cyc_b TO cyc_c;")
        cls.refused = sql_error('GRANT cyc_b TO cyc_a')
        run("UPDATE pg_auth_members SET member = 'cyc_a'::regrole "
            "WHERE roleid = 'cyc_b'::regrole AND member = 'cyc_c'::regrole")

    @classmethod
    def tearDownClass(cls):
        run("UPDATE pg_auth_members SET member = 'cyc_c'::regrole "
            "WHERE roleid = 'cyc_b'::regrole AND member = 'cyc_a'::regrole")
        run("DROP ROLE cyc_a, cyc_b, cyc_c")

    def test_server_refuses_cycles(self):
        self.assertIn('is a member of role', self.refused)

    def test_functions_terminate_and_report(self):
        rows = q("SELECT access FROM access_chain('cyc_a')")
        self.assertIn(['CYCLE: stops here'], rows)
        self.assertIn('(CYCLE: stops here)', ''.join(r[0] for r in q("SELECT tree FROM access_tree('cyc_a')")))
        self.assertIn(('cyc_a', 'membership cycle'),
                      {(r[0], r[1]) for r in q("SELECT role_name, flag FROM access_red_flags('cyc_a')")})
        self.assertIn(['membership cycle', 'cyc_b'], q("SELECT category, name FROM access_risky() WHERE category = 'membership cycle'"))
        self.assertEqual(q1("SELECT result FROM access_why('cyc_a', 'sales.orders', 'SELECT') WHERE step = 0"), 'NO')


# --------------------------------------------------------------------------
ALL_CALLS = [
    "SELECT * FROM access_help()",
    "SELECT * FROM access_chain('app_user')",
    "SELECT * FROM access_why('app_user', 'sales.orders', 'SELECT')",
    "SELECT * FROM access_privileges('app_user')",
    "SELECT * FROM access_default_privileges('app_user')",
    "SELECT * FROM access_who_can('sales.orders', 'SELECT')",
    "SELECT * FROM access_red_flags()",
    "SELECT * FROM access_red_flags('report_user')",
    "SELECT * FROM access_explain_error('permission denied for table ledger', 'fin_reader')",
    "SELECT * FROM access_compare('app_user', 'app_user2')",
    "SELECT * FROM access_tree('app_read', 'down')",
    "SELECT access_tree_mermaid('app_user')",
    "SELECT * FROM access_risky()",
    "SELECT * FROM access_function_check('cfg.fn_config_audit_trg()', 'cfg_user')",
    "SELECT * FROM access_function_check('cfg.fn_count_flags()')",
    "SELECT * FROM access_trigger_check('cfg.app_config', 'cfg_user')",
    "SELECT * FROM access_explain_error('ERROR: permission denied for schema cfg CONTEXT: "
    "PL/pgSQL function cfg.fn_config_audit_trg() line 13 at SQL statement', 'cfg_user')",
]


class ReadOnly(unittest.TestCase):
    def test_function_attributes(self):
        rows = q("""SELECT p.proname, p.provolatile, p.prosecdef, array_to_string(p.proconfig, ',')
                      FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace AND p.proname LIKE 'access\\_%'""")
        self.assertGreaterEqual(len(rows), 25)
        for name, vol, secdef, config in rows:
            self.assertIn(vol, ('s', 'i'), name)
            self.assertEqual(secdef, 'f', name)
            self.assertEqual(config, 'search_path=pg_catalog, pg_temp', name)

    def test_every_function_runs_in_read_only_transaction(self):
        script = 'BEGIN TRANSACTION READ ONLY; ' + '; '.join(ALL_CALLS) + '; COMMIT;'
        self.assertEqual(run(script, check=False).stderr, '')

    def test_unprivileged_caller(self):
        script = 'BEGIN TRANSACTION READ ONLY; ' + '; '.join(ALL_CALLS) + '; COMMIT;'
        res = run(script, user='plain_user', check=False)
        self.assertEqual(res.returncode, 0, res.stderr)

    def test_no_install_psql_file_is_read_only_and_creates_nothing(self):
        before = q1("SELECT (SELECT count(*) FROM pg_class) || '/' || (SELECT count(*) FROM pg_proc)")
        env = dict(os.environ, PGOPTIONS='-c default_transaction_read_only=on')
        res = subprocess.run(['psql', '-X', '-v', 'ON_ERROR_STOP=1', '-d', DB, '-v', 'role=report_user',
                              '-v', 'object=finance.ledger', '-v', 'action=select',
                              '-f', str(ROOT / 'psql' / 'access_checks.sql')],
                             text=True, capture_output=True, env=env, check=False)
        self.assertEqual(res.returncode, 0, res.stderr)
        out = res.stdout
        for section in ('== 1.', '== 2.', '== 3.', '== 4.', '== 5.', '== 6.'):
            self.assertIn(section, out)
        self.assertIn('report_user → reporting | needs SET ROLE', out)
        self.assertIn('reporting [needs SET ROLE]', out)
        self.assertIn('NOINHERIT breaks the chain', out)
        self.assertEqual(before, q1("SELECT (SELECT count(*) FROM pg_class) || '/' || (SELECT count(*) FROM pg_proc)"))

    def test_psql_file_function_and_trigger_sections(self):
        env = dict(os.environ, PGOPTIONS='-c default_transaction_read_only=on')
        before = q1("SELECT (SELECT count(*) FROM pg_class) || '/' || (SELECT count(*) FROM pg_proc)")
        res = subprocess.run(['psql', '-X', '-v', 'ON_ERROR_STOP=1', '-d', DB, '-v', 'role=cfg_user',
                              '-v', 'function=cfg.fn_config_audit_trg', '-v', 'table=cfg.app_config',
                              '-f', str(ROOT / 'psql' / 'access_checks.sql')],
                             text=True, capture_output=True, env=env, check=False)
        self.assertEqual(res.returncode, 0, res.stderr)
        out = res.stdout
        self.assertIn('== 7.', out)
        self.assertIn('== 8.', out)
        self.assertRegex(out, r'SECURITY DEFINER \| audit_owner')
        self.assertRegex(out, r'INSERT \| cfg.config_audit \| audit_owner \| false +\| true +\| GRANT USAGE ON SCHEMA cfg TO audit_owner;')
        self.assertIn('audit_owner (owner, SECURITY DEFINER)', out)
        res = subprocess.run(['psql', '-X', '-v', 'ON_ERROR_STOP=1', '-d', DB, '-v', 'role=cfg_user',
                              '-v', 'function=cfg.fn_next_change_id()', '-f', str(ROOT / 'psql' / 'access_checks.sql')],
                             text=True, capture_output=True, env=env, check=False)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn('NOT PINNED (security risk)', res.stdout)
        self.assertRegex(res.stdout, r'USAGE +\| cfg.change_seq +\| cfg_owner')
        self.assertEqual(before, q1("SELECT (SELECT count(*) FROM pg_class) || '/' || (SELECT count(*) FROM pg_proc)"))

    def test_psql_file_without_object(self):
        res = subprocess.run(['psql', '-X', '-v', 'ON_ERROR_STOP=1', '-d', DB, '-U', 'app_user',
                              '-f', str(ROOT / 'psql' / 'access_checks.sql')],
                             text=True, capture_output=True, check=False)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn('app_user → app_team → app_rw → app_read → app_base', res.stdout)
        self.assertNotIn('== 2.', res.stdout)


class InstallUninstall(unittest.TestCase):
    def test_reinstall_uninstall_reinstall(self):
        install, uninstall = str(ROOT / 'install.sql'), str(ROOT / 'uninstall.sql')
        count = "SELECT count(*) FROM pg_proc WHERE pronamespace = 'public'::regnamespace AND proname LIKE 'access\\_%'"
        n = int(q1(count))
        for f in (install, uninstall):
            subprocess.run(['psql', '-X', '-q', '-v', 'ON_ERROR_STOP=1', '-d', DB, '-f', f], check=True, capture_output=True)
            if f == install:
                self.assertEqual(int(q1(count)), n)  # idempotent
        self.assertEqual(int(q1(count)), 0)
        self.assertEqual(q1("SELECT count(*) FROM pg_proc WHERE proname = 'reset_counter'"), '1')  # nothing else dropped
        subprocess.run(['psql', '-X', '-q', '-v', 'ON_ERROR_STOP=1', '-d', DB, '-f', install], check=True, capture_output=True)
        self.assertEqual(int(q1(count)), n)

    def test_install_needs_create_on_public(self):
        run('DROP DATABASE IF EXISTS scratch', db='postgres')
        run('CREATE DATABASE scratch', db='postgres')
        res = subprocess.run(['psql', '-X', '-q', '-v', 'ON_ERROR_STOP=1', '-U', 'plain_user', '-d', 'scratch',
                              '-f', str(ROOT / 'install.sql')], text=True, capture_output=True, check=False)
        if PGV >= 15:
            self.assertNotEqual(res.returncode, 0)
            self.assertIn('permission denied for schema public', res.stderr)
        else:
            self.assertEqual(res.returncode, 0, res.stderr)  # PG14: PUBLIC still has CREATE on public
        run('DROP DATABASE scratch', db='postgres')


if __name__ == '__main__':
    unittest.main()
