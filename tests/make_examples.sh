#!/usr/bin/env bash
# Regenerates EXAMPLES.md from the test fixture: every output block is real.
#   PG_BINDIR=/usr/lib/postgresql/17/bin tests/run_tests.sh --examples
set -euo pipefail
ROOT=${PAI_ROOT:?run through tests/run_tests.sh --examples}
OUT="$ROOT/EXAMPLES.md"
VER=$(psql -X -At -c "SELECT current_setting('server_version')" | cut -d' ' -f1)

ex() {  # ex <title> <story> <sql> [raw]
  {
    [[ -n "$1" ]] && printf '\n## %s\n\n' "$1"
    [[ -n "$2" ]] && printf '%s\n\n' "$2"
    printf '```sql\n%s\n```\n\n```%s\n' "$3" "$([[ "${4:-}" == raw ]] && echo mermaid || echo text)"
    if [[ "${4:-}" == raw ]]; then
      psql -X -q -At -c "$3"
    else
      psql -X -q -P pager=off -P null='' -c "$3" | sed -e 's/[[:space:]]*$//' | sed -e '${/^$/d;}'
    fi
    printf '```\n'
  } >>"$OUT"
}

cat >"$OUT" <<HDR
# Examples

Real troubleshooting scenarios. Every output below was captured from the test
fixture (\`tests/fixture.sql\`) on PostgreSQL ${VER} by \`tests/make_examples.sh\`.
All role, schema and table names are made up.

The fixture has, among others:

- \`app_user → app_team → app_rw → app_read → app_base\` (4 hops; \`app_base\` holds CONNECT)
- \`report_user\` (NOINHERIT) in \`reporting\`
- \`fin_reader\` with SELECT on \`finance.ledger\` but no USAGE on \`finance\`
- \`hr_reader\` with column grants on \`hr.employees\`
- \`sales.orders\` with row level security and one policy for \`sales_emea\`
- default privileges for \`app_owner\` in \`sales\`, but tables there are also created by \`etl_owner\`
- \`acme_clerk → acme_rw → acme_ro\` (plus a direct \`acme_clerk → acme_ro\`) with grants in schemas \`billing\` and \`billing_arch\`
- schema \`cfg\` with audit triggers: \`cfg.fn_config_audit_trg()\` is SECURITY DEFINER and its owner \`audit_owner\` has no USAGE on \`cfg\`; \`cfg.fn_flag_audit_trg()\` is SECURITY INVOKER and the caller \`cfg_user\` cannot insert into its audit table
HDR

ex "1. Multi-level inheritance: where does the access come from?" \
"\`app_user\` can read \`sales.customers\`, but nobody granted it anything directly. \`access_why\` names the role that holds each grant and the path to it." \
"SELECT step, check_name, result, detail
  FROM access_why('app_user', 'sales.customers', 'SELECT');"

ex "2. The whole chain in one call" \
"Every role \`app_user\` belongs to, with the path and how each hop behaves. \`server_confirms\` is PostgreSQL's own \`pg_has_role(..., 'USAGE')\` answer." \
"SELECT depth, member_of, path, access, hop_inherit, hop_set
  FROM access_chain('app_user');"

ex "3. Membership tree, both directions" \
"Up: what \`app_user\` belongs to. Down: who sits under the group role \`app_read\`, login roles marked." \
"SELECT * FROM access_tree('app_user');
SELECT * FROM access_tree('app_read', 'down');"

ex "4. NOINHERIT breaks the chain" \
"\`report_user\` is NOINHERIT. The grant is on \`reporting\`, so plain queries fail until the session runs \`SET ROLE reporting\`." \
"SELECT step, check_name, result, detail, suggested_fix
  FROM access_why('report_user', 'finance.ledger', 'SELECT');"

ex "5. Missing schema USAGE" \
"\`fin_reader\` has SELECT on the table, but not USAGE on its schema, so it cannot even see the table." \
"SELECT step, check_name, result, detail, suggested_fix
  FROM access_why('fin_reader', 'finance.ledger', 'SELECT');"

ex "6. Column grants: SELECT * fails, named columns work" \
"" \
"SELECT step, check_name, result, detail
  FROM access_why('hr_reader', 'hr.employees', 'SELECT');"

ex "7. Row level security hides rows (no error)" \
"\`sales_apac\` has SELECT on \`sales.orders\` but no policy applies to it, so it silently gets zero rows. \`sales_emea\` is filtered by its policy." \
"SELECT object, check_name, result, detail
  FROM access_why('sales_apac', 'sales.orders', 'SELECT') WHERE check_name IN ('answer', 'row level security')
UNION ALL
SELECT object, check_name, result, detail
  FROM access_why('sales_emea', 'sales.orders', 'SELECT') WHERE check_name IN ('answer', 'row level security');"

ex "8. New tables are not readable: default privileges for a different creator" \
"\`app_owner\`'s new tables in \`sales\` are covered by default privileges. \`etl_owner\` and \`sales_owner\` also create tables there, and theirs are not covered. The suggested grantee is the role in the chain that already holds SELECT on most tables in that schema." \
"SELECT creator_role, schema_name, object_type, privileges, grantee, how, note
  FROM access_default_privileges('app_user');"

ex "9. Explain a permission-denied error" \
"Paste the error, plus the STATEMENT line from the server log if you have it. The fix is returned as text and is never run." \
"SELECT * FROM access_explain_error(
  'ERROR:  permission denied for table orders
   STATEMENT:  INSERT INTO sales.orders (region, amount) VALUES (''EMEA'', 10)',
  'app_user2');"

ex "10. Explain an error when the action is ambiguous" \
"Without the statement, the message does not say which privilege was missing. The function lists what the role has and lacks, and still finds the real blocker (schema USAGE)." \
"SELECT * FROM access_explain_error('ERROR:  permission denied for table ledger', 'fin_reader');"

ex "11. Compare two app users" \
"Why can \`app_user\` write \`sales.orders\` when \`app_user2\` can't? Only differences are listed." \
"SELECT * FROM access_compare('app_user', 'app_user2');"

ex "12. Who can read this table?" \
"" \
"SELECT role_name, can_login, result, via, missing
  FROM access_who_can('finance.ledger', 'SELECT');"

ex "13. Red flags for every role" \
"" \
"SELECT role_name, severity, flag, detail FROM access_red_flags();"

ex "14. Risky access finder" \
"Database-wide. \`3\` is the chain depth above which login roles are reported." \
"SELECT severity, category, name, detail FROM access_risky(3);"

ex "15. Mermaid diagram for a ticket" \
"Paste the text into any Mermaid renderer (GitHub, Confluence, mermaid.live)." \
"SELECT access_tree_mermaid('dba_user');" raw

{
  printf '\n## 16. No-install version\n\n%s\n\n```sh\n%s\n```\n\n```text\n' \
    "Same main checks with nothing created, for databases where you cannot install functions. Section 2 of the output:" \
    "psql -X -d inspector_test -v role=report_user -v object=finance.ledger -v action=SELECT -f psql/access_checks.sql"
  psql -X -P pager=off -v role=report_user -v object=finance.ledger -v action=SELECT -f "$ROOT/psql/access_checks.sql" \
    | sed -n '/^== 2\./,/^== 3\./p' | sed -e '$d' -e 's/[[:space:]]*$//' | sed -e :a -e '/^\n*$/{$d;N;ba' -e '}'
  printf '```\n'
} >>"$OUT"
sqlq() { printf '%s' "$1" | sed "s/'/''/g"; }

# Functions and triggers: errors captured from a real session as cfg_user
ERR_DEF=$(psql -X -U cfg_user -c "UPDATE cfg.app_config SET value = '60' WHERE key = 'timeout'" 2>&1 >/dev/null || true)
ERR_INV=$(psql -X -U cfg_user -c "INSERT INTO cfg.feature_flags VALUES ('beta', true)" 2>&1 >/dev/null || true)

{
  printf '\n## 17. Error inside a SECURITY DEFINER trigger: the owner is missing the privilege\n\n%s\n\n' \
    "A made-up copy of a real case. \`cfg_user\` can update \`cfg.app_config\`, but the UPDATE fires the audit trigger \`cfg.fn_config_audit_trg()\`, which is SECURITY DEFINER. Its owner \`audit_owner\` has INSERT on \`cfg.config_audit\` but no USAGE on schema \`cfg\`. The error psql printed for \`UPDATE cfg.app_config SET value = '60' WHERE key = 'timeout'\`:"
  printf '```text\n%s\n```\n\n' "$ERR_DEF"
  printf '%s\n\n' "Paste all of it, CONTEXT line included (a client's \`Where:\` line works too):"
} >>"$OUT"
ex "" "" "SELECT step, finding, detail, suggested_fix
  FROM access_explain_error('$(sqlq "$ERR_DEF")', 'cfg_user');"

ex "18. Check a function before it fails" \
"Who \`cfg.fn_config_audit_trg()\` runs as, and whether that role can reach every object its body names. Line numbers match the ones in PL/pgSQL CONTEXT lines. The sequence row comes from the \`bigserial\` default on \`cfg.config_audit.id\`." \
"SELECT step, check_name, line, object, action, result, detail, suggested_fix
  FROM access_function_check('cfg.fn_config_audit_trg()', 'cfg_user');"

ex "19. Every trigger on a table" \
"The caller's own privilege for each triggering event, then each trigger with the role its function really runs as." \
"SELECT trigger_name, timing, events, enabled, check_name, line, object, action, result, detail
  FROM access_trigger_check('cfg.app_config', 'cfg_user');"

{
  printf '\n## 20. Error inside a SECURITY INVOKER trigger: the caller is missing the privilege\n\n%s\n\n' \
    "Same shape, but \`cfg.fn_flag_audit_trg()\` is SECURITY INVOKER, so it runs as \`cfg_user\`, which may read \`cfg.flag_audit\` but not insert into it. The error for \`INSERT INTO cfg.feature_flags VALUES ('beta', true)\`:"
  printf '```text\n%s\n```\n\n' "$ERR_INV"
} >>"$OUT"
ex "" "" "SELECT step, finding, detail, suggested_fix
  FROM access_explain_error('$(sqlq "$ERR_INV")', 'cfg_user');"

ex "21. SECURITY DEFINER owner that only has access through NOINHERIT" \
"\`noinh_owner\` is NOINHERIT and gets USAGE on \`cfg\` and INSERT on \`cfg.change_log\` only through \`cfg_writer\`. Outside a function \`SET ROLE cfg_writer\` would help; inside a SECURITY DEFINER function \`SET ROLE\` is not allowed, so the fix is a direct grant." \
"SELECT check_name, line, object, action, result, suggested_fix
  FROM access_function_check('cfg.fn_log_change(text)', 'cfg_user')
 WHERE check_name IN ('runs as', 'owner NOINHERIT', 'reference', 'summary');"

ex "22. Security warnings, unqualified names and dynamic SQL" \
"\`cfg.fn_next_change_id()\` is SECURITY DEFINER with no pinned search_path, uses \`nextval('cfg.change_seq')\` and an unqualified \`app_config\`. \`cfg.fn_count_flags()\` pins \`search_path = cfg, pg_temp\`, so its unqualified names resolve there. \`cfg.fn_purge(text)\` builds its SQL at run time." \
"SELECT function_name, check_name, line, object, action, result, detail
  FROM access_function_check('cfg.fn_next_change_id()', 'cfg_user')
 WHERE check_name IN ('search_path', 'reference', 'summary')
UNION ALL
SELECT function_name, check_name, line, object, action, result, detail
  FROM access_function_check('cfg.fn_count_flags()', 'cfg_user')
 WHERE check_name IN ('search_path', 'reference')
UNION ALL
SELECT function_name, check_name, line, object, action, result, detail
  FROM access_function_check('cfg.fn_purge(text)', 'cfg_user')
 WHERE check_name IN ('dynamic SQL', 'summary');"

ex "23. SQL-language function" \
"Errors from \`LANGUAGE sql\` functions say \`SQL function \"fn_sql_counts\" statement 2\`; the check reports the line of each statement." \
"SELECT check_name, line, object, action, result, source_line
  FROM access_function_check('cfg.fn_sql_counts()', 'cfg_user')
 WHERE check_name IN ('runs as', 'reference', 'summary');"

{
  printf '\n## 24. No-install function and trigger check\n\n%s\n\n```sh\n%s\n```\n\n```text\n' \
    "Sections 7 and 8 of the psql file, for databases where you cannot install functions:" \
    "psql -X -d inspector_test -v role=cfg_user -v function=cfg.fn_config_audit_trg -v table=cfg.app_config -f psql/access_checks.sql"
  psql -X -P pager=off -v role=cfg_user -v function=cfg.fn_config_audit_trg -v table=cfg.app_config -f "$ROOT/psql/access_checks.sql" \
    | sed -n '/^== 7\./,$p' | sed -e 's/[[:space:]]*$//' | sed -e :a -e '/^\n*$/{$d;N;ba' -e '}'
  printf '```\n'
} >>"$OUT"

ex "25. Full access report for one role" \
"\`access_report\` lists everything \`acme_clerk\` can do, from role attributes down to columns. \`acme_clerk\` is in \`acme_rw\`, which is in \`acme_ro\`, and is also a direct member of \`acme_ro\`. A privilege that arrives more than one way gets one row per path. \`OWNER\` stands for every privilege on the object plus ALTER, DROP and GRANT. On PostgreSQL 16+ the fixture also grants \`acme_admin\` with \`INHERIT FALSE\`, so its rows say \`needs SET ROLE\`." \
"SELECT * FROM access_report('acme_clerk', 'billing');"

ex "26. Full access report: NOINHERIT and superuser" \
"\`report_user\` is NOINHERIT, so nothing from \`reporting\` is active until \`SET ROLE reporting\`. \`p_include_public => false\` hides the PUBLIC rows. A superuser gets one \`superuser\` row instead of a row for every object." \
"SELECT * FROM access_report('report_user', 'finance', false);
SELECT * FROM access_report('legacy_su');"

{
  printf '\n## 27. No-install full access report\n\n%s\n\n```sh\n%s\n```\n\n```text\n' \
    "Section 9 of the psql file returns the same rows as \`access_report\`:" \
    "psql -X -d inspector_test -v role=acme_clerk -v report=1 -v schema=billing_arch -f psql/access_checks.sql"
  psql -X -P pager=off -v role=acme_clerk -v report=1 -v schema=billing_arch -f "$ROOT/psql/access_checks.sql" \
    | sed -n '/^== 9\./,$p' | sed -e 's/[[:space:]]*$//' | sed -e :a -e '/^\n*$/{$d;N;ba' -e '}'
  printf '```\n'
} >>"$OUT"
echo "wrote $OUT"
