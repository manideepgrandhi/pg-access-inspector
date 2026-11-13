#!/usr/bin/env bash
# Regenerates EXAMPLES.md from the test fixture: every output block is real.
#   PG_BINDIR=/usr/lib/postgresql/17/bin tests/run_tests.sh --examples
set -euo pipefail
ROOT=${PAI_ROOT:?run through tests/run_tests.sh --examples}
OUT="$ROOT/EXAMPLES.md"
VER=$(psql -X -At -c "SELECT current_setting('server_version')" | cut -d' ' -f1)

ex() {  # ex <title> <story> <sql> [raw]
  {
    printf '\n## %s\n\n' "$1"
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
echo "wrote $OUT"
