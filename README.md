# pg-access-inspector

Read-only SQL functions that answer PostgreSQL access questions in one call,
even when a role inherits its privileges through many other roles.

- **Can this role do X, and why not?** `access_why` gives a yes or no, names
  the role in the chain that holds the grant, and checks schema USAGE,
  database CONNECT, column grants, row level security, NOINHERIT hops and
  superuser in the same call.
- **What does this error mean?** `access_explain_error` takes a
  `permission denied` message and returns the missing grant plus a `GRANT`
  statement to fix it. The fix is text only; nothing is ever run for you.
- **Who is this role, really?** `access_chain` and `access_tree` show every
  role it belongs to, with the full path (`app_user → app_rw → app_read`) and
  whether each hop inherits, needs `SET ROLE`, or grants nothing.

It works on PostgreSQL and Aurora PostgreSQL 14, 15, 16 and 17. Nothing in it
writes data or changes grants.

## Functions

| Function | What it answers |
|---|---|
| `access_why(role, object, action [, object_type])` | Can the role do the action on the object? Which role supplied the grant, and which prerequisite blocks it? |
| `access_explain_error(error_text [, role [, action]])` | What a `permission denied` / `must be owner` / RLS error means for this role, and the fix |
| `access_chain(role)` | Every role it belongs to, directly or through others, with path, depth and INHERIT / SET / ADMIN per hop |
| `access_tree(role [, 'up' \| 'down'])` | Indented membership tree. `up` = what it belongs to, `down` = who is under a group role |
| `access_tree_mermaid(role [, 'up' \| 'down'])` | The same graph as Mermaid text for tickets and wikis |
| `access_privileges(role [, include_public])` | Everything the role can use (databases, schemas, tables, columns, sequences, functions) and where each privilege comes from |
| `access_who_can(object, action [, object_type])` | Reverse lookup: which roles can do it, and through which role |
| `access_default_privileges(role [, schema])` | What new objects will grant the role, per creator and schema, plus creators whose new tables it will **not** be able to read |
| `access_compare(role_a, role_b [, object])` | Memberships, attributes and privileges one role has and the other lacks |
| `access_red_flags([role])` | Problems with one role, or every role when called without one |
| `access_risky([max_depth])` | Database-wide finder: PUBLIC grants, powerful roles, `rds_superuser` members, ineffective default privileges, deep chains, cycles |
| `access_help()` | The list above with an example call for each |

Helpers are named `access__*` (two underscores). They are internal and may
change.

## Install

```sh
psql -X -v ON_ERROR_STOP=1 -d mydb -f install.sql
```

Install once per database you want to inspect. Everything goes into the
`public` schema, named `access_*`, inside one transaction. Running it again
replaces the functions in place.

To remove it:

```sh
psql -X -v ON_ERROR_STOP=1 -d mydb -f uninstall.sql
```

`uninstall.sql` drops every function `install.sql` created and nothing else.

### Required privileges

- **To install:** `CREATE` on schema `public`. On PostgreSQL 15 and later
  ordinary roles do not have this by default, so install as the database owner
  or, on RDS / Aurora, the master user (a member of `rds_superuser`). On 14,
  `PUBLIC` still has `CREATE` on `public` unless you revoked it.
- **To call:** nothing special. `public` is on every role's default
  `search_path` and functions are executable by `PUBLIC` by default. The
  functions read only catalogs every role can read, so any role can check any
  other role.

If your database revoked `EXECUTE` from `PUBLIC` by default, grant it to the
DBA roles that need it:

```sql
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO dba_team;  -- or name the access_* functions
```

## Quick start

The five calls that cover most tickets:

```sql
-- 1. Can app_user read sales.orders? If not, why not, and what fixes it?
SELECT * FROM access_why('app_user', 'sales.orders', 'SELECT');

-- 2. Explain an error from the application log (add the STATEMENT: line if you have it)
SELECT * FROM access_explain_error('ERROR:  permission denied for table orders', 'app_user');

-- 3. Every role app_user inherits from, with the path to each
SELECT * FROM access_chain('app_user');

-- 4. Why can one user do it and the other can't?
SELECT * FROM access_compare('app_user', 'app_user2', 'sales.orders');

-- 5. "New tables aren't readable": which creators' tables are not covered
SELECT * FROM access_default_privileges('app_user');
```

[EXAMPLES.md](EXAMPLES.md) walks through real scenarios with their output.

### Reading `access_why`

The first row (`step 0`, `answer`) is the verdict. The rows after it are the
checks that led to it:

| `answer` | Meaning |
|---|---|
| `YES` | The privilege, schema USAGE and database CONNECT are all in place |
| `YES, RLS FILTERS ROWS` | Allowed, but row level security policies limit the rows |
| `YES, BUT RLS BLOCKS ALL ROWS` | Allowed, but RLS is on and no policy applies, so the role sees zero rows without an error |
| `ONLY AFTER SET ROLE` | The grant is on a role it belongs to without inheriting (NOINHERIT, PG16 `INHERIT FALSE`, or a superuser role) |
| `COLUMNS ONLY` | Only column-level grants: `SELECT *` fails, named columns work |
| `NO` | Something is missing; the `detail` says what, `suggested_fix` says how |

The privilege check is confirmed with PostgreSQL's own `has_table_privilege()`,
`has_schema_privilege()` and related functions. The tool's job is to explain
the server's answer, not to second-guess it.

Object names can be schema-qualified (`sales.orders`), quoted
(`sales."Daily Report"`), functions with argument types
(`sales.calc_total(integer)`), schemas or databases. An unqualified name is
looked up in every schema, so `orders` in two schemas returns both. Pass
`object_type` (`table`, `view`, `sequence`, `function`, `schema`, `database`)
to narrow it.

## No-install version

For databases where you cannot create functions,
[`psql/access_checks.sql`](psql/access_checks.sql) runs the main checks as
plain queries. It creates nothing and runs inside a read-only transaction:

```sh
psql -X -d mydb -v role=app_user -v object=sales.orders -v action=SELECT -f psql/access_checks.sql
```

It prints the membership chain, the why-check (privilege with its sources,
schema USAGE, CONNECT, column grants, RLS), the role's privileges, default
privileges, who can access the object, and red flags. It is less detailed than
the functions: no error parsing, comparison or suggested fixes.

## Version notes

| Version | What changes |
|---|---|
| 14, 15 | Inheritance is a property of the member role (`INHERIT` / `NOINHERIT`). Any member can `SET ROLE`. `hop_set` is always true. |
| 15+ | `public` is owned by `pg_database_owner` and `PUBLIC` loses `CREATE` on it. The database owner's implicit membership in `pg_database_owner` is shown in the chain. |
| 16+ | Each grant has its own `INHERIT`, `SET` and `ADMIN` options, and one membership can exist from several grantors. A membership can inherit without allowing `SET ROLE`, allow `SET ROLE` without inheriting, or do neither. All three are reported. |
| 17 | The `MAINTAIN` privilege and the `pg_maintain` role are recognised. |

The version is detected at run time. The PG16 `pg_auth_members` columns are
read through `to_jsonb()` of the catalog row, so the same functions run on
every version without dynamic SQL.

Predefined roles are understood: `pg_read_all_data` and `pg_write_all_data`
(including their implicit schema USAGE), `pg_maintain`, and
`pg_database_owner`.

## RDS and Aurora notes

- `rds_superuser` is an ordinary role, not a real superuser. Its members are
  reported as high-risk (`access_red_flags`, `access_risky`), which is expected
  for the master user.
- Attributes on `rds_superuser` and `rdsadmin` are AWS-managed. They are shown
  as INFO with no suggested fix.
- `rds.force_ssl`, IAM authentication (`rds_iam`) and `pg_hba.conf` rules are
  outside what SQL can see on RDS. If a role cannot log in at all and these
  functions show CONNECT, look there.
- `VALID UNTIL` expires the password only. It does not affect IAM
  authentication.

## Safety

- Every function is `STABLE` (or `IMMUTABLE`), `SECURITY INVOKER`, and pins
  `search_path = pg_catalog, pg_temp`.
- They only read system catalogs and call `has_*_privilege()` /
  `pg_has_role()`. No writes, no dynamic SQL, no DDL. The test suite runs every
  function inside `BEGIN TRANSACTION READ ONLY`.
- Suggested fixes are returned as text. Review them before you run them; the
  `CREATE POLICY` suggestions are templates with placeholders.

## Limitations

- `pg_hba.conf`, `rds.force_ssl` and authentication method problems are not
  covered in v1.
- PostgreSQL does not record when a role last logged in, so unused login roles
  cannot be found from SQL. `access_risky` says so and points to
  `log_connections`, pgAudit or CloudWatch.
- Privileges on types, languages, large objects, tablespaces, foreign servers
  and foreign-data wrappers are not analysed.
- `SECURITY DEFINER` functions and views run with their owner's privileges.
  `access_why` checks the object you name, not the objects a view or function
  touches underneath.
- Membership paths are followed to 64 levels. Graphs with a very large number
  of overlapping paths make `access_chain` long, because it lists every path.
- Default privilege gaps (`NOT COVERED`) are reported for schemas where the
  role already reads at least one table, and only for tables.

## Tests

`tests/run_tests.sh` creates a throwaway cluster, loads
[`tests/fixture.sql`](tests/fixture.sql) (a 4-level chain, a NOINHERIT hop,
PG16 SET-only and INHERIT-only memberships, column grants, RLS, default
privileges per creator, PUBLIC grants, expired and locked roles, a forced
membership cycle), installs the functions and runs
[`tests/test_inspector.py`](tests/test_inspector.py). Where possible the tests
check a claim against what PostgreSQL really does: they log in as the role and
run the statement, or apply the suggested fix inside a rolled-back transaction
and confirm the statement then works.

```sh
PG_BINDIR=/usr/lib/postgresql/17/bin tests/run_tests.sh             # run the tests
PG_BINDIR=/usr/lib/postgresql/17/bin tests/run_tests.sh --examples  # regenerate EXAMPLES.md
PG_BINDIR=/usr/lib/postgresql/17/bin tests/run_tests.sh --shell     # explore the fixture
```

CI runs the suite on PostgreSQL 14, 15, 16 and 17.

## License

MIT. See [LICENSE](LICENSE).
