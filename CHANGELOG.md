# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [1.1.0] - Unreleased

### Added
- `access_function_check(function [, caller_role])`: whose privileges count
  inside a function (owner for SECURITY DEFINER, caller for SECURITY INVOKER),
  owner and its login flag, schema owner, pinned `search_path`, language, and a
  best-effort scan of PL/pgSQL and SQL bodies. Every table, sequence and
  function the body names is checked for the effective role, with the line
  number, schema USAGE, the missing grant and a suggested fix. Flags SECURITY
  DEFINER without a pinned or with an unsafe `search_path`, an owner without
  USAGE on its own schema, and owner grants that only arrive through NOINHERIT
  memberships. Dynamic SQL and unresolvable names are reported as `CANNOT
  VERIFY`. Accepts text or `regprocedure`.
- `access_trigger_check(table [, caller_role])`: every user trigger on a table
  with timing, events and enabled state, the caller's own privilege for the
  triggering events, and `access_function_check` for each trigger function.
- `access_report(role [, schema [, include_public]])`: full access report,
  one row per privilege per membership path, at role level (attributes,
  memberships, predefined roles such as `pg_read_all_data` and
  `rds_superuser`), database level (CONNECT, CREATE, TEMPORARY on every
  database, PUBLIC defaults, ownership), schema level and object level
  (tables, views, materialized views, foreign tables, sequences, functions,
  procedures, column grants, ownership). `via` is `direct`, `owner`, `PUBLIC`
  or the full chain; paths through a NOINHERIT member or a PG16+ `INHERIT
  FALSE` grant are labeled `needs SET ROLE: ...`. A superuser gets a single
  `superuser` row. `schema` limits schema and object rows; `include_public =>
  false` drops PUBLIC rows.
- `psql/access_checks.sql`: section 9 (`-v report=1`, optional `-v schema=...`
  and `-v include_public=off`), the same rows as `access_report`.
- `psql/access_checks.sql`: sections 7 (`-v function=...`) and 8
  (`-v table=...`) for a function's effective role and a table's triggers.
- Tests for all three, verified against the server, on PostgreSQL 14 to 17.

### Changed
- `access_explain_error` reads `CONTEXT:` / `Where:` lines (`PL/pgSQL function
  X line N`, `SQL function "X" statement N`). When the statement ran inside a
  SECURITY DEFINER function it checks the function owner instead of the
  caller, shows the statement at line N, the objects it names, and states
  whose privilege is missing (`whose privilege: OWNER ...` or `CALLER ...`).
  The fix covers the whole failing statement, replaces `SET ROLE` advice with
  direct grants where `SET ROLE` cannot work, and drops database CONNECT
  checks for errors raised inside a function. Messages without a function
  context behave as before.
- Function names with argument types now resolve even when the caller has no
  USAGE on the function's schema.
- `access_risky` no longer reports PUBLIC EXECUTE on SECURITY DEFINER trigger
  functions: they cannot be called directly.

## [1.0.0] - Unreleased

### Added
- `access_why`: yes/no for an action on a table, view, materialized view,
  sequence, function, foreign table, schema or database, with the role in the
  chain that supplied the grant and checks for schema USAGE, database CONNECT,
  column grants, row level security, NOINHERIT hops and superuser.
- `access_explain_error`: parses `permission denied for ...`, `must be owner of
  ...`, `permission denied to set role ...` and RLS violation messages and
  returns the missing grant with a suggested fix (text only, never executed).
  Lists candidate actions when the message is ambiguous.
- `access_chain`, `access_tree`, `access_tree_mermaid`: membership chain with
  full paths and per-hop INHERIT / SET / ADMIN options; cycle-safe.
- `access_privileges`, `access_who_can`, `access_default_privileges`,
  `access_compare`, `access_red_flags`, `access_risky`, `access_help`.
- `psql/access_checks.sql`: no-install, read-only psql version of the main checks.
- Support for PostgreSQL / Aurora PostgreSQL 14 to 17, including PG16 per-grant
  membership options, predefined roles and `pg_database_owner`.
- Test suite and CI on PostgreSQL 14, 15, 16 and 17.
