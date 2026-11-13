# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

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
