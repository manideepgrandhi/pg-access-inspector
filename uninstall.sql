-- pg-access-inspector -- uninstall.sql
-- Drops every function install.sql created. Touches nothing else.
BEGIN;
DROP FUNCTION IF EXISTS public.access_help();
DROP FUNCTION IF EXISTS public.access_risky(integer);
DROP FUNCTION IF EXISTS public.access_tree_mermaid(text, text);
DROP FUNCTION IF EXISTS public.access_tree(text, text);
DROP FUNCTION IF EXISTS public.access__tree_lines(oid, text, text, oid[]);
DROP FUNCTION IF EXISTS public.access_compare(text, text, text);
DROP FUNCTION IF EXISTS public.access_explain_error(text, text, text);
DROP FUNCTION IF EXISTS public.access_red_flags(text);
DROP FUNCTION IF EXISTS public.access_who_can(text, text, text, boolean);
DROP FUNCTION IF EXISTS public.access_default_privileges(text, text);
DROP FUNCTION IF EXISTS public.access_privileges(text, boolean);
DROP FUNCTION IF EXISTS public.access_trigger_check(text, text);
DROP FUNCTION IF EXISTS public.access_function_check(regprocedure, text);
DROP FUNCTION IF EXISTS public.access_function_check(text, text);
DROP FUNCTION IF EXISTS public.access__function_check(oid, oid);
DROP FUNCTION IF EXISTS public.access__find(text, text, text);
DROP FUNCTION IF EXISTS public.access__body_refs(text, text);
DROP FUNCTION IF EXISTS public.access__name_at(text[], text[], integer);
DROP FUNCTION IF EXISTS public.access__tokens(text);
DROP FUNCTION IF EXISTS public.access_why(text, text, text, text);
DROP FUNCTION IF EXISTS public.access_chain(text);
DROP FUNCTION IF EXISTS public.access__is_system_schema(name);
DROP FUNCTION IF EXISTS public.access__fmt(text, text, text);
DROP FUNCTION IF EXISTS public.access__sources(oid, aclitem[], text, oid, text);
DROP FUNCTION IF EXISTS public.access__has(oid, text, oid, text);
DROP FUNCTION IF EXISTS public.access__objects(text, text);
DROP FUNCTION IF EXISTS public.access__keyword(text, boolean);
DROP FUNCTION IF EXISTS public.access__valid_privs(text);
DROP FUNCTION IF EXISTS public.access__kind_matches(text, text);
DROP FUNCTION IF EXISTS public.access__break(oid[]);
DROP FUNCTION IF EXISTS public.access__reach(oid);
DROP FUNCTION IF EXISTS public.access__walk(oid, text);
DROP FUNCTION IF EXISTS public.access__edges();
DROP FUNCTION IF EXISTS public.access__role(text);

-- Safety net: anything else in public carrying the install marker
-- (for example an overload left behind by a different version).
DO $$
DECLARE f regprocedure;
BEGIN
  FOR f IN SELECT p.oid::regprocedure FROM pg_proc p
            WHERE p.pronamespace = 'public'::regnamespace
              AND p.proname LIKE 'access\_%'
              AND obj_description(p.oid, 'pg_proc') LIKE 'pg-access-inspector:%'
  LOOP
    EXECUTE format('DROP FUNCTION %s', f);
  END LOOP;
END
$$;
COMMIT;
