-- TEST FIXTURES ONLY: this file creates objects in a throwaway local database.
CREATE ROLE anon NOLOGIN;
CREATE ROLE authenticated NOLOGIN;
GRANT USAGE ON SCHEMA public TO anon, authenticated;

CREATE TABLE public.open_write (id integer);
GRANT SELECT, INSERT, UPDATE, DELETE ON public.open_write TO anon;

CREATE TABLE public.open_read (id integer);
GRANT SELECT ON public.open_read TO anon;

CREATE TABLE public.member_read (id integer);
GRANT SELECT ON public.member_read TO authenticated;

CREATE TABLE public.default_deny (id integer);
ALTER TABLE public.default_deny ENABLE ROW LEVEL SECURITY;
GRANT SELECT ON public.default_deny TO anon;

CREATE TABLE public.has_policy (id integer);
ALTER TABLE public.has_policy ENABLE ROW LEVEL SECURITY;
CREATE POLICY allow_all ON public.has_policy FOR SELECT USING (true);
GRANT SELECT ON public.has_policy TO anon;

CREATE FUNCTION public.unsafe_write() RETURNS void
LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
  UPDATE public.open_write SET id = 2;
END;
$$;

CREATE FUNCTION public.auth_reference_only() RETURNS text
LANGUAGE sql SECURITY DEFINER AS $$
  SELECT 'auth.uid() appears in a string, not a check'::text;
$$;

CREATE FUNCTION public.member_function() RETURNS integer
LANGUAGE sql SECURITY DEFINER AS $$ SELECT 1; $$;

REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.unsafe_write() TO anon;
GRANT EXECUTE ON FUNCTION public.auth_reference_only() TO anon;
GRANT EXECUTE ON FUNCTION public.member_function() TO authenticated;

CREATE SCHEMA private;
CREATE FUNCTION private.hidden() RETURNS integer
LANGUAGE sql SECURITY DEFINER AS $$ SELECT 1; $$;
GRANT EXECUTE ON FUNCTION private.hidden() TO anon;
-- No private-schema USAGE: the hidden function must not appear.
