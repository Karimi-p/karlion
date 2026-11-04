-- TEST-ONLY. Minimal stand-in for the parts of Supabase our migrations depend on
-- (auth.users, auth.uid(), the three API roles, the extensions schema).
-- Real Supabase provides all of these itself; this file is never applied to a real project.
-- Passing these tests proves the SQL logic on vanilla Postgres, NOT behaviour on Supabase.

create schema auth;
create table auth.users (id uuid primary key default gen_random_uuid(), email text);
create function auth.uid() returns uuid language sql stable as $$
  select nullif(current_setting('request.jwt.claim.sub', true), '')::uuid
$$;

create schema extensions;
create extension if not exists pgcrypto with schema extensions;

create role anon nologin;
create role authenticated nologin;
create role service_role nologin bypassrls;

grant usage on schema public, auth, extensions to anon, authenticated, service_role;
grant execute on function auth.uid() to anon, authenticated, service_role;
-- Supabase leaves ordinary tables with no automatic grants here; our migrations grant explicitly.
