-- KARLION Phase 1 / migration 1: tenancy, membership, RLS helper functions.
-- Principles: every business table carries organization_id; RLS keys off membership;
-- clients get only the grants they need; sensitive writes go through the backend (service_role).

create schema if not exists app;           -- internal helpers; NOT exposed through the API
revoke all on schema app from public;
grant usage on schema app to authenticated, service_role;

create type public.app_role as enum ('owner', 'admin', 'member', 'viewer');

create table public.organizations (
  id         uuid primary key default gen_random_uuid(),
  name       text not null check (length(trim(name)) > 0),
  slug       text not null unique check (slug ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table public.memberships (
  id              uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations (id) on delete cascade,
  user_id         uuid not null references auth.users (id) on delete cascade,
  role            public.app_role not null,
  created_at      timestamptz not null default now(),
  unique (organization_id, user_id)
);
create index memberships_user_idx on public.memberships (user_id);

-- Generic updated_at trigger.
create function app.set_updated_at() returns trigger
language plpgsql set search_path = '' as $$
begin
  new.updated_at := now();
  return new;
end $$;

create trigger organizations_set_updated_at
  before update on public.organizations
  for each row execute function app.set_updated_at();

-- RLS helpers. SECURITY DEFINER so policies on memberships cannot recurse into themselves.
create function app.is_member(org uuid) returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (
    select 1 from public.memberships m
    where m.organization_id = org and m.user_id = (select auth.uid())
  );
$$;

create function app.has_role(org uuid, roles public.app_role[]) returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (
    select 1 from public.memberships m
    where m.organization_id = org
      and m.user_id = (select auth.uid())
      and m.role = any (roles)
  );
$$;

revoke all on function app.is_member(uuid) from public;
revoke all on function app.has_role(uuid, public.app_role[]) from public;
grant execute on function app.is_member(uuid) to authenticated, service_role;
grant execute on function app.has_role(uuid, public.app_role[]) to authenticated, service_role;

-- RLS
alter table public.organizations enable row level security;
alter table public.memberships  enable row level security;

revoke all on public.organizations, public.memberships from anon, authenticated;
grant select on public.organizations, public.memberships to authenticated;
grant all on public.organizations, public.memberships to service_role;

create policy organizations_select on public.organizations
  for select to authenticated
  using (app.is_member(id));

-- A user sees their own membership; owners/admins see everyone in their org.
create policy memberships_select on public.memberships
  for select to authenticated
  using (
    user_id = (select auth.uid())
    or app.has_role(organization_id, array['owner', 'admin']::public.app_role[])
  );
-- No client INSERT/UPDATE/DELETE policies: membership changes are backend-only and audited.
