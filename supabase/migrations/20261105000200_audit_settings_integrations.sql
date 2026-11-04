-- KARLION Phase 1 / migration 2: append-only audit log, company settings, integrations, notifications.

create table public.activity_logs (
  id              uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations (id) on delete cascade,
  occurred_at     timestamptz not null default now(),
  actor_type      text not null check (actor_type in ('user', 'agent', 'system', 'integration')),
  actor_id        uuid,
  action          text not null,
  entity_type     text not null,
  entity_id       uuid,
  changes         jsonb,
  correlation_id  uuid,
  metadata        jsonb not null default '{}'::jsonb
);
create index activity_logs_org_time_idx on public.activity_logs (organization_id, occurred_at desc);
create index activity_logs_entity_idx   on public.activity_logs (entity_type, entity_id);

-- Append-only: nobody (including service_role) can rewrite history.
create function app.activity_logs_immutable() returns trigger
language plpgsql set search_path = '' as $$
begin
  raise exception 'activity_logs is append-only' using errcode = 'insufficient_privilege';
end $$;

create trigger activity_logs_no_update_delete
  before update or delete on public.activity_logs
  for each row execute function app.activity_logs_immutable();
create trigger activity_logs_no_truncate
  before truncate on public.activity_logs
  for each statement execute function app.activity_logs_immutable();

-- Generic row-level audit trigger. Runs in the same transaction as the change.
-- Actor: the authenticated user if there is one. In a backend (service_role) context the
-- caller may declare an agent/integration actor via set_config('app.actor_type'|'app.actor_id', ..., true).
-- That override is ignored whenever an end user is authenticated, so clients cannot spoof it.
create function app.audit_row() returns trigger
language plpgsql security definer set search_path = '' as $$
declare
  v_row   jsonb;
  v_org   uuid;
  v_id    uuid;
  v_uid   uuid := (select auth.uid());
  v_type  text;
  v_actor uuid;
begin
  v_row := case when tg_op = 'DELETE' then to_jsonb(old) else to_jsonb(new) end;
  v_org := (v_row ->> 'organization_id')::uuid;
  v_id  := coalesce((v_row ->> 'id')::uuid, v_org);

  if v_uid is not null then
    v_type := 'user';
    v_actor := v_uid;
  else
    v_type := coalesce(nullif(current_setting('app.actor_type', true), ''), 'system');
    if v_type not in ('agent', 'integration', 'system') then v_type := 'system'; end if;
    v_actor := nullif(current_setting('app.actor_id', true), '')::uuid;
  end if;

  insert into public.activity_logs (organization_id, actor_type, actor_id, action, entity_type, entity_id, changes, correlation_id)
  values (
    v_org, v_type, v_actor,
    tg_table_name || '.' || lower(tg_op), tg_table_name, v_id,
    case tg_op
      when 'INSERT' then jsonb_build_object('new', to_jsonb(new))
      when 'DELETE' then jsonb_build_object('old', to_jsonb(old))
      else jsonb_build_object('old', to_jsonb(old), 'new', to_jsonb(new))
    end,
    nullif(current_setting('app.correlation_id', true), '')::uuid
  );
  return null;
end $$;

create table public.company_settings (
  organization_id     uuid primary key references public.organizations (id) on delete cascade,
  base_currency       char(3) not null default 'KES' check (base_currency ~ '^[A-Z]{3}$'),
  timezone            text not null default 'Africa/Nairobi',
  fiscal_year_start_month smallint not null default 1 check (fiscal_year_start_month between 1 and 12),
  -- Which action types need human approval, and optional KES thresholds (minor units).
  approval_policy     jsonb not null default '{
    "financial_transaction": {"required": true},
    "production_deployment": {"required": true},
    "destructive_operation": {"required": true},
    "external_commitment":   {"required": true}
  }'::jsonb,
  feature_flags       jsonb not null default '{}'::jsonb,
  created_at          timestamptz not null default now(),
  updated_at          timestamptz not null default now()
);
create trigger company_settings_set_updated_at before update on public.company_settings
  for each row execute function app.set_updated_at();
create trigger company_settings_audit after insert or update or delete on public.company_settings
  for each row execute function app.audit_row();

create table public.integrations (
  id                    uuid primary key default gen_random_uuid(),
  organization_id       uuid not null references public.organizations (id) on delete cascade,
  provider              text not null check (provider in ('slack', 'telegram', 'github', 'n8n', 'vercel', 'supabase')),
  name                  text not null,
  status                text not null default 'unconfigured' check (status in ('unconfigured', 'configured', 'verified', 'failing', 'disabled')),
  config                jsonb not null default '{}'::jsonb,   -- NON-secret settings only
  secret_ref            text,                                  -- pointer (env var name / vault id); never the secret itself
  last_health_check_at  timestamptz,
  last_health_status    text,
  created_at            timestamptz not null default now(),
  updated_at            timestamptz not null default now(),
  unique (organization_id, provider, name)
);
create trigger integrations_set_updated_at before update on public.integrations
  for each row execute function app.set_updated_at();
create trigger integrations_audit after insert or update or delete on public.integrations
  for each row execute function app.audit_row();

create table public.notifications (
  id              uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations (id) on delete cascade,
  channel         text not null check (channel in ('slack', 'telegram', 'email', 'in_app')),
  target          text not null,                  -- e.g. slack channel key; not a secret
  template        text not null,
  payload         jsonb not null default '{}'::jsonb,
  status          text not null default 'pending' check (status in ('pending', 'sent', 'failed', 'suppressed')),
  attempts        integer not null default 0,
  dedupe_key      text,
  error           text,
  created_at      timestamptz not null default now(),
  sent_at         timestamptz
);
create unique index notifications_dedupe_idx on public.notifications (organization_id, dedupe_key) where dedupe_key is not null;
create index notifications_status_idx on public.notifications (organization_id, status, created_at);

-- RLS + least-privilege grants.
alter table public.activity_logs  enable row level security;
alter table public.company_settings enable row level security;
alter table public.integrations   enable row level security;
alter table public.notifications  enable row level security;

revoke all on public.activity_logs, public.company_settings, public.integrations, public.notifications from anon, authenticated;
revoke update, delete, truncate on public.activity_logs from service_role;

grant select on public.activity_logs to authenticated;
grant select, update on public.company_settings to authenticated;
-- Column-level grant: clients can never read secret_ref.
grant select (id, organization_id, provider, name, status, config, last_health_check_at, last_health_status, created_at, updated_at)
  on public.integrations to authenticated;
grant select on public.notifications to authenticated;

grant select, insert on public.activity_logs to service_role;
grant all on public.company_settings, public.integrations, public.notifications to service_role;

create policy activity_logs_select on public.activity_logs
  for select to authenticated
  using (app.has_role(organization_id, array['owner', 'admin']::public.app_role[]));

create policy company_settings_select on public.company_settings
  for select to authenticated using (app.is_member(organization_id));
create policy company_settings_update on public.company_settings
  for update to authenticated
  using (app.has_role(organization_id, array['owner', 'admin']::public.app_role[]))
  with check (app.has_role(organization_id, array['owner', 'admin']::public.app_role[]));

create policy integrations_select on public.integrations
  for select to authenticated
  using (app.has_role(organization_id, array['owner', 'admin']::public.app_role[]));

create policy notifications_select on public.notifications
  for select to authenticated
  using (app.has_role(organization_id, array['owner', 'admin']::public.app_role[]));
