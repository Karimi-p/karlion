-- KARLION Phase 1 / migration 4: Tasks (vertical slice) and organization bootstrap.

create table public.tasks (
  id                uuid primary key default gen_random_uuid(),
  organization_id   uuid not null references public.organizations (id) on delete cascade,
  title             text not null check (length(trim(title)) between 1 and 300),
  description       text,
  status            text not null default 'todo' check (status in ('todo', 'in_progress', 'blocked', 'done', 'cancelled')),
  priority          text not null default 'normal' check (priority in ('low', 'normal', 'high', 'urgent')),
  due_at            timestamptz,
  assignee_user_id  uuid references auth.users (id) on delete set null,
  assignee_agent_id uuid,                       -- FK added when the agents table lands (Phase 3)
  project_id        uuid,                       -- FK added when projects land (Phase 2)
  created_by        uuid references auth.users (id) on delete set null,
  completed_at      timestamptz,
  created_at        timestamptz not null default now(),
  updated_at        timestamptz not null default now(),
  check (assignee_user_id is null or assignee_agent_id is null)
);
create index tasks_org_status_due_idx on public.tasks (organization_id, status, due_at);
create index tasks_assignee_idx on public.tasks (assignee_user_id) where assignee_user_id is not null;

create function app.tasks_before_write() returns trigger
language plpgsql set search_path = '' as $$
begin
  new.updated_at := now();
  if tg_op = 'INSERT' then
    new.created_by := coalesce(new.created_by, (select auth.uid()));
  end if;
  if new.status = 'done' and (tg_op = 'INSERT' or old.status is distinct from 'done') then
    new.completed_at := now();
  elsif new.status <> 'done' then
    new.completed_at := null;
  end if;
  return new;
end $$;

create function app.tasks_emit() returns trigger
language plpgsql security definer set search_path = '' as $$
declare v_payload jsonb;
begin
  v_payload := jsonb_build_object('task_id', new.id, 'title', new.title, 'status', new.status,
                                  'priority', new.priority, 'due_at', new.due_at);
  if tg_op = 'INSERT' then
    perform app.emit_event(new.organization_id, 'task.created', 'task', new.id, v_payload);
  elsif new.status is distinct from old.status then
    perform app.emit_event(new.organization_id,
      case when new.status = 'done' then 'task.completed' else 'task.status_changed' end,
      'task', new.id, v_payload || jsonb_build_object('previous_status', old.status));
  end if;
  return null;
end $$;

create trigger tasks_before_write before insert or update on public.tasks
  for each row execute function app.tasks_before_write();
create trigger tasks_audit after insert or update on public.tasks
  for each row execute function app.audit_row();
create trigger tasks_emit after insert or update on public.tasks
  for each row execute function app.tasks_emit();

alter table public.tasks enable row level security;
revoke all on public.tasks from anon, authenticated;
-- No DELETE for clients: deleting is a destructive operation and goes through the approval gate.
-- Use status = 'cancelled' for normal removal.
grant select, insert, update on public.tasks to authenticated;
grant all on public.tasks to service_role;

create policy tasks_select on public.tasks
  for select to authenticated using (app.is_member(organization_id));
create policy tasks_insert on public.tasks
  for insert to authenticated
  with check (app.has_role(organization_id, array['owner', 'admin', 'member']::public.app_role[]));
create policy tasks_update on public.tasks
  for update to authenticated
  using (app.has_role(organization_id, array['owner', 'admin', 'member']::public.app_role[]))
  with check (app.has_role(organization_id, array['owner', 'admin', 'member']::public.app_role[]));

-- Create an organization with its first owner and default settings. Backend/CLI only.
create function public.bootstrap_organization(p_name text, p_slug text, p_owner uuid) returns uuid
language plpgsql security definer set search_path = '' as $$
declare v_org uuid;
begin
  insert into public.organizations (name, slug) values (p_name, p_slug) returning id into v_org;
  insert into public.memberships (organization_id, user_id, role) values (v_org, p_owner, 'owner');
  insert into public.company_settings (organization_id) values (v_org);
  return v_org;
end $$;
revoke all on function public.bootstrap_organization(text, text, uuid) from public, anon, authenticated;
grant execute on function public.bootstrap_organization(text, text, uuid) to service_role;
