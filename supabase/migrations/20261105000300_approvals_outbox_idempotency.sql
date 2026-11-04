-- KARLION Phase 1 / migration 3: approval gate, transactional outbox, webhook idempotency.

---------------------------------------------------------------------------------------------
-- Outbox: events are written in the same transaction as the state change, delivered later.
---------------------------------------------------------------------------------------------
create table public.outbox_events (
  id              uuid primary key default gen_random_uuid(),   -- doubles as the webhook idempotency key
  organization_id uuid not null references public.organizations (id) on delete cascade,
  event_type      text not null,
  aggregate_type  text not null,
  aggregate_id    uuid,
  payload         jsonb not null default '{}'::jsonb,
  status          text not null default 'pending' check (status in ('pending', 'delivering', 'delivered', 'dead')),
  attempts        integer not null default 0,
  next_attempt_at timestamptz not null default now(),
  locked_until    timestamptz,
  last_error      text,
  created_at      timestamptz not null default now(),
  delivered_at    timestamptz
);
create index outbox_ready_idx on public.outbox_events (next_attempt_at) where status in ('pending', 'delivering');

create function app.emit_event(p_org uuid, p_type text, p_agg_type text, p_agg_id uuid, p_payload jsonb)
returns void language sql security definer set search_path = '' as $$
  insert into public.outbox_events (organization_id, event_type, aggregate_type, aggregate_id, payload)
  values (p_org, p_type, p_agg_type, p_agg_id, coalesce(p_payload, '{}'::jsonb));
$$;
revoke all on function app.emit_event(uuid, text, text, uuid, jsonb) from public;

-- Claim a batch with a lease (SKIP LOCKED so parallel dispatchers never double-send).
create function public.claim_outbox_batch(p_limit integer default 20, p_lease_seconds integer default 60)
returns setof public.outbox_events
language sql security definer set search_path = '' as $$
  with c as (
    select id from public.outbox_events
    where (status = 'pending' and next_attempt_at <= now())
       or (status = 'delivering' and locked_until < now())
    order by created_at
    limit greatest(1, least(p_limit, 100))
    for update skip locked
  )
  update public.outbox_events o
     set status = 'delivering',
         locked_until = now() + make_interval(secs => p_lease_seconds),
         attempts = o.attempts + 1
    from c
   where o.id = c.id
  returning o.*;
$$;

create function public.outbox_mark_delivered(p_id uuid) returns void
language sql security definer set search_path = '' as $$
  update public.outbox_events
     set status = 'delivered', delivered_at = now(), locked_until = null, last_error = null
   where id = p_id;
$$;

-- Exponential backoff (30s, 60s, 120s ... capped at 1h); dead-letter after p_max_attempts.
create function public.outbox_mark_failed(p_id uuid, p_error text, p_max_attempts integer default 8) returns void
language sql security definer set search_path = '' as $$
  update public.outbox_events
     set status = case when attempts >= p_max_attempts then 'dead' else 'pending' end,
         next_attempt_at = now() + make_interval(secs => least(3600, 30 * power(2, greatest(attempts - 1, 0)))::int),
         locked_until = null,
         last_error = left(p_error, 1000)
   where id = p_id;
$$;

---------------------------------------------------------------------------------------------
-- Idempotency receipts for inbound webhooks.
---------------------------------------------------------------------------------------------
create table public.idempotency_keys (
  scope           text not null,
  key             text not null,
  request_hash    text not null,
  status          text not null default 'in_progress' check (status in ('in_progress', 'completed')),
  response        jsonb,
  response_status integer,
  created_at      timestamptz not null default now(),
  expires_at      timestamptz not null default now() + interval '7 days',
  primary key (scope, key)
);

create function public.idempotency_claim(p_scope text, p_key text, p_request_hash text)
returns table (outcome text, response jsonb, response_status integer)
language plpgsql security definer set search_path = '' as $$
declare r public.idempotency_keys;
begin
  insert into public.idempotency_keys (scope, key, request_hash)
  values (p_scope, p_key, p_request_hash)
  on conflict (scope, key) do nothing
  returning * into r;
  if found then
    return query select 'new'::text, null::jsonb, null::integer; return;
  end if;

  select * into r from public.idempotency_keys k where k.scope = p_scope and k.key = p_key for update;
  if r.request_hash <> p_request_hash then
    return query select 'conflict'::text, null::jsonb, null::integer; return;
  end if;
  if r.status = 'completed' then
    return query select 'replay'::text, r.response, r.response_status; return;
  end if;
  -- A crashed handler leaves 'in_progress' behind; allow a retry after 5 minutes.
  if r.created_at < now() - interval '5 minutes' then
    update public.idempotency_keys k set created_at = now() where k.scope = p_scope and k.key = p_key;
    return query select 'new'::text, null::jsonb, null::integer; return;
  end if;
  return query select 'in_progress'::text, null::jsonb, null::integer;
end $$;

create function public.idempotency_complete(p_scope text, p_key text, p_response jsonb, p_status integer) returns void
language sql security definer set search_path = '' as $$
  update public.idempotency_keys
     set status = 'completed', response = p_response, response_status = p_status
   where scope = p_scope and key = p_key;
$$;

-- If a handler fails, release the key so the sender's retry is processed immediately.
create function public.idempotency_release(p_scope text, p_key text) returns void
language sql security definer set search_path = '' as $$
  delete from public.idempotency_keys where scope = p_scope and key = p_key and status = 'in_progress';
$$;

---------------------------------------------------------------------------------------------
-- Approvals: immutable request payload, human-only decision, exactly-once execution claim.
---------------------------------------------------------------------------------------------
create table public.approvals (
  id                uuid primary key default gen_random_uuid(),
  organization_id   uuid not null references public.organizations (id) on delete cascade,
  action_type       text not null check (action_type in
                      ('financial_transaction', 'production_deployment', 'destructive_operation', 'external_commitment')),
  summary           text not null check (length(trim(summary)) > 0),
  payload           jsonb not null,
  payload_hash      text not null,
  requested_by_type text not null check (requested_by_type in ('user', 'agent', 'system', 'integration')),
  requested_by_id   uuid,
  status            text not null default 'pending'
                      check (status in ('pending', 'approved', 'rejected', 'expired', 'executing', 'executed', 'failed')),
  expires_at        timestamptz not null default now() + interval '24 hours',
  -- decided_by references auth.users: only a human account can ever decide. Agents have no user row.
  decided_by        uuid references auth.users (id),
  decided_at        timestamptz,
  decision_note     text,
  executed_at       timestamptz,
  execution_error   text,
  created_at        timestamptz not null default now(),
  updated_at        timestamptz not null default now(),
  check ((status in ('approved', 'rejected', 'executing', 'executed', 'failed')) = (decided_by is not null))
);
create index approvals_org_status_idx on public.approvals (organization_id, status, created_at desc);

create function app.approvals_guard() returns trigger
language plpgsql set search_path = '' as $$
begin
  if tg_op = 'INSERT' then
    new.payload_hash := encode(extensions.digest(convert_to(new.payload::text, 'utf8'), 'sha256'), 'hex');
    new.status := 'pending';
    new.decided_by := null; new.decided_at := null;
    return new;
  end if;

  if new.payload is distinct from old.payload
     or new.payload_hash is distinct from old.payload_hash
     or new.action_type is distinct from old.action_type
     or new.organization_id is distinct from old.organization_id
     or new.requested_by_type is distinct from old.requested_by_type
     or new.requested_by_id is distinct from old.requested_by_id then
    raise exception 'approval request is immutable' using errcode = 'integrity_constraint_violation';
  end if;

  if new.status is distinct from old.status and not (
       (old.status = 'pending'   and new.status in ('approved', 'rejected', 'expired'))
    or (old.status = 'approved'  and new.status in ('executing', 'expired'))
    or (old.status = 'executing' and new.status in ('executed', 'failed'))
  ) then
    raise exception 'illegal approval transition % -> %', old.status, new.status
      using errcode = 'integrity_constraint_violation';
  end if;
  new.updated_at := now();
  return new;
end $$;

create trigger approvals_guard before insert or update on public.approvals
  for each row execute function app.approvals_guard();
create trigger approvals_audit after insert or update on public.approvals
  for each row execute function app.audit_row();

create function app.approvals_emit() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  if tg_op = 'INSERT' then
    perform app.emit_event(new.organization_id, 'approval.requested', 'approval', new.id,
      jsonb_build_object('approval_id', new.id, 'action_type', new.action_type, 'summary', new.summary,
                         'expires_at', new.expires_at, 'payload_hash', new.payload_hash));
  elsif new.status is distinct from old.status and new.status in ('approved', 'rejected', 'expired', 'executed', 'failed') then
    perform app.emit_event(new.organization_id, 'approval.' || new.status, 'approval', new.id,
      jsonb_build_object('approval_id', new.id, 'action_type', new.action_type, 'status', new.status));
  end if;
  return null;
end $$;
create trigger approvals_emit after insert or update on public.approvals
  for each row execute function app.approvals_emit();

-- Human decision. Caller (backend) passes the authenticated human's user id.
create function public.decide_approval(p_id uuid, p_decider uuid, p_decision text, p_note text default null)
returns public.approvals
language plpgsql security definer set search_path = '' as $$
declare a public.approvals;
begin
  if p_decision not in ('approved', 'rejected') then
    raise exception 'invalid decision %', p_decision using errcode = 'invalid_parameter_value';
  end if;
  select * into a from public.approvals where id = p_id for update;
  if not found then raise exception 'approval_not_found' using errcode = 'no_data_found'; end if;

  if not exists (select 1 from public.memberships m
                  where m.organization_id = a.organization_id and m.user_id = p_decider
                    and m.role in ('owner', 'admin')) then
    raise exception 'approver_not_authorised' using errcode = 'insufficient_privilege';
  end if;
  if a.status <> 'pending' then
    raise exception 'approval_not_pending' using errcode = 'invalid_parameter_value';
  end if;
  if a.expires_at <= now() then
    update public.approvals set status = 'expired' where id = p_id returning * into a;
    return a;
  end if;

  update public.approvals
     set status = p_decision, decided_by = p_decider, decided_at = now(), decision_note = p_note
   where id = p_id returning * into a;
  return a;
end $$;

-- Exactly-once claim: only an 'approved', unexpired approval can move to 'executing'.
-- Returns the stored payload; the caller must execute exactly this payload.
create function public.claim_approval_execution(p_id uuid)
returns table (approval_id uuid, organization_id uuid, action_type text, payload jsonb, payload_hash text)
language plpgsql security definer set search_path = '' as $$
declare a public.approvals;
begin
  select * into a from public.approvals where id = p_id for update;
  if not found then raise exception 'approval_not_found' using errcode = 'no_data_found'; end if;
  if a.status <> 'approved' then
    raise exception 'approval_not_executable' using errcode = 'invalid_parameter_value';
  end if;
  if a.expires_at <= now() then
    update public.approvals set status = 'expired' where id = p_id;
    raise exception 'approval_expired' using errcode = 'invalid_parameter_value';
  end if;
  update public.approvals set status = 'executing' where id = p_id;
  return query select a.id, a.organization_id, a.action_type, a.payload, a.payload_hash;
end $$;

create function public.complete_approval_execution(p_id uuid, p_success boolean, p_error text default null) returns void
language sql security definer set search_path = '' as $$
  update public.approvals
     set status = case when p_success then 'executed' else 'failed' end,
         executed_at = now(), execution_error = left(p_error, 1000)
   where id = p_id and status = 'executing';
$$;

---------------------------------------------------------------------------------------------
-- RLS and grants. Outbox/idempotency: no client access at all.
---------------------------------------------------------------------------------------------
alter table public.outbox_events    enable row level security;
alter table public.idempotency_keys enable row level security;
alter table public.approvals        enable row level security;

revoke all on public.outbox_events, public.idempotency_keys, public.approvals from anon, authenticated;
grant all on public.outbox_events, public.idempotency_keys, public.approvals to service_role;
grant select on public.approvals to authenticated;

create policy approvals_select on public.approvals
  for select to authenticated
  using (app.has_role(organization_id, array['owner', 'admin']::public.app_role[]));
-- No client INSERT/UPDATE: requests and decisions go through the backend and the functions above.

-- RPC functions are callable by the backend only.
revoke all on function public.claim_outbox_batch(integer, integer)            from public, anon, authenticated;
revoke all on function public.outbox_mark_delivered(uuid)                     from public, anon, authenticated;
revoke all on function public.outbox_mark_failed(uuid, text, integer)         from public, anon, authenticated;
revoke all on function public.idempotency_claim(text, text, text)             from public, anon, authenticated;
revoke all on function public.idempotency_complete(text, text, jsonb, integer) from public, anon, authenticated;
revoke all on function public.idempotency_release(text, text)                from public, anon, authenticated;
revoke all on function public.decide_approval(uuid, uuid, text, text)         from public, anon, authenticated;
revoke all on function public.claim_approval_execution(uuid)                  from public, anon, authenticated;
revoke all on function public.complete_approval_execution(uuid, boolean, text) from public, anon, authenticated;
grant execute on function public.claim_outbox_batch(integer, integer)            to service_role;
grant execute on function public.outbox_mark_delivered(uuid)                     to service_role;
grant execute on function public.outbox_mark_failed(uuid, text, integer)         to service_role;
grant execute on function public.idempotency_claim(text, text, text)             to service_role;
grant execute on function public.idempotency_complete(text, text, jsonb, integer) to service_role;
grant execute on function public.idempotency_release(text, text)                to service_role;
grant execute on function public.decide_approval(uuid, uuid, text, text)         to service_role;
grant execute on function public.claim_approval_execution(uuid)                  to service_role;
grant execute on function public.complete_approval_execution(uuid, boolean, text) to service_role;
