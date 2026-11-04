\set ON_ERROR_STOP on
\set QUIET on

-- Tiny assertion helpers (pgTAP is not required).
create schema t;

create function t.use(p_uid uuid, p_role text) returns void language plpgsql as $$
begin
  perform set_config('request.jwt.claim.sub', coalesce(p_uid::text, ''), false);
  execute format('set role %I', p_role);
end $$;

create function t.ok(p_cond boolean, p_msg text) returns void language plpgsql as $$
begin
  if p_cond is not true then raise exception 'FAIL: %', p_msg; end if;
  raise notice 'PASS: %', p_msg;
end $$;

create function t.run(p_sql text, p_uid uuid, p_role text) returns void language plpgsql as $$
begin
  perform t.use(p_uid, p_role);
  execute p_sql;
  execute 'reset role';
exception when others then
  execute 'reset role';
  raise;
end $$;

create function t.scalar(p_sql text, p_uid uuid, p_role text) returns text language plpgsql as $$
declare v text;
begin
  perform t.use(p_uid, p_role);
  execute p_sql into v;
  execute 'reset role';
  return v;
exception when others then
  execute 'reset role';
  raise;
end $$;

create function t.fails(p_sql text, p_uid uuid, p_role text, p_msg text) returns void language plpgsql as $$
declare failed boolean := false;
begin
  perform t.use(p_uid, p_role);
  begin execute p_sql; exception when others then failed := true; end;
  execute 'reset role';
  if not failed then raise exception 'FAIL (expected an error): %', p_msg; end if;
  raise notice 'PASS: %', p_msg;
end $$;

-- Fixtures ------------------------------------------------------------------------------
insert into auth.users (id, email) values
  ('00000000-0000-0000-0000-00000000000a', 'owner@x.test'),
  ('00000000-0000-0000-0000-00000000000b', 'member@x.test'),
  ('00000000-0000-0000-0000-00000000000c', 'viewer@x.test'),
  ('00000000-0000-0000-0000-00000000000d', 'outsider@x.test'),
  ('00000000-0000-0000-0000-00000000000e', 'other-org-owner@x.test');

select t.use(null, 'service_role');
select public.bootstrap_organization('Org One', 'org-one', '00000000-0000-0000-0000-00000000000a') as org1 \gset
select public.bootstrap_organization('Org Two', 'org-two', '00000000-0000-0000-0000-00000000000e') as org2 \gset
insert into public.memberships (organization_id, user_id, role) values
  (:'org1', '00000000-0000-0000-0000-00000000000b', 'member'),
  (:'org1', '00000000-0000-0000-0000-00000000000c', 'viewer');
reset role;

\set owner  '00000000-0000-0000-0000-00000000000a'
\set member '00000000-0000-0000-0000-00000000000b'
\set viewer '00000000-0000-0000-0000-00000000000c'
\set outsider '00000000-0000-0000-0000-00000000000d'
\set other  '00000000-0000-0000-0000-00000000000e'

-- 1. Tenant isolation ------------------------------------------------------------------
select t.run(format($q$insert into public.tasks (organization_id, title) values (%L, 'First task')$q$, :'org1'), :'member', 'authenticated');

select t.ok(t.scalar('select count(*) from public.tasks', :'member', 'authenticated')::int = 1, 'member sees their org task');
select t.ok(t.scalar('select count(*) from public.tasks', :'viewer', 'authenticated')::int = 1, 'viewer can read tasks');
select t.ok(t.scalar('select count(*) from public.tasks', :'outsider', 'authenticated')::int = 0, 'user with no membership sees no tasks');
select t.ok(t.scalar('select count(*) from public.tasks', :'other', 'authenticated')::int = 0, 'owner of ANOTHER org sees no tasks');
select t.ok(t.scalar('select count(*) from public.organizations', :'other', 'authenticated')::int = 1, 'other-org owner sees only their own org');
select t.fails('select count(*) from public.tasks', null, 'anon', 'anon role has no access to tasks');

-- 2. Role enforcement ------------------------------------------------------------------
select t.fails(format($q$insert into public.tasks (organization_id, title) values (%L, 'nope')$q$, :'org1'), :'viewer', 'authenticated', 'viewer cannot insert tasks');
select t.fails(format($q$insert into public.tasks (organization_id, title) values (%L, 'cross-tenant')$q$, :'org2'), :'member', 'authenticated', 'member cannot insert into another org');
select t.fails(format($q$insert into public.tasks (organization_id, title) values (%L, 'outsider')$q$, :'org1'), :'outsider', 'authenticated', 'outsider cannot insert tasks');
select t.fails('delete from public.tasks', :'owner', 'authenticated', 'even an owner cannot DELETE tasks via the client (approval-gated)');
select t.ok(t.scalar('select count(*) from public.activity_logs', :'member', 'authenticated')::int = 0, 'member cannot read the audit log');
select t.ok(t.scalar('select count(*) from public.activity_logs', :'owner', 'authenticated')::int > 0, 'owner can read the audit log');
select t.ok(t.scalar($q$with u as (update public.company_settings set base_currency = 'USD' returning 1) select count(*) from u$q$, :'viewer', 'authenticated')::int = 0, 'viewer update of company settings affects 0 rows');
select t.ok(t.scalar($q$with u as (update public.company_settings set base_currency = 'USD' returning 1) select count(*) from u$q$, :'member', 'authenticated')::int = 0, 'member update of company settings affects 0 rows');
select t.ok(t.scalar($q$with u as (update public.company_settings set timezone = 'UTC' returning 1) select count(*) from u$q$, :'owner', 'authenticated')::int = 1, 'owner can update company settings');
select t.ok((select base_currency from public.company_settings where organization_id = :'org1') = 'KES', 'base currency defaults to KES');
select t.ok(t.scalar('select count(*) from public.memberships', :'viewer', 'authenticated')::int = 1, 'viewer sees only their own membership row');
select t.ok(t.scalar('select count(*) from public.memberships', :'owner', 'authenticated')::int = 3, 'owner sees all memberships in their org only');
select t.fails($q$update public.memberships set role = 'owner' where role = 'viewer'$q$, :'viewer', 'authenticated', 'client cannot self-promote');

-- 3. Secrets and backend-only tables -------------------------------------------------
select t.run(format($q$insert into public.integrations (organization_id, provider, name, secret_ref) values (%L, 'n8n', 'main', 'N8N_INBOUND_SIGNING_SECRET')$q$, :'org1'), null, 'service_role');
select t.fails('select secret_ref from public.integrations', :'owner', 'authenticated', 'owner cannot read integrations.secret_ref from the client');
select t.fails('select * from public.integrations', :'owner', 'authenticated', 'select * on integrations is denied (secret_ref column)');
select t.ok(t.scalar('select count(*) from (select id, provider, config from public.integrations) s', :'owner', 'authenticated')::int = 1, 'owner can read non-secret integration columns');
select t.fails('select * from public.outbox_events', :'owner', 'authenticated', 'clients cannot read outbox');
select t.fails('select * from public.idempotency_keys', :'owner', 'authenticated', 'clients cannot read idempotency keys');
select t.fails($q$select public.claim_outbox_batch(5)$q$, :'owner', 'authenticated', 'clients cannot call claim_outbox_batch');
select t.fails($q$select public.bootstrap_organization('x','xx-org','00000000-0000-0000-0000-00000000000a')$q$, :'owner', 'authenticated', 'clients cannot bootstrap orgs');
select t.fails($q$select public.decide_approval(gen_random_uuid(), gen_random_uuid(), 'approved')$q$, :'owner', 'authenticated', 'clients cannot call decide_approval directly');

-- 4. Audit trail + outbox emitted in the same transaction ------------------------------
select t.ok((select count(*) from public.activity_logs where action = 'tasks.insert' and actor_type = 'user'
             and actor_id = :'member') = 1, 'task insert audited with the user as actor');
select t.ok((select count(*) from public.outbox_events where event_type = 'task.created') = 1, 'task.created event queued in outbox');

select t.run($q$update public.tasks set status = 'done'$q$, :'member', 'authenticated');
select t.ok((select completed_at is not null from public.tasks limit 1), 'completed_at set when task is done');
select t.ok((select count(*) from public.outbox_events where event_type = 'task.completed') = 1, 'task.completed event queued');
select t.ok((select count(*) from public.activity_logs where action = 'tasks.update') = 1, 'task update audited');
select t.run($q$update public.tasks set status = 'in_progress'$q$, :'member', 'authenticated');
select t.ok((select completed_at is null from public.tasks limit 1), 'completed_at cleared when task reopened');

-- Agent actor attribution works only in a backend context, never for end users.
select t.use(null, 'service_role');
select set_config('app.actor_type', 'agent', false), set_config('app.actor_id', '00000000-0000-0000-0000-0000000000aa', false);
insert into public.tasks (organization_id, title) values (:'org1', 'created by an agent');
reset role;
select t.ok((select count(*) from public.activity_logs where action = 'tasks.insert' and actor_type = 'agent'
             and actor_id = '00000000-0000-0000-0000-0000000000aa') = 1, 'backend can attribute an audit row to an agent');
select t.use(:'member', 'authenticated');
select set_config('app.actor_type', 'agent', false);
insert into public.tasks (organization_id, title) values (:'org1', 'spoof attempt');
reset role;
select t.ok((select actor_type from public.activity_logs where action = 'tasks.insert'
             order by occurred_at desc, id limit 1) = 'user', 'end user cannot spoof actor_type');
select set_config('app.actor_type', '', false);

-- 5. Append-only audit log -------------------------------------------------------------
select t.fails($q$update public.activity_logs set action = 'tampered'$q$, null, 'service_role', 'service_role cannot UPDATE audit rows');
select t.fails($q$delete from public.activity_logs$q$, null, 'service_role', 'service_role cannot DELETE audit rows');
do $$ begin
  begin update public.activity_logs set action = 'tampered'; raise exception 'FAIL: superuser updated audit log';
  exception when insufficient_privilege then raise notice 'PASS: trigger blocks even the table owner from UPDATE'; end;
  begin truncate public.activity_logs; raise exception 'FAIL: superuser truncated audit log';
  exception when insufficient_privilege then raise notice 'PASS: trigger blocks TRUNCATE'; end;
end $$;

-- 6. Approvals ------------------------------------------------------------------------
select t.use(null, 'service_role');
insert into public.approvals (organization_id, action_type, summary, payload, requested_by_type, requested_by_id)
values (:'org1', 'financial_transaction', 'Pay hosting invoice', '{"amount_minor": 250000, "currency": "KES", "to": "vendor-1"}',
        'agent', '00000000-0000-0000-0000-0000000000aa') returning id as ap1 \gset
reset role;

select t.ok((select payload_hash = encode(sha256(convert_to(payload::text, 'utf8')), 'hex') from public.approvals where id = :'ap1'),
            'payload hash is SHA-256 of the stored payload');
select t.ok((select status from public.approvals where id = :'ap1') = 'pending', 'new approval starts pending');
select t.ok((select count(*) from public.outbox_events where event_type = 'approval.requested') = 1, 'approval.requested queued');
select t.fails(format($q$update public.approvals set payload = '{"amount_minor": 1}' where id = %L$q$, :'ap1'), null, 'service_role', 'approval payload is immutable');
select t.fails(format($q$update public.approvals set status = 'approved' where id = %L$q$, :'ap1'), null, 'service_role', 'cannot approve without a human decider (constraint)');
select t.fails(format($q$update public.approvals set status = 'executing' where id = %L$q$, :'ap1'), null, 'service_role', 'cannot skip pending -> executing');
select t.fails(format($q$select * from public.claim_approval_execution(%L)$q$, :'ap1'), null, 'service_role', 'cannot execute a pending approval');
select t.fails(format($q$select public.decide_approval(%L, %L, 'approved')$q$, :'ap1', :'member'), null, 'service_role', 'plain member cannot approve');
select t.fails(format($q$select public.decide_approval(%L, %L, 'approved')$q$, :'ap1', :'outsider'), null, 'service_role', 'outsider cannot approve');
select t.fails(format($q$select public.decide_approval(%L, %L, 'approved')$q$, :'ap1', :'other'), null, 'service_role', 'owner of another org cannot approve');
select t.fails(format($q$select public.decide_approval(%L, '00000000-0000-0000-0000-0000000000aa', 'approved')$q$, :'ap1'), null, 'service_role', 'an agent id cannot approve');
select t.ok(t.scalar(format($q$select (public.decide_approval(%L, %L, 'approved', 'ok')).status$q$, :'ap1', :'owner'), null, 'service_role') = 'approved', 'owner can approve');
select t.fails(format($q$select public.decide_approval(%L, %L, 'rejected')$q$, :'ap1', :'owner'), null, 'service_role', 'cannot decide twice');
select t.ok(t.scalar(format($q$select payload->>'currency' from public.claim_approval_execution(%L)$q$, :'ap1'), null, 'service_role') = 'KES', 'approved action can be claimed with its original payload');
select t.fails(format($q$select * from public.claim_approval_execution(%L)$q$, :'ap1'), null, 'service_role', 'approval can be claimed only once');
select t.run(format($q$select public.complete_approval_execution(%L, true)$q$, :'ap1'), null, 'service_role');
select t.ok((select status from public.approvals where id = :'ap1') = 'executed', 'approval marked executed');

-- expiry
select t.use(null, 'service_role');
insert into public.approvals (organization_id, action_type, summary, payload, requested_by_type, expires_at)
values (:'org1', 'production_deployment', 'Deploy v1', '{"sha": "abc"}', 'system', now() - interval '1 minute') returning id as ap2 \gset
reset role;
select t.ok(t.scalar(format($q$select (public.decide_approval(%L, %L, 'approved')).status$q$, :'ap2', :'owner'), null, 'service_role') = 'expired', 'late decision on an expired approval yields expired, not approved');

select t.ok(t.scalar('select count(*) from public.approvals', :'member', 'authenticated')::int = 0, 'plain member cannot read approvals');
select t.ok(t.scalar('select count(*) from public.approvals', :'owner', 'authenticated')::int = 2, 'owner can read approvals');
select t.fails($q$update public.approvals set decision_note = 'x'$q$, :'owner', 'authenticated', 'owner cannot write approvals through the client');

-- 7. Outbox claim / retry / dead-letter ----------------------------------------------------
select count(*) as pending_before from public.outbox_events where status = 'pending' \gset
select t.ok(:pending_before > 0, 'outbox has pending events');
select t.use(null, 'service_role');
create temp table claimed1 as select * from public.claim_outbox_batch(100, 60);
create temp table claimed2 as select * from public.claim_outbox_batch(100, 60);
reset role;
select t.ok((select count(*) from claimed1) = :pending_before, 'first claim takes all pending events');
select t.ok((select count(*) from claimed2) = 0, 'leased events are not handed out twice');
select t.ok((select min(attempts) from claimed1) = 1, 'attempt counter incremented on claim');

select id as ev from claimed1 limit 1 \gset
select t.run(format($q$select public.outbox_mark_delivered(%L)$q$, :'ev'), null, 'service_role');
select t.ok((select status from public.outbox_events where id = :'ev') = 'delivered', 'delivered event marked delivered');

select id as ev2 from claimed1 where id <> :'ev' limit 1 \gset
select t.run(format($q$select public.outbox_mark_failed(%L, 'boom', 3)$q$, :'ev2'), null, 'service_role');
select t.ok((select status = 'pending' and next_attempt_at > now() and last_error = 'boom' from public.outbox_events where id = :'ev2'), 'failed event retried later with backoff');
update public.outbox_events set attempts = 3 where id = :'ev2';
select t.run(format($q$select public.outbox_mark_failed(%L, 'boom again', 3)$q$, :'ev2'), null, 'service_role');
select t.ok((select status from public.outbox_events where id = :'ev2') = 'dead', 'event dead-lettered after max attempts');

-- expired lease is reclaimed
select id as ev3 from claimed1 where id not in (:'ev', :'ev2') limit 1 \gset
update public.outbox_events set locked_until = now() - interval '1 second' where id = :'ev3';
select t.ok(t.scalar($q$select count(*) from public.claim_outbox_batch(100, 60)$q$, null, 'service_role')::int >= 1, 'event with an expired lease is reclaimed');

-- 8. Idempotency ----------------------------------------------------------------------------
select t.ok(t.scalar($q$select outcome from public.idempotency_claim('n8n:inbound', 'k1', 'hashA')$q$, null, 'service_role') = 'new', 'first delivery is new');
select t.ok(t.scalar($q$select outcome from public.idempotency_claim('n8n:inbound', 'k1', 'hashA')$q$, null, 'service_role') = 'in_progress', 'concurrent duplicate reports in_progress');
select t.ok(t.scalar($q$select outcome from public.idempotency_claim('n8n:inbound', 'k1', 'hashB')$q$, null, 'service_role') = 'conflict', 'same key, different body is a conflict');
select t.run($q$select public.idempotency_complete('n8n:inbound', 'k1', '{"ok":true}', 200)$q$, null, 'service_role');
select t.ok(t.scalar($q$select outcome || ':' || (response->>'ok') from public.idempotency_claim('n8n:inbound', 'k1', 'hashA')$q$, null, 'service_role') = 'replay:true', 'completed key replays the stored response');
update public.idempotency_keys set status = 'in_progress', created_at = now() - interval '10 minutes' where key = 'k1';
select t.ok(t.scalar($q$select outcome from public.idempotency_claim('n8n:inbound', 'k1', 'hashA')$q$, null, 'service_role') = 'new', 'stale in_progress key can be retried');

select t.ok(t.scalar($q$select outcome from public.idempotency_claim('n8n:inbound', 'k2', 'h')$q$, null, 'service_role') = 'new', 'k2 first claim is new');
select t.run($q$select public.idempotency_release('n8n:inbound', 'k2')$q$, null, 'service_role');
select t.ok(t.scalar($q$select outcome from public.idempotency_claim('n8n:inbound', 'k2', 'h')$q$, null, 'service_role') = 'new', 'released key can be retried immediately');
select t.run($q$select public.idempotency_complete('n8n:inbound', 'k2', '{}', 200)$q$, null, 'service_role');
select t.run($q$select public.idempotency_release('n8n:inbound', 'k2')$q$, null, 'service_role');
select t.ok(t.scalar($q$select outcome from public.idempotency_claim('n8n:inbound', 'k2', 'h')$q$, null, 'service_role') = 'replay', 'release never deletes a completed key');
select t.fails($q$select public.idempotency_release('a','b')$q$, :'owner', 'authenticated', 'clients cannot call idempotency_release');

\echo ALL DATABASE TESTS PASSED
