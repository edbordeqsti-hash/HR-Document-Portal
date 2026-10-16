[index.html](https://github.com/user-attachments/files/33530634/index.html)

-- =====================================================================
-- HR Document Portal (DTR + Payslips) — Supabase schema
-- Run once in: Supabase Dashboard → SQL Editor → New query → Run
-- =====================================================================

-- ---------- Tables ----------------------------------------------------
create table public.profiles (
  id                   uuid primary key references auth.users(id) on delete cascade,
  employee_no          text not null unique,
  full_name            text not null,
  email                text not null unique,
  department           text,
  position             text,
  role                 text not null default 'employee' check (role in ('admin','employee')),
  active               boolean not null default true,
  must_change_password boolean not null default true,
  last_login_at        timestamptz,
  created_at           timestamptz not null default now()
);

create table public.documents (
  id               uuid primary key default gen_random_uuid(),
  employee_id      uuid not null references public.profiles(id) on delete restrict,
  doc_type         text not null check (doc_type in ('dtr','payslip')),
  period_year      smallint not null check (period_year between 2000 and 2100),
  period_month     smallint not null check (period_month between 1 and 12),
  -- 0 = whole month, 1 = 1st half (1–15), 2 = 2nd half (16–end)
  period_half      smallint not null default 0 check (period_half in (0,1,2)),
  file_path        text not null unique,
  file_name        text not null,
  mime_type        text not null,
  file_size        bigint not null,
  file_hash        text not null,           -- SHA-256, used for duplicate detection
  status           text not null default 'active' check (status in ('active','replaced')),
  notes            text,
  uploaded_by      uuid references public.profiles(id),
  uploaded_at      timestamptz not null default now(),
  replaced_at      timestamptz,
  replaced_by      uuid references public.profiles(id),
  replace_reason   text,
  view_count       int not null default 0,   -- employee's own views
  download_count   int not null default 0,   -- employee's own downloads
  first_viewed_at  timestamptz,
  last_accessed_at timestamptz
);

-- Only one ACTIVE document per employee / type / period. Replaced ones are kept for audit.
create unique index documents_one_active_per_slot
  on public.documents (employee_id, doc_type, period_year, period_month, period_half)
  where status = 'active';
create index documents_hash_idx     on public.documents (file_hash);
create index documents_employee_idx on public.documents (employee_id, period_year desc, period_month desc);
create index documents_uploaded_idx on public.documents (uploaded_at desc);

create table public.activity_logs (
  id          bigint generated always as identity primary key,
  created_at  timestamptz not null default now(),
  user_id     uuid references public.profiles(id) on delete set null,  -- who did it
  action      text not null check (action in (
                'login','upload','replace','view','download','password_change',
                'employee_create','employee_update','employee_deactivate',
                'employee_activate','password_reset')),
  document_id uuid references public.documents(id) on delete set null,
  employee_id uuid references public.profiles(id) on delete set null,  -- whose record
  details     jsonb not null default '{}'
);
create index activity_logs_created_idx  on public.activity_logs (created_at desc);
create index activity_logs_employee_idx on public.activity_logs (employee_id, created_at desc);

-- ---------- Helper ----------------------------------------------------
create or replace function public.is_admin()
returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.profiles
                 where id = auth.uid() and role = 'admin' and active);
$$;

-- ---------- Row Level Security ---------------------------------------
alter table public.profiles      enable row level security;
alter table public.documents     enable row level security;
alter table public.activity_logs enable row level security;

-- profiles: employees see only themselves; admins see and edit everyone.
-- (Creating accounts / roles happens server-side with the service-role key.)
create policy profiles_select on public.profiles
  for select to authenticated using (id = auth.uid() or public.is_admin());
create policy profiles_admin_update on public.profiles
  for update to authenticated using (public.is_admin()) with check (public.is_admin());

-- documents: employees see only their own ACTIVE documents; admins see all.
-- Writes go through register_document() below. No delete policy: records are retained.
create policy documents_select_own on public.documents
  for select to authenticated
  using (
    employee_id = auth.uid() and status = 'active'
    and exists (select 1 from public.profiles p where p.id = auth.uid() and p.active)
  );
create policy documents_select_admin on public.documents
  for select to authenticated using (public.is_admin());

-- activity_logs: admins read; nobody writes directly (see log_event()).
create policy logs_select_admin on public.activity_logs
  for select to authenticated using (public.is_admin());

-- ---------- Functions used by the app --------------------------------

-- Atomically store a document record; archives the previous one if replacing.
create or replace function public.register_document(
  p_employee_id uuid, p_doc_type text, p_year int, p_month int, p_half int,
  p_path text, p_name text, p_mime text, p_size bigint, p_hash text,
  p_notes text, p_replace boolean, p_reason text
) returns uuid
language plpgsql security definer set search_path = public as $$
declare
  old_id uuid; new_id uuid;
begin
  if not public.is_admin() then raise exception 'Admins only'; end if;
  if not exists (select 1 from profiles where id = p_employee_id and role = 'employee' and active) then
    raise exception 'Employee not found or inactive';
  end if;
  if p_hash !~ '^[0-9a-f]{64}$' then raise exception 'Invalid file hash'; end if;
  if split_part(p_path, '/', 1) <> p_employee_id::text then raise exception 'Invalid file path'; end if;

  select id into old_id from documents
   where employee_id = p_employee_id and doc_type = p_doc_type
     and period_year = p_year and period_month = p_month and period_half = p_half
     and status = 'active'
   for update;

  if old_id is not null and not coalesce(p_replace, false) then
    raise exception 'ALREADY_EXISTS';
  end if;

  if old_id is not null then
    update documents
       set status = 'replaced', replaced_at = now(), replaced_by = auth.uid(),
           replace_reason = nullif(p_reason, '')
     where id = old_id;
  end if;

  insert into documents (employee_id, doc_type, period_year, period_month, period_half,
                         file_path, file_name, mime_type, file_size, file_hash, notes, uploaded_by)
  values (p_employee_id, p_doc_type, p_year, p_month, p_half,
          p_path, p_name, p_mime, p_size, p_hash, nullif(p_notes, ''), auth.uid())
  returning id into new_id;

  insert into activity_logs (user_id, action, document_id, employee_id, details)
  values (auth.uid(), case when old_id is null then 'upload' else 'replace' end,
          new_id, p_employee_id,
          jsonb_build_object('doc_type', p_doc_type, 'period_year', p_year,
                             'period_month', p_month, 'period_half', p_half,
                             'file_name', p_name, 'replaced_document', old_id,
                             'reason', nullif(p_reason, '')));
  return new_id;
end $$;

-- Access / audit logging. Also keeps per-document view and download counters.
create or replace function public.log_event(
  p_action text, p_document_id uuid default null, p_employee_id uuid default null
) returns void
language plpgsql security definer set search_path = public as $$
declare
  uid uuid := auth.uid();
  me  profiles%rowtype;
  doc documents%rowtype;
  det jsonb;
begin
  if uid is null then raise exception 'Not authenticated'; end if;
  select * into me from profiles where id = uid and active;
  if not found then raise exception 'Account inactive'; end if;

  if p_action in ('view','download') then
    select * into doc from documents where id = p_document_id;
    if not found then raise exception 'Document not found'; end if;
    if me.role <> 'admin' and (doc.employee_id <> uid or doc.status <> 'active') then
      raise exception 'Not allowed';
    end if;
    det := jsonb_build_object('doc_type', doc.doc_type, 'period_year', doc.period_year,
                              'period_month', doc.period_month, 'period_half', doc.period_half,
                              'file_name', doc.file_name);
    if doc.employee_id = uid then   -- only the employee's own access counts as "access"
      update documents
         set view_count     = view_count     + case when p_action = 'view' then 1 else 0 end,
             download_count = download_count + case when p_action = 'download' then 1 else 0 end,
             first_viewed_at  = coalesce(first_viewed_at, now()),
             last_accessed_at = now()
       where id = doc.id;
    end if;
    insert into activity_logs (user_id, action, document_id, employee_id, details)
    values (uid, p_action, doc.id, doc.employee_id, det);

  elsif p_action = 'login' then
    update profiles set last_login_at = now() where id = uid;
    insert into activity_logs (user_id, action, employee_id) values (uid, 'login', uid);

  elsif p_action = 'employee_update' and me.role = 'admin' then
    insert into activity_logs (user_id, action, employee_id) values (uid, 'employee_update', p_employee_id);

  else
    raise exception 'Invalid action';
  end if;
end $$;

-- Called after the user sets their own password.
create or replace function public.complete_password_change()
returns void language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then raise exception 'Not authenticated'; end if;
  update profiles set must_change_password = false where id = auth.uid();
  insert into activity_logs (user_id, action, employee_id)
  values (auth.uid(), 'password_change', auth.uid());
end $$;

revoke all on function public.is_admin()                 from public, anon;
revoke all on function public.register_document(uuid,text,int,int,int,text,text,text,bigint,text,text,boolean,text) from public, anon;
revoke all on function public.log_event(text,uuid,uuid)  from public, anon;
revoke all on function public.complete_password_change() from public, anon;
grant execute on function public.is_admin()                 to authenticated;
grant execute on function public.register_document(uuid,text,int,int,int,text,text,text,bigint,text,text,boolean,text) to authenticated;
grant execute on function public.log_event(text,uuid,uuid)  to authenticated;
grant execute on function public.complete_password_change() to authenticated;

-- ---------- Private file storage -------------------------------------
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('hr-documents', 'hr-documents', false, 10485760,
        array['application/pdf','image/jpeg','image/png','image/webp'])
on conflict (id) do nothing;

-- Files live at  <employee_uuid>/<type>/<file>. Employees can read only their own folder.
create policy hr_docs_admin_all on storage.objects
  for all to authenticated
  using (bucket_id = 'hr-documents' and public.is_admin())
  with check (bucket_id = 'hr-documents' and public.is_admin());

create policy hr_docs_employee_read on storage.objects
  for select to authenticated
  using (
    bucket_id = 'hr-documents'
    and (storage.foldername(name))[1] = auth.uid()::text
    and exists (select 1 from public.profiles p where p.id = auth.uid() and p.active)
  );
