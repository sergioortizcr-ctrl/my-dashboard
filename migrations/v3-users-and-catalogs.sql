-- ============================================================
-- v3: users, roles, catalogs, assignee, attachments
-- ============================================================

create extension if not exists pgcrypto;

-- ---------- PROFILES ----------
create table if not exists profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  username text unique not null,
  full_name text,
  role text default 'user' check (role in ('admin','user')),
  must_change_password boolean default false,
  created_at timestamptz default now()
);
alter table profiles enable row level security;

create policy "profiles readable by team" on profiles
  for select to authenticated using (true);
create policy "own profile update" on profiles
  for update to authenticated using (auth.uid() = id) with check (auth.uid() = id);

-- auto-create profile when a user signs up (metadata comes from the app)
create or replace function handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into profiles (id, username, full_name, role, must_change_password)
  values (
    new.id,
    coalesce(new.raw_user_meta_data->>'username', split_part(new.email,'@',1)),
    coalesce(new.raw_user_meta_data->>'full_name', ''),
    coalesce(new.raw_user_meta_data->>'role', 'user'),
    coalesce((new.raw_user_meta_data->>'must_change_password')::boolean, false)
  )
  on conflict (id) do nothing;
  return new;
end $$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function handle_new_user();

-- helper: is the current user an admin?
create or replace function is_admin() returns boolean
language sql security definer stable set search_path = public as
$$ select exists(select 1 from profiles where id = auth.uid() and role = 'admin') $$;

-- login with username: resolve to email (anon needs this at the login screen)
create or replace function email_for_username(u text) returns text
language sql security definer stable set search_path = public as
$$ select au.email from auth.users au join profiles p on p.id = au.id where p.username = lower(u) $$;
grant execute on function email_for_username(text) to anon, authenticated;

-- admin resets another user's password; forces them to change it on next login
create or replace function admin_reset_password(target uuid, new_password text) returns void
language plpgsql security definer set search_path = public, extensions as $$
begin
  if not is_admin() then raise exception 'Only admins can reset passwords'; end if;
  if length(new_password) < 6 then raise exception 'Password must be at least 6 characters'; end if;
  update auth.users set encrypted_password = crypt(new_password, gen_salt('bf')) where id = target;
  update profiles set must_change_password = true where id = target;
end $$;

-- user clears their own flag after changing password
create or replace function clear_password_flag() returns void
language sql security definer set search_path = public as
$$ update profiles set must_change_password = false where id = auth.uid() $$;

-- ---------- CATALOGS ----------
create table if not exists departments (
  id uuid default gen_random_uuid() primary key,
  name text unique not null
);
create table if not exists clients (
  id uuid default gen_random_uuid() primary key,
  name text unique not null
);
create table if not exists projects (
  id uuid default gen_random_uuid() primary key,
  name text unique not null
);

alter table departments enable row level security;
alter table clients enable row level security;
alter table projects enable row level security;

-- everyone reads; users may ADD departments/clients; only admin edits/deletes
create policy "read departments" on departments for select to authenticated using (true);
create policy "add departments" on departments for insert to authenticated with check (true);
create policy "admin update departments" on departments for update to authenticated using (is_admin());
create policy "admin delete departments" on departments for delete to authenticated using (is_admin());

create policy "read clients" on clients for select to authenticated using (true);
create policy "add clients" on clients for insert to authenticated with check (true);
create policy "admin update clients" on clients for update to authenticated using (is_admin());
create policy "admin delete clients" on clients for delete to authenticated using (is_admin());

-- projects: ONLY admin creates
create policy "read projects" on projects for select to authenticated using (true);
create policy "admin insert projects" on projects for insert to authenticated with check (is_admin());
create policy "admin update projects" on projects for update to authenticated using (is_admin());
create policy "admin delete projects" on projects for delete to authenticated using (is_admin());

-- ---------- TASKS: team visibility + responsible ----------
alter table tasks add column if not exists assignee_id uuid references profiles(id);

drop policy if exists "own tasks" on tasks;
create policy "team tasks" on tasks
  for all to authenticated using (true) with check (true);

drop policy if exists "own comments" on task_comments;
create policy "team comments" on task_comments
  for all to authenticated using (true) with check (true);

-- ---------- ATTACHMENTS ----------
create table if not exists task_attachments (
  id uuid default gen_random_uuid() primary key,
  task_id uuid references tasks(id) on delete cascade not null,
  user_id uuid references auth.users(id) not null,
  file_path text not null,
  file_name text not null,
  content_type text,
  created_at timestamptz default now()
);
alter table task_attachments enable row level security;
create policy "team attachments" on task_attachments
  for all to authenticated using (true) with check (true);

insert into storage.buckets (id, name, public)
values ('attachments', 'attachments', true)
on conflict (id) do nothing;

create policy "team can upload files" on storage.objects
  for insert to authenticated with check (bucket_id = 'attachments');
create policy "team can read files" on storage.objects
  for select to authenticated using (bucket_id = 'attachments');
create policy "team can delete files" on storage.objects
  for delete to authenticated using (bucket_id = 'attachments');

-- ---------- BOOTSTRAP: Sergio is admin ----------
insert into profiles (id, username, full_name, role)
select id, 'sortiz', 'Sergio Ortiz Rojas', 'admin'
from auth.users where email = 'sergio.ortizcr@gmail.com'
on conflict (id) do update set role = 'admin', username = 'sortiz', full_name = 'Sergio Ortiz Rojas';
