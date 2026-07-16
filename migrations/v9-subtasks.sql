-- ============================================================
-- v9: checklist (subtasks) inside tasks — complementary data,
--   independent from the progress %.
--   Add + check/uncheck: any stakeholder (creator or any responsible).
--   Delete: admin or the task creator only.
-- ============================================================

create table if not exists subtasks (
  id uuid default gen_random_uuid() primary key,
  task_id uuid references tasks(id) on delete cascade not null,
  user_id uuid references auth.users(id) not null,
  title text not null,
  done boolean default false,
  created_at timestamptz default now()
);
create index if not exists subtasks_task_idx on subtasks(task_id);
alter table subtasks enable row level security;

create policy "subtasks_select" on subtasks for select to authenticated
  using (exists (select 1 from tasks t where t.id = task_id and (
    is_admin() or t.user_id = auth.uid()
    or t.assignee_id = auth.uid() or t.assignee2_id = auth.uid() or t.assignee3_id = auth.uid())));

create policy "subtasks_insert" on subtasks for insert to authenticated
  with check (user_id = auth.uid() and exists (select 1 from tasks t where t.id = task_id and (
    is_admin() or t.user_id = auth.uid()
    or t.assignee_id = auth.uid() or t.assignee2_id = auth.uid() or t.assignee3_id = auth.uid())));

create policy "subtasks_update" on subtasks for update to authenticated
  using (exists (select 1 from tasks t where t.id = task_id and (
    is_admin() or t.user_id = auth.uid()
    or t.assignee_id = auth.uid() or t.assignee2_id = auth.uid() or t.assignee3_id = auth.uid())))
  with check (exists (select 1 from tasks t where t.id = task_id and (
    is_admin() or t.user_id = auth.uid()
    or t.assignee_id = auth.uid() or t.assignee2_id = auth.uid() or t.assignee3_id = auth.uid())));

create policy "subtasks_delete" on subtasks for delete to authenticated
  using (exists (select 1 from tasks t where t.id = task_id and (
    is_admin() or t.user_id = auth.uid())));
