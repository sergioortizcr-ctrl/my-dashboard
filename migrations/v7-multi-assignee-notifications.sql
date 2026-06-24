-- ============================================================
-- v7: up to 3 responsibles per task + in-app notifications
-- ============================================================

-- ---------- extra responsibles ----------
alter table tasks add column if not exists assignee2_id uuid references profiles(id);
alter table tasks add column if not exists assignee3_id uuid references profiles(id);

-- visibility + update access now include the extra responsibles
drop policy if exists "tasks_select" on tasks;
create policy "tasks_select" on tasks for select to authenticated
  using (is_admin() or user_id = auth.uid()
      or assignee_id = auth.uid() or assignee2_id = auth.uid() or assignee3_id = auth.uid());

drop policy if exists "tasks_update" on tasks;
create policy "tasks_update" on tasks for update to authenticated
  using  (is_admin() or user_id = auth.uid()
       or assignee_id = auth.uid() or assignee2_id = auth.uid() or assignee3_id = auth.uid())
  with check (is_admin() or user_id = auth.uid()
       or assignee_id = auth.uid() or assignee2_id = auth.uid() or assignee3_id = auth.uid());

-- non-creators (any responsible) stay limited to status + progress
create or replace function enforce_task_update_rules() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if is_admin() or old.user_id = auth.uid() then
    return new;
  end if;
  new.title := old.title; new.description := old.description;
  new.priority := old.priority; new.due_date := old.due_date;
  new.assignee_id := old.assignee_id; new.assignee2_id := old.assignee2_id; new.assignee3_id := old.assignee3_id;
  new.department := old.department; new.client := old.client; new.project := old.project;
  new.tags := old.tags; new.user_id := old.user_id; new.created_at := old.created_at;
  return new;
end $$;

-- ---------- notifications ----------
create table if not exists notifications (
  id uuid default gen_random_uuid() primary key,
  user_id uuid references auth.users(id) on delete cascade not null,  -- recipient
  task_id uuid references tasks(id) on delete cascade,
  message text not null,
  read boolean default false,
  created_at timestamptz default now()
);
create index if not exists notifications_user_idx on notifications(user_id, created_at desc);
alter table notifications enable row level security;

-- recipients manage their own; any signed-in user may create one (to notify a responsible)
create policy "notif_select_own" on notifications for select to authenticated using (user_id = auth.uid());
create policy "notif_update_own" on notifications for update to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());
create policy "notif_delete_own" on notifications for delete to authenticated using (user_id = auth.uid());
create policy "notif_insert"     on notifications for insert to authenticated with check (auth.uid() is not null);

-- live updates
alter publication supabase_realtime add table notifications;
