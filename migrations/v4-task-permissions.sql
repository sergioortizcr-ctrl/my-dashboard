-- ============================================================
-- v4: per-user task visibility and edit permissions
--   * Admin sees/edits everything.
--   * Regular user sees only tasks they created OR are assigned to.
--   * Creator can fully edit + delete their own tasks.
--   * Assignee (not creator) may ONLY change status (+ comments/attachments).
-- ============================================================

-- ---------- TASKS: row visibility & access ----------
drop policy if exists "team tasks" on tasks;

create policy "tasks_select" on tasks for select to authenticated
  using (is_admin() or user_id = auth.uid() or assignee_id = auth.uid());

create policy "tasks_insert" on tasks for insert to authenticated
  with check (is_admin() or user_id = auth.uid());

create policy "tasks_update" on tasks for update to authenticated
  using  (is_admin() or user_id = auth.uid() or assignee_id = auth.uid())
  with check (is_admin() or user_id = auth.uid() or assignee_id = auth.uid());

create policy "tasks_delete" on tasks for delete to authenticated
  using (is_admin() or user_id = auth.uid());

-- ---------- TASKS: column-level rule for assignees ----------
-- A non-admin, non-creator (i.e. an assignee) may change ONLY the status.
-- Any attempt to change other columns is silently reverted to the old value.
create or replace function enforce_task_update_rules() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if is_admin() or old.user_id = auth.uid() then
    return new;  -- admins and the creator can change anything
  end if;
  -- assignee: keep everything except status (and updated_at) as it was
  new.title       := old.title;
  new.description := old.description;
  new.priority    := old.priority;
  new.due_date    := old.due_date;
  new.assignee_id := old.assignee_id;
  new.department  := old.department;
  new.client      := old.client;
  new.project     := old.project;
  new.tags        := old.tags;
  new.user_id     := old.user_id;
  new.created_at  := old.created_at;
  return new;
end $$;

drop trigger if exists trg_task_update_rules on tasks;
create trigger trg_task_update_rules before update on tasks
  for each row execute function enforce_task_update_rules();

-- ---------- COMMENTS: only on tasks the user can see ----------
drop policy if exists "team comments" on task_comments;
create policy "comments_rw" on task_comments for all to authenticated
  using (exists (
    select 1 from tasks t where t.id = task_id
      and (is_admin() or t.user_id = auth.uid() or t.assignee_id = auth.uid())))
  with check (user_id = auth.uid() and exists (
    select 1 from tasks t where t.id = task_id
      and (is_admin() or t.user_id = auth.uid() or t.assignee_id = auth.uid())));

-- ---------- ATTACHMENTS: only on tasks the user can see ----------
drop policy if exists "team attachments" on task_attachments;
create policy "attachments_rw" on task_attachments for all to authenticated
  using (exists (
    select 1 from tasks t where t.id = task_id
      and (is_admin() or t.user_id = auth.uid() or t.assignee_id = auth.uid())))
  with check (user_id = auth.uid() and exists (
    select 1 from tasks t where t.id = task_id
      and (is_admin() or t.user_id = auth.uid() or t.assignee_id = auth.uid())));
