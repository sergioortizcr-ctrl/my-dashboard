-- ============================================================
-- v8 fix: let every task stakeholder read & write comments and
--   attachments — admin, creator, OR any of the 3 responsibles.
--   (v7 added responsibles 2 & 3 to task visibility but not to
--    the comment/attachment policies — this aligns them.)
-- ============================================================

-- ---------- COMMENTS ----------
drop policy if exists "own comments"  on task_comments;
drop policy if exists "team comments" on task_comments;
drop policy if exists "comments_rw"   on task_comments;

create policy "comments_rw" on task_comments for all to authenticated
  using (exists (
    select 1 from tasks t where t.id = task_id and (
      is_admin() or t.user_id = auth.uid()
      or t.assignee_id = auth.uid() or t.assignee2_id = auth.uid() or t.assignee3_id = auth.uid())))
  with check (user_id = auth.uid() and exists (
    select 1 from tasks t where t.id = task_id and (
      is_admin() or t.user_id = auth.uid()
      or t.assignee_id = auth.uid() or t.assignee2_id = auth.uid() or t.assignee3_id = auth.uid())));

-- ---------- ATTACHMENTS ----------
drop policy if exists "own attachments"  on task_attachments;
drop policy if exists "team attachments" on task_attachments;
drop policy if exists "attachments_rw"   on task_attachments;

create policy "attachments_rw" on task_attachments for all to authenticated
  using (exists (
    select 1 from tasks t where t.id = task_id and (
      is_admin() or t.user_id = auth.uid()
      or t.assignee_id = auth.uid() or t.assignee2_id = auth.uid() or t.assignee3_id = auth.uid())))
  with check (user_id = auth.uid() and exists (
    select 1 from tasks t where t.id = task_id and (
      is_admin() or t.user_id = auth.uid()
      or t.assignee_id = auth.uid() or t.assignee2_id = auth.uid() or t.assignee3_id = auth.uid())));
