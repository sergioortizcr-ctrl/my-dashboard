-- ============================================================
-- v5: activity (system) messages in the task thread
--   Adds a "kind" marker so system entries (created / status changed)
--   render differently from normal comments.
-- ============================================================

alter table task_comments add column if not exists kind text default 'comment';
