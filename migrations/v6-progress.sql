-- ============================================================
-- v6: per-task progress percentage (0-100)
--   The existing update-rules trigger does NOT revert "progress",
--   so assignees may report their own advance (status + progress),
--   while everything else stays locked for them.
-- ============================================================

alter table tasks
  add column if not exists progress int not null default 0
  check (progress between 0 and 100);
