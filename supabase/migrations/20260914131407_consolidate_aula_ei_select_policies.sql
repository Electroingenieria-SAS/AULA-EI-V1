-- Consolidate equivalent SELECT policies to avoid repeated RLS evaluation.

-- block_progress: owner OR Aula EI staff can read.
drop policy if exists progress_admin_select on public.block_progress;
drop policy if exists progress_self_select on public.block_progress;
create policy progress_select_policy
on public.block_progress
for select
to authenticated
using (
  user_id = (select auth.uid())
  or (select public.is_admin())
);

-- enrollments: replace the broad ALL policy with explicit write policies
-- and one combined SELECT policy.
drop policy if exists enrollments_admin_all on public.enrollments;
drop policy if exists enrollments_self_select on public.enrollments;

create policy enrollments_select_policy
on public.enrollments
for select
to authenticated
using (
  user_id = (select auth.uid())
  or (select public.is_admin())
);

create policy enrollments_admin_insert
on public.enrollments
for insert
to authenticated
with check ((select public.is_admin()));

create policy enrollments_admin_update
on public.enrollments
for update
to authenticated
using ((select public.is_admin()))
with check ((select public.is_admin()));

create policy enrollments_admin_delete
on public.enrollments
for delete
to authenticated
using ((select public.is_admin()));
