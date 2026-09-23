-- Aula EI: prevent certificate/exam forgery through direct Data API writes
-- and restore the intended Super Admin-only delete rules for exam content.

-- 1) Certificates are written only by trusted SECURITY DEFINER RPCs
-- (submit_exam / admin_generate_certificate). Clients only need read access.
drop policy if exists certificates_admin_all on public.certificates;
drop policy if exists certificates_insert_policy on public.certificates;
drop policy if exists certificates_update_policy on public.certificates;
drop policy if exists certificates_self_select on public.certificates;

revoke insert, update, delete on table public.certificates from anon, authenticated;
grant select on table public.certificates to authenticated;

drop policy if exists certificates_select_policy on public.certificates;
create policy certificates_select_policy
on public.certificates
for select
to authenticated
using (
  user_id = (select auth.uid())
  or (select public.is_admin())
);

-- 2) Exam attempts are created only by submit_exam().
-- A browser client must not be able to insert an arbitrary passed attempt.
drop policy if exists exam_attempts_insert_policy on public.exam_attempts;
drop policy if exists attempts_admin_select on public.exam_attempts;
drop policy if exists attempts_self_select on public.exam_attempts;
drop policy if exists exam_attempts_select_policy on public.exam_attempts;

revoke insert, update, delete on table public.exam_attempts from anon, authenticated;
grant select on table public.exam_attempts to authenticated;

create policy exam_attempts_select_policy
on public.exam_attempts
for select
to authenticated
using (
  user_id = (select auth.uid())
  or (select public.is_admin())
);

-- 3) Signatures are mutated only through save_certificate_signature()
-- and clear_certificate_signature(), which enforce participant/admin ownership.
drop policy if exists certificate_signatures_insert_policy on public.certificate_signatures;
drop policy if exists certificate_signatures_update_policy on public.certificate_signatures;

revoke insert, update, delete on table public.certificate_signatures from anon, authenticated;
grant select on table public.certificate_signatures to authenticated;

-- 4) The ALL policies below made the separate Super Admin DELETE policies moot,
-- because permissive RLS policies are OR'ed together.
drop policy if exists questions_manage_policy on public.questions;
drop policy if exists question_options_manage_policy on public.question_options;

-- Existing per-operation policies remain:
-- SELECT/INSERT/UPDATE -> Aula EI staff; DELETE -> Super Admin only.

-- 5) Remove a redundant profiles SELECT policy without changing effective access.
drop policy if exists profiles_select_own_or_manager on public.profiles;

drop policy if exists profiles_self_select on public.profiles;
create policy profiles_self_select
on public.profiles
for select
to authenticated
using (
  id = (select auth.uid())
  or (select public.is_admin())
);

-- 6) Cheap RLS init-plan improvements on high-frequency self-service tables.
drop policy if exists progress_self_insert on public.block_progress;
create policy progress_self_insert
on public.block_progress
for insert
to authenticated
with check (user_id = (select auth.uid()));

drop policy if exists progress_self_select on public.block_progress;
create policy progress_self_select
on public.block_progress
for select
to authenticated
using (user_id = (select auth.uid()));

drop policy if exists progress_self_update on public.block_progress;
create policy progress_self_update
on public.block_progress
for update
to authenticated
using (user_id = (select auth.uid()))
with check (user_id = (select auth.uid()));

drop policy if exists enrollments_self_select on public.enrollments;
create policy enrollments_self_select
on public.enrollments
for select
to authenticated
using (user_id = (select auth.uid()));
