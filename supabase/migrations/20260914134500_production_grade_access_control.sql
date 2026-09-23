-- Aula EI production-grade access control and managed-account hardening
-- 2026-09-14

begin;

-- Preserve learning/certificate history when access is revoked.
alter table public.profiles
  add column if not exists is_active boolean not null default true,
  add column if not exists deactivated_at timestamptz,
  add column if not exists deactivated_by uuid;

create index if not exists profiles_active_role_idx
  on public.profiles (is_active, role);

-- Scope the shared Auth trigger to Aula EI managed accounts on INSERT.
-- Existing Aula EI profiles remain untouched. Email changes only update an
-- already-existing Aula profile, which avoids creating Aula profiles for
-- users that belong to other apps sharing this Supabase project.
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
  if tg_op = 'INSERT' then
    if nullif(new.raw_app_meta_data->>'aula_ei_role', '') is null then
      return new;
    end if;

    insert into public.profiles (
      id, email, full_name, role, is_active, created_at, updated_at
    )
    values (
      new.id,
      new.email,
      coalesce(
        nullif(new.raw_user_meta_data->>'full_name', ''),
        split_part(coalesce(new.email, ''), '@', 1),
        'Colaborador EI'
      ),
      public.normalize_aula_ei_role(new.raw_app_meta_data->>'aula_ei_role'),
      true,
      now(),
      now()
    )
    on conflict (id) do update
    set
      email = excluded.email,
      full_name = coalesce(nullif(public.profiles.full_name, ''), excluded.full_name),
      updated_at = now();
  else
    update public.profiles
    set email = new.email,
        updated_at = now()
    where id = new.id;
  end if;

  return new;
end;
$$;

-- First-login password change becomes server-owned metadata that users cannot
-- clear from the browser. Existing managed accounts that still carry the old
-- user_metadata flag are migrated once.
update auth.users
set raw_app_meta_data = coalesce(raw_app_meta_data, '{}'::jsonb)
  || jsonb_build_object('aula_ei_must_change_password', true)
where raw_app_meta_data ? 'aula_ei_role'
  and coalesce((raw_user_meta_data->>'must_change_password')::boolean, false) = true
  and coalesce((raw_app_meta_data->>'aula_ei_must_change_password')::boolean, false) = false;

create or replace function public.is_aula_active(p_user_id uuid default auth.uid())
returns boolean
language sql
stable
security definer
set search_path = public, pg_temp
as $$
  select exists (
    select 1
    from public.profiles p
    where p.id = p_user_id
      and p.is_active = true
  );
$$;

create or replace function public.is_staff()
returns boolean
language sql
stable
security definer
set search_path = public, pg_temp
as $$
  select exists (
    select 1
    from public.profiles p
    where p.id = auth.uid()
      and p.is_active = true
      and public.normalize_aula_ei_role(p.role) in (
        'creador_contenido', 'revisor', 'admin', 'super_admin'
      )
  );
$$;

-- "Admin" now means Admin/Super Admin. Content staff use can_manage_courses().
create or replace function public.is_admin()
returns boolean
language sql
stable
security definer
set search_path = public, pg_temp
as $$
  select exists (
    select 1
    from public.profiles p
    where p.id = auth.uid()
      and p.is_active = true
      and public.normalize_aula_ei_role(p.role) in ('admin', 'super_admin')
  );
$$;

create or replace function public.is_super_admin()
returns boolean
language sql
stable
security definer
set search_path = public, pg_temp
as $$
  select exists (
    select 1
    from public.profiles p
    where p.id = auth.uid()
      and p.is_active = true
      and public.normalize_aula_ei_role(p.role) = 'super_admin'
  );
$$;

create or replace function public.can_manage_courses()
returns boolean
language sql
stable
security definer
set search_path = public, pg_temp
as $$
  select public.is_staff();
$$;

create or replace function public.can_manage_assignments()
returns boolean
language sql
stable
security definer
set search_path = public, pg_temp
as $$
  select public.is_admin();
$$;

create or replace function public.can_manage_users()
returns boolean
language sql
stable
security definer
set search_path = public, pg_temp
as $$
  select public.is_admin();
$$;

create or replace function public.can_delete_critical_content()
returns boolean
language sql
stable
security definer
set search_path = public, pg_temp
as $$
  select public.is_super_admin();
$$;

-- An inactive account never receives an Aula EI profile through this RPC.
create or replace function public.get_my_profile()
returns table(
  id uuid,
  email text,
  full_name text,
  avatar_url text,
  role text,
  created_at timestamptz,
  updated_at timestamptz
)
language sql
stable
security definer
set search_path = public, pg_temp
as $$
  select
    p.id,
    p.email,
    p.full_name,
    p.avatar_url,
    public.normalize_aula_ei_role(p.role) as role,
    p.created_at,
    p.updated_at
  from public.profiles p
  where p.id = auth.uid()
    and p.is_active = true
  limit 1;
$$;

-- Keep profile role and trusted Auth app_metadata synchronized.
create or replace function public.set_user_role(p_user_id uuid, p_role text)
returns void
language plpgsql
security definer
set search_path = public, auth, pg_temp
as $$
declare
  v_actor_role text;
  v_target_role text;
  v_new_role text;
begin
  v_new_role := public.normalize_aula_ei_role(p_role);

  select public.normalize_aula_ei_role(role)
  into v_actor_role
  from public.profiles
  where id = auth.uid()
    and is_active = true;

  if v_actor_role not in ('admin', 'super_admin') then
    raise exception 'Acceso denegado. Solo Admin o Super Admin pueden cambiar roles.';
  end if;

  select public.normalize_aula_ei_role(role)
  into v_target_role
  from public.profiles
  where id = p_user_id;

  if v_target_role is null then
    raise exception 'Usuario no encontrado en profiles.';
  end if;

  if v_actor_role = 'admin' and v_new_role in ('admin', 'super_admin') then
    raise exception 'Un Admin no puede asignar roles Admin ni Super Admin.';
  end if;

  if v_actor_role = 'admin' and v_target_role in ('admin', 'super_admin') then
    raise exception 'Un Admin no puede modificar usuarios Admin ni Super Admin.';
  end if;

  update public.profiles
  set role = v_new_role,
      updated_at = now()
  where id = p_user_id;

  update auth.users
  set raw_app_meta_data = coalesce(raw_app_meta_data, '{}'::jsonb)
    || jsonb_build_object('aula_ei_role', v_new_role)
  where id = p_user_id;
end;
$$;

-- Staff may preview exams while building/reviewing courses. Learners still
-- need enrollment and completion of required content.
create or replace function public.get_exam_questions(p_course_id uuid)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_result jsonb;
begin
  if auth.uid() is null or not public.is_aula_active() then
    raise exception 'Sesión de Aula EI requerida.';
  end if;

  if not (
    public.can_manage_courses()
    or public.is_enrolled(p_course_id, auth.uid())
  ) then
    raise exception 'No tienes acceso a este examen.';
  end if;

  if not public.can_manage_courses()
     and not public.can_take_exam(p_course_id, auth.uid()) then
    raise exception 'Completa primero todos los contenidos obligatorios.';
  end if;

  select jsonb_agg(
    jsonb_build_object(
      'id', q.id,
      'prompt', q.prompt,
      'options', coalesce((
        select jsonb_agg(
          jsonb_build_object('id', o.id, 'label', o.label)
          order by o.sort_order
        )
        from public.question_options o
        where o.question_id = q.id
      ), '[]'::jsonb)
    )
    order by q.sort_order
  )
  into v_result
  from public.questions q
  where q.course_id = p_course_id
    and q.active = true;

  if v_result is null or jsonb_array_length(v_result) = 0 then
    raise exception 'El examen no tiene preguntas activas.';
  end if;

  return v_result;
end;
$$;

-- -------------------- RLS: content management --------------------
drop policy if exists courses_admin_insert on public.courses;
drop policy if exists courses_admin_select on public.courses;
drop policy if exists courses_admin_update on public.courses;
create policy courses_staff_insert on public.courses
  for insert to authenticated
  with check ((select public.can_manage_courses()));
create policy courses_access_select on public.courses
  for select to authenticated
  using (
    (select public.can_manage_courses())
    or (
      (select public.is_aula_active())
      and status = 'published'
      and public.is_enrolled(id)
    )
  );
create policy courses_staff_update on public.courses
  for update to authenticated
  using ((select public.can_manage_courses()))
  with check ((select public.can_manage_courses()));

drop policy if exists phases_admin_insert on public.course_phases;
drop policy if exists phases_admin_select on public.course_phases;
drop policy if exists phases_admin_update on public.course_phases;
create policy phases_staff_insert on public.course_phases
  for insert to authenticated
  with check ((select public.can_manage_courses()));
create policy phases_access_select on public.course_phases
  for select to authenticated
  using (
    (select public.can_manage_courses())
    or (
      (select public.is_aula_active())
      and exists (
        select 1 from public.courses c
        where c.id = course_phases.course_id
          and c.status = 'published'
          and public.is_enrolled(c.id)
      )
    )
  );
create policy phases_staff_update on public.course_phases
  for update to authenticated
  using ((select public.can_manage_courses()))
  with check ((select public.can_manage_courses()));

drop policy if exists blocks_admin_insert on public.content_blocks;
drop policy if exists blocks_admin_select on public.content_blocks;
drop policy if exists blocks_admin_update on public.content_blocks;
create policy blocks_staff_insert on public.content_blocks
  for insert to authenticated
  with check ((select public.can_manage_courses()));
create policy blocks_access_select on public.content_blocks
  for select to authenticated
  using (
    (select public.can_manage_courses())
    or (
      (select public.is_aula_active())
      and status = 'published'
      and exists (
        select 1
        from public.course_phases p
        join public.courses c on c.id = p.course_id
        where p.id = content_blocks.phase_id
          and c.status = 'published'
          and public.is_enrolled(c.id)
      )
    )
  );
create policy blocks_staff_update on public.content_blocks
  for update to authenticated
  using ((select public.can_manage_courses()))
  with check ((select public.can_manage_courses()));

-- Exam authoring follows the content-management role. Critical deletes remain
-- Super Admin only through the existing *_super_admin_delete policies.
drop policy if exists questions_admin_insert on public.questions;
drop policy if exists questions_admin_update on public.questions;
drop policy if exists questions_staff_select on public.questions;
create policy questions_staff_insert on public.questions
  for insert to authenticated
  with check ((select public.can_manage_courses()));
create policy questions_staff_update on public.questions
  for update to authenticated
  using ((select public.can_manage_courses()))
  with check ((select public.can_manage_courses()));
create policy questions_staff_select on public.questions
  for select to authenticated
  using ((select public.can_manage_courses()));

drop policy if exists options_admin_insert on public.question_options;
drop policy if exists options_admin_update on public.question_options;
drop policy if exists question_options_staff_select on public.question_options;
create policy options_staff_insert on public.question_options
  for insert to authenticated
  with check ((select public.can_manage_courses()));
create policy options_staff_update on public.question_options
  for update to authenticated
  using ((select public.can_manage_courses()))
  with check ((select public.can_manage_courses()));
create policy question_options_staff_select on public.question_options
  for select to authenticated
  using ((select public.can_manage_courses()));

-- -------------------- RLS: admin-only operations --------------------
drop policy if exists enrollments_admin_insert on public.enrollments;
drop policy if exists enrollments_admin_update on public.enrollments;
drop policy if exists enrollments_admin_delete on public.enrollments;
drop policy if exists enrollments_select_policy on public.enrollments;
create policy enrollments_admin_insert on public.enrollments
  for insert to authenticated
  with check ((select public.can_manage_assignments()));
create policy enrollments_admin_update on public.enrollments
  for update to authenticated
  using ((select public.can_manage_assignments()))
  with check ((select public.can_manage_assignments()));
create policy enrollments_admin_delete on public.enrollments
  for delete to authenticated
  using ((select public.can_manage_assignments()));
create policy enrollments_select_policy on public.enrollments
  for select to authenticated
  using (
    ((user_id = (select auth.uid())) and (select public.is_aula_active()))
    or (select public.can_manage_assignments())
  );

drop policy if exists profiles_self_select on public.profiles;
create policy profiles_self_or_admin_select on public.profiles
  for select to authenticated
  using (
    ((id = (select auth.uid())) and is_active = true)
    or (select public.can_manage_users())
  );

drop policy if exists audit_admin_select on public.audit_logs;
create policy audit_admin_select on public.audit_logs
  for select to authenticated
  using ((select public.is_admin()));

drop policy if exists certificates_select_policy on public.certificates;
create policy certificates_select_policy on public.certificates
  for select to authenticated
  using (
    ((user_id = (select auth.uid())) and (select public.is_aula_active()))
    or (select public.is_admin())
  );

drop policy if exists exam_attempts_select_policy on public.exam_attempts;
create policy exam_attempts_select_policy on public.exam_attempts
  for select to authenticated
  using (
    ((user_id = (select auth.uid())) and (select public.is_aula_active()))
    or (select public.is_admin())
  );

-- -------------------- Progress integrity --------------------
drop policy if exists progress_self_insert on public.block_progress;
drop policy if exists progress_self_update on public.block_progress;
drop policy if exists progress_select_policy on public.block_progress;

create policy progress_self_insert on public.block_progress
  for insert to authenticated
  with check (
    user_id = (select auth.uid())
    and (select public.is_aula_active())
    and exists (
      select 1
      from public.content_blocks b
      join public.course_phases p on p.id = b.phase_id
      join public.courses c on c.id = p.course_id
      join public.enrollments e
        on e.course_id = c.id
       and e.user_id = (select auth.uid())
      where b.id = block_progress.block_id
        and b.status = 'published'
        and c.status = 'published'
        and coalesce(e.status, 'assigned') <> 'cancelled'
    )
  );

create policy progress_self_update on public.block_progress
  for update to authenticated
  using (
    user_id = (select auth.uid())
    and (select public.is_aula_active())
  )
  with check (
    user_id = (select auth.uid())
    and (select public.is_aula_active())
    and exists (
      select 1
      from public.content_blocks b
      join public.course_phases p on p.id = b.phase_id
      join public.courses c on c.id = p.course_id
      join public.enrollments e
        on e.course_id = c.id
       and e.user_id = (select auth.uid())
      where b.id = block_progress.block_id
        and b.status = 'published'
        and c.status = 'published'
        and coalesce(e.status, 'assigned') <> 'cancelled'
    )
  );

create policy progress_select_policy on public.block_progress
  for select to authenticated
  using (
    ((user_id = (select auth.uid())) and (select public.is_aula_active()))
    or (select public.is_admin())
  );

-- Storage: content staff can upload/update/read course assets; only Super Admin
-- can delete them. Learners retain access through their published enrollment.
drop policy if exists course_assets_admin_insert on storage.objects;
drop policy if exists course_assets_admin_update on storage.objects;
drop policy if exists course_assets_authorized_select on storage.objects;
create policy course_assets_staff_insert on storage.objects
  for insert to authenticated
  with check (
    bucket_id = 'course-assets'
    and (select public.can_manage_courses())
  );
create policy course_assets_staff_update on storage.objects
  for update to authenticated
  using (
    bucket_id = 'course-assets'
    and (select public.can_manage_courses())
  )
  with check (
    bucket_id = 'course-assets'
    and (select public.can_manage_courses())
  );
create policy course_assets_authorized_select on storage.objects
  for select to authenticated
  using (
    bucket_id = 'course-assets'
    and (
      (select public.can_manage_courses())
      or (
        (select public.is_aula_active())
        and exists (
          select 1
          from public.enrollments e
          join public.courses c on c.id = e.course_id
          where e.user_id = (select auth.uid())
            and c.status = 'published'
            and coalesce(e.status, 'assigned') <> 'cancelled'
            and e.course_id::text = (storage.foldername(objects.name))[1]
        )
      )
    )
  );

-- Explicitly keep these auth-only RPCs away from anonymous callers.
revoke execute on function public.get_my_profile() from public, anon;
revoke execute on function public.get_my_certificates() from public, anon;
revoke execute on function public.get_exam_questions(uuid) from public, anon;
revoke execute on function public.submit_exam(uuid, jsonb) from public, anon;
revoke execute on function public.set_user_role(uuid, text) from public, anon;
revoke execute on function public.admin_certificate_ranking() from public, anon;
revoke execute on function public.admin_completed_without_certificate() from public, anon;
revoke execute on function public.admin_generate_certificate(uuid, uuid) from public, anon;
revoke execute on function public.save_certificate_signature(text, text, text) from public, anon;
revoke execute on function public.clear_certificate_signature(text, text) from public, anon;
revoke execute on function public.get_certificate_signatures(text) from public, anon;
revoke execute on function public.get_certificate_by_code(text) from public, anon;
revoke execute on function public.can_access_certificate(text) from public, anon;

grant execute on function public.get_my_profile() to authenticated, service_role;
grant execute on function public.get_my_certificates() to authenticated, service_role;
grant execute on function public.get_exam_questions(uuid) to authenticated, service_role;
grant execute on function public.submit_exam(uuid, jsonb) to authenticated, service_role;
grant execute on function public.set_user_role(uuid, text) to authenticated, service_role;
grant execute on function public.admin_certificate_ranking() to authenticated, service_role;
grant execute on function public.admin_completed_without_certificate() to authenticated, service_role;
grant execute on function public.admin_generate_certificate(uuid, uuid) to authenticated, service_role;
grant execute on function public.save_certificate_signature(text, text, text) to authenticated, service_role;
grant execute on function public.clear_certificate_signature(text, text) to authenticated, service_role;
grant execute on function public.get_certificate_signatures(text) to authenticated, service_role;
grant execute on function public.get_certificate_by_code(text) to authenticated, service_role;
grant execute on function public.can_access_certificate(text) to authenticated, service_role;

commit;
