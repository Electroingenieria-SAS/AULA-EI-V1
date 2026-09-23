-- Aula EI final membership, role and progress integrity hardening.
-- Preserve all existing learning data; only tighten authorization and write paths.

update auth.users u
set raw_app_meta_data = coalesce(u.raw_app_meta_data, '{}'::jsonb)
  || jsonb_build_object(
    'aula_ei_role', public.normalize_aula_ei_role(p.role),
    'aula_ei_active', p.is_active
  )
from public.profiles p
where p.id = u.id
  and (
    not (coalesce(u.raw_app_meta_data, '{}'::jsonb) ? 'aula_ei_role')
    or not (coalesce(u.raw_app_meta_data, '{}'::jsonb) ? 'aula_ei_active')
  );

create or replace function public.is_aula_active(p_user_id uuid default auth.uid())
returns boolean
language sql
stable
security definer
set search_path = public, auth, pg_temp
as $$
  select exists (
    select 1
    from public.profiles p
    join auth.users u on u.id = p.id
    where p.id = p_user_id
      and p.is_active = true
      and coalesce(u.raw_app_meta_data->>'aula_ei_active', 'false') = 'true'
      and u.raw_app_meta_data ? 'aula_ei_role'
      and public.normalize_aula_ei_role(u.raw_app_meta_data->>'aula_ei_role') = public.normalize_aula_ei_role(p.role)
  );
$$;

create or replace function public.is_staff()
returns boolean
language sql
stable
security definer
set search_path = public, pg_temp
as $$
  select public.is_aula_active()
    and exists (
      select 1 from public.profiles p
      where p.id = auth.uid()
        and public.normalize_aula_ei_role(p.role) in ('creador_contenido','revisor','admin','super_admin')
    );
$$;

create or replace function public.is_admin()
returns boolean
language sql
stable
security definer
set search_path = public, pg_temp
as $$
  select public.is_aula_active()
    and exists (
      select 1 from public.profiles p
      where p.id = auth.uid()
        and public.normalize_aula_ei_role(p.role) in ('admin','super_admin')
    );
$$;

create or replace function public.is_super_admin()
returns boolean
language sql
stable
security definer
set search_path = public, pg_temp
as $$
  select public.is_aula_active()
    and exists (
      select 1 from public.profiles p
      where p.id = auth.uid()
        and public.normalize_aula_ei_role(p.role) = 'super_admin'
    );
$$;

create or replace function public.is_enrolled(p_course_id uuid, p_user_id uuid default auth.uid())
returns boolean
language sql
stable
security definer
set search_path = public, pg_temp
as $$
  select p_user_id is not null
    and public.is_aula_active(p_user_id)
    and (p_user_id = auth.uid() or public.is_admin())
    and exists (
      select 1 from public.enrollments e
      where e.course_id = p_course_id
        and e.user_id = p_user_id
        and coalesce(e.status,'assigned') <> 'cancelled'
    );
$$;

create or replace function public.can_take_exam(p_course_id uuid, p_user_id uuid default auth.uid())
returns boolean
language sql
stable
security definer
set search_path = public, pg_temp
as $$
  select p_user_id is not null
    and public.is_aula_active(p_user_id)
    and (p_user_id = auth.uid() or public.is_admin())
    and public.is_enrolled(p_course_id, p_user_id)
    and not exists (
      select 1
      from public.content_blocks b
      join public.course_phases p on p.id=b.phase_id
      where p.course_id=p_course_id
        and b.required=true
        and b.status='published'
        and not exists (
          select 1 from public.block_progress bp
          where bp.block_id=b.id and bp.user_id=p_user_id and bp.status='completed'
        )
    );
$$;

create or replace function public.can_access_certificate(p_certificate_code text)
returns boolean
language sql
stable
security definer
set search_path = public, pg_temp
as $$
  select public.is_aula_active()
    and exists (
      select 1 from public.certificates cert
      where cert.certificate_code=p_certificate_code
        and (cert.user_id=auth.uid() or public.is_admin())
    );
$$;

create or replace function public.get_my_profile()
returns table(id uuid,email text,full_name text,avatar_url text,role text,created_at timestamptz,updated_at timestamptz)
language sql
stable
security definer
set search_path = public, pg_temp
as $$
  select p.id,p.email,p.full_name,p.avatar_url,
         public.normalize_aula_ei_role(p.role),p.created_at,p.updated_at
  from public.profiles p
  where p.id=auth.uid() and public.is_aula_active()
  limit 1;
$$;

create or replace function public.set_user_role(p_user_id uuid, p_role text)
returns void
language plpgsql
security definer
set search_path = public, auth, pg_temp
as $$
declare
  v_actor uuid := auth.uid();
  v_target_role text;
  v_new_role text;
  v_super_count integer;
begin
  if v_actor is null or not public.is_super_admin() then
    raise exception 'Acceso denegado. Solo Super Admin puede cambiar roles existentes.';
  end if;
  if p_user_id = v_actor then
    raise exception 'No puedes cambiar tu propio rol desde este panel.';
  end if;
  v_new_role := public.normalize_aula_ei_role(p_role);
  if v_new_role not in ('colaborador','creador_contenido','revisor','admin','super_admin') then
    raise exception 'Rol inválido.';
  end if;
  select public.normalize_aula_ei_role(role) into v_target_role
  from public.profiles where id=p_user_id;
  if v_target_role is null then raise exception 'Usuario no encontrado en Aula EI.'; end if;
  if v_target_role='super_admin' and v_new_role<>'super_admin' then
    select count(*) into v_super_count from public.profiles
    where is_active=true and public.normalize_aula_ei_role(role)='super_admin';
    if v_super_count <= 1 then raise exception 'No se puede degradar al último Super Admin activo.'; end if;
  end if;
  update public.profiles
  set role=v_new_role, updated_at=now()
  where id=p_user_id;
  update auth.users
  set raw_app_meta_data=coalesce(raw_app_meta_data,'{}'::jsonb)
      || jsonb_build_object('aula_ei_role',v_new_role,'aula_ei_active',true),
      raw_user_meta_data=coalesce(raw_user_meta_data,'{}'::jsonb)
      || jsonb_build_object('managed_role',v_new_role)
  where id=p_user_id;
  insert into public.audit_logs(actor_id,action,entity_type,entity_id,metadata)
  values(v_actor,'set_user_role','profile',p_user_id,jsonb_build_object('old_role',v_target_role,'new_role',v_new_role));
end;
$$;

create or replace function public.complete_block(p_block_id uuid, p_data jsonb default '{}'::jsonb)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_user uuid := auth.uid();
  v_course uuid;
  v_phase uuid;
  v_phase_order integer;
  v_block_order integer;
  v_status text;
  v_required boolean;
begin
  if v_user is null then raise exception 'Sesión requerida.'; end if;
  if not public.is_aula_active(v_user) then raise exception 'Cuenta no habilitada para Aula EI.'; end if;

  select p.course_id,p.id,p.sort_order,b.sort_order,b.status,b.required
  into v_course,v_phase,v_phase_order,v_block_order,v_status,v_required
  from public.content_blocks b
  join public.course_phases p on p.id=b.phase_id
  join public.courses c on c.id=p.course_id
  where b.id=p_block_id and b.status='published' and c.status='published';
  if v_course is null then raise exception 'Contenido no disponible o no publicado.'; end if;
  if not public.is_enrolled(v_course,v_user) then raise exception 'No estás asignado a esta capacitación.'; end if;

  if exists (
    select 1
    from public.content_blocks prior
    join public.course_phases pp on pp.id=prior.phase_id
    where pp.course_id=v_course
      and prior.required=true
      and prior.status='published'
      and (pp.sort_order < v_phase_order or (pp.sort_order=v_phase_order and prior.sort_order < v_block_order))
      and not exists (
        select 1 from public.block_progress bp
        where bp.user_id=v_user and bp.block_id=prior.id and bp.status='completed'
      )
  ) then
    raise exception 'Completa primero los contenidos obligatorios anteriores.';
  end if;

  insert into public.block_progress(user_id,block_id,status,progress_percent,completed_at,data,updated_at)
  values(v_user,p_block_id,'completed',100,now(),coalesce(p_data,'{}'::jsonb),now())
  on conflict(user_id,block_id) do update
  set status='completed',progress_percent=100,completed_at=coalesce(public.block_progress.completed_at,excluded.completed_at),
      data=excluded.data,updated_at=now();

  update public.enrollments
  set status=case when status='completed' then status else 'in_progress' end, updated_at=now()
  where course_id=v_course and user_id=v_user and coalesce(status,'assigned')<>'cancelled';

  return jsonb_build_object('ok',true,'block_id',p_block_id,'course_id',v_course,'completed',true);
end;
$$;

revoke all on function public.complete_block(uuid,jsonb) from public, anon;
grant execute on function public.complete_block(uuid,jsonb) to authenticated;

drop policy if exists progress_self_insert on public.block_progress;
drop policy if exists progress_self_update on public.block_progress;
revoke insert, update, delete on public.block_progress from authenticated;

drop policy if exists profiles_self_or_admin_select on public.profiles;
create policy profiles_self_or_admin_select on public.profiles
for select to authenticated
using (((id=(select auth.uid())) and (select public.is_aula_active())) or (select public.can_manage_users()));
