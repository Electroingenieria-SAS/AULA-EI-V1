-- Prevent shared-Supabase accounts from being exposed as Aula EI members.
-- A caller may validate itself; only trusted active Admin/Super Admin callers may validate a different user.
create or replace function public.is_aula_active(p_user_id uuid default auth.uid())
returns boolean
language sql
stable
security definer
set search_path = public, auth, pg_temp
as $$
  with caller as (
    select p.id,
           p.is_active,
           public.normalize_aula_ei_role(p.role) as profile_role,
           public.normalize_aula_ei_role(u.raw_app_meta_data->>'aula_ei_role') as app_role,
           coalesce(u.raw_app_meta_data->>'aula_ei_active','false') = 'true' as app_active
    from public.profiles p
    join auth.users u on u.id=p.id
    where p.id=auth.uid()
  )
  select p_user_id is not null
    and (
      p_user_id=auth.uid()
      or exists (
        select 1 from caller c
        where c.is_active=true
          and c.app_active=true
          and c.profile_role=c.app_role
          and c.profile_role in ('admin','super_admin')
      )
    )
    and exists (
      select 1
      from public.profiles p
      join auth.users u on u.id=p.id
      where p.id=p_user_id
        and p.is_active=true
        and coalesce(u.raw_app_meta_data->>'aula_ei_active','false')='true'
        and u.raw_app_meta_data ? 'aula_ei_role'
        and public.normalize_aula_ei_role(u.raw_app_meta_data->>'aula_ei_role')=public.normalize_aula_ei_role(p.role)
    );
$$;

revoke execute on function public.is_aula_active(uuid) from public, anon;
grant execute on function public.is_aula_active(uuid) to authenticated;

drop policy if exists profiles_self_or_admin_select on public.profiles;
create policy profiles_self_or_admin_select on public.profiles
for select to authenticated
using (
  ((id=(select auth.uid())) and (select public.is_aula_active()))
  or ((select public.can_manage_users()) and public.is_aula_active(id))
);
