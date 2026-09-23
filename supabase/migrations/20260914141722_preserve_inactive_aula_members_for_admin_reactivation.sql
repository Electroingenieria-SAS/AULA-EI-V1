-- Keep inactive Aula members visible to trusted Admin/Super Admin for reactivation,
-- while continuing to block inactive users from self access.
create schema if not exists aula_private;
revoke all on schema aula_private from public, anon;
grant usage on schema aula_private to authenticated;

create or replace function aula_private.is_member(p_user_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public, auth, pg_temp
as $$
  select p_user_id is not null
    and exists (
      select 1
      from public.profiles p
      join auth.users u on u.id=p.id
      where p.id=p_user_id
        and u.raw_app_meta_data ? 'aula_ei_role'
        and public.normalize_aula_ei_role(u.raw_app_meta_data->>'aula_ei_role')=public.normalize_aula_ei_role(p.role)
    );
$$;

revoke all on function aula_private.is_member(uuid) from public, anon;
grant execute on function aula_private.is_member(uuid) to authenticated;

drop policy if exists profiles_self_or_admin_select on public.profiles;
create policy profiles_self_or_admin_select on public.profiles
for select to authenticated
using (
  ((id=(select auth.uid())) and (select public.is_aula_active()))
  or ((select public.can_manage_users()) and aula_private.is_member(id))
);
