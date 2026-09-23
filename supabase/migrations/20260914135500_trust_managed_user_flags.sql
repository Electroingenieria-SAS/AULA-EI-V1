-- Ensure Aula EI managed-account flags are server-owned even when an older
-- provisioning function only provides aula_ei_role.

begin;

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public, auth, pg_temp
as $$
begin
  if tg_op = 'INSERT' then
    if nullif(new.raw_app_meta_data->>'aula_ei_role', '') is null then
      return new;
    end if;

    update auth.users
    set raw_app_meta_data = coalesce(raw_app_meta_data, '{}'::jsonb)
      || jsonb_build_object(
        'aula_ei_role', public.normalize_aula_ei_role(new.raw_app_meta_data->>'aula_ei_role'),
        'aula_ei_active', true,
        'aula_ei_must_change_password', true
      )
    where id = new.id;

    insert into public.profiles (
      id, email, full_name, role, is_active, deactivated_at, deactivated_by,
      created_at, updated_at
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
      null,
      null,
      now(),
      now()
    )
    on conflict (id) do update
    set
      email = excluded.email,
      full_name = coalesce(nullif(public.profiles.full_name, ''), excluded.full_name),
      role = public.normalize_aula_ei_role(public.profiles.role),
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

-- Synchronize trusted status flags for every existing managed Aula EI account.
update auth.users u
set raw_app_meta_data = coalesce(u.raw_app_meta_data, '{}'::jsonb)
  || jsonb_build_object(
    'aula_ei_role', public.normalize_aula_ei_role(p.role),
    'aula_ei_active', p.is_active,
    'aula_ei_must_change_password',
      coalesce((u.raw_app_meta_data->>'aula_ei_must_change_password')::boolean,
               (u.raw_user_meta_data->>'must_change_password')::boolean,
               false)
  )
from public.profiles p
where p.id = u.id
  and u.raw_app_meta_data ? 'aula_ei_role';

commit;
