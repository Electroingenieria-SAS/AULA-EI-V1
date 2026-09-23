-- Existing managed accounts were historically created with must_change_password=true,
-- but the legacy frontend never completed that workflow. Do not force a retroactive
-- password reset across the installed user base; the new provisioning flow will set
-- the flag only for newly-created accounts once the UI consumes it end-to-end.

begin;

update auth.users
set raw_app_meta_data = jsonb_set(
      coalesce(raw_app_meta_data, '{}'::jsonb),
      '{aula_ei_must_change_password}',
      'false'::jsonb,
      true
    ),
    raw_user_meta_data = jsonb_set(
      coalesce(raw_user_meta_data, '{}'::jsonb),
      '{must_change_password}',
      'false'::jsonb,
      true
    )
where raw_app_meta_data ? 'aula_ei_role'
  and created_at < now();

commit;
