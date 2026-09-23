-- Helper functions are internal/authenticated contracts, never anonymous API endpoints.
revoke execute on function public.is_aula_active(uuid) from public, anon;
grant execute on function public.is_aula_active(uuid) to authenticated;

revoke execute on function public.is_staff() from public, anon;
grant execute on function public.is_staff() to authenticated;

-- Trigger-only function must not be callable through PostgREST/RPC.
revoke execute on function public.validate_course_before_publish() from public, anon, authenticated;
