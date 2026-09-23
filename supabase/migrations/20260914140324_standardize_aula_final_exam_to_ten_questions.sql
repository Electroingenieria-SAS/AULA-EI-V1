-- Standardize Aula EI final assessments to 10 questions without deleting existing question banks.

create or replace function public.get_exam_questions(p_course_id uuid)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_result jsonb;
begin
  if auth.uid() is null then raise exception 'Sesión requerida.'; end if;
  if not public.is_aula_active() then raise exception 'Cuenta no habilitada para Aula EI.'; end if;
  if not (public.can_manage_courses() or public.is_enrolled(p_course_id, auth.uid())) then
    raise exception 'No tienes acceso a este examen.';
  end if;
  if not public.can_manage_courses() and not public.can_take_exam(p_course_id, auth.uid()) then
    raise exception 'Completa primero todos los contenidos obligatorios.';
  end if;

  select jsonb_agg(
    jsonb_build_object(
      'id',q.id,
      'prompt',q.prompt,
      'options',coalesce((
        select jsonb_agg(jsonb_build_object('id',o.id,'label',o.label) order by o.sort_order)
        from public.question_options o where o.question_id=q.id
      ),'[]'::jsonb)
    ) order by q.exam_order
  ) into v_result
  from (
    select base.*, row_number() over () as exam_order
    from (
      select id,prompt,sort_order
      from public.questions
      where course_id=p_course_id and active=true
      order by random()
      limit 10
    ) base
  ) q;

  if v_result is null or jsonb_array_length(v_result)=0 then
    raise exception 'El examen no tiene preguntas activas.';
  end if;
  return v_result;
end;
$$;

create or replace function public.submit_exam(p_course_id uuid,p_answers jsonb)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_user uuid := auth.uid();
  v_available integer;
  v_total integer;
  v_answer_count integer;
  v_valid_questions integer;
  v_correct integer;
  v_score integer;
  v_passing integer;
  v_passed boolean;
  v_attempt uuid;
  v_code text;
  v_existing_code text;
begin
  if v_user is null then raise exception 'Sesión requerida.'; end if;
  if not public.is_aula_active(v_user) then raise exception 'Cuenta no habilitada para Aula EI.'; end if;
  if not public.is_enrolled(p_course_id,v_user) then raise exception 'No estás asignado a esta capacitación.'; end if;
  if not public.can_take_exam(p_course_id,v_user) then raise exception 'Completa primero todos los contenidos obligatorios.'; end if;

  select passing_score into v_passing from public.courses where id=p_course_id and status='published';
  if v_passing is null then raise exception 'Curso no disponible o no publicado.'; end if;

  select count(*) into v_available from public.questions where course_id=p_course_id and active=true;
  if v_available=0 then raise exception 'El examen no tiene preguntas activas.'; end if;
  v_total := least(10,v_available);
  if jsonb_typeof(coalesce(p_answers,'{}'::jsonb)) <> 'object' then raise exception 'Formato de respuestas inválido.'; end if;
  select count(*) into v_answer_count from jsonb_object_keys(coalesce(p_answers,'{}'::jsonb));
  if v_answer_count <> v_total then
    raise exception 'Debes responder exactamente % preguntas para enviar este examen.',v_total;
  end if;

  select count(*) into v_valid_questions
  from public.questions q
  where q.course_id=p_course_id and q.active=true
    and coalesce(p_answers,'{}'::jsonb) ? q.id::text;
  if v_valid_questions <> v_total then raise exception 'El examen contiene respuestas para preguntas no válidas.'; end if;

  select count(*) into v_correct
  from public.questions q
  join public.question_options o on o.question_id=q.id and o.is_correct=true
  where q.course_id=p_course_id and q.active=true
    and (coalesce(p_answers,'{}'::jsonb)->>q.id::text)=o.id::text;

  v_score := round((v_correct::numeric/v_total::numeric)*100)::integer;
  v_passed := v_score >= v_passing;

  insert into public.exam_attempts(course_id,user_id,answers,score,passed)
  values(p_course_id,v_user,coalesce(p_answers,'{}'::jsonb),v_score,v_passed)
  returning id into v_attempt;

  if v_passed then
    select certificate_code into v_existing_code from public.certificates
    where course_id=p_course_id and user_id=v_user;
    v_code := coalesce(v_existing_code,public.next_certificate_code());
    insert into public.certificates(course_id,user_id,exam_attempt_id,certificate_code,score,issued_at)
    values(p_course_id,v_user,v_attempt,v_code,v_score,now())
    on conflict(course_id,user_id) do update
      set exam_attempt_id=excluded.exam_attempt_id,
          certificate_code=public.certificates.certificate_code,
          score=greatest(public.certificates.score,excluded.score),
          issued_at=public.certificates.issued_at
    returning certificate_code into v_code;
    update public.enrollments set status='completed',updated_at=now()
    where course_id=p_course_id and user_id=v_user;
  else
    update public.enrollments set status='in_progress',updated_at=now()
    where course_id=p_course_id and user_id=v_user;
  end if;

  return jsonb_build_object('attempt_id',v_attempt,'score',v_score,'passed',v_passed,'certificate_code',v_code,'question_count',v_total);
end;
$$;

create or replace function public.validate_course_before_publish()
returns trigger
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_questions integer;
  v_invalid integer;
begin
  if new.status='published' and (tg_op='INSERT' or old.status is distinct from new.status) then
    select count(*) into v_questions from public.questions q where q.course_id=new.id and q.active=true;
    if v_questions < 10 then
      raise exception 'Para publicar una capacitación debes crear al menos 10 preguntas activas en el examen final.';
    end if;
    select count(*) into v_invalid
    from public.questions q
    where q.course_id=new.id and q.active=true
      and ((select count(*) from public.question_options o where o.question_id=q.id) < 2
        or (select count(*) from public.question_options o where o.question_id=q.id and o.is_correct=true) <> 1);
    if v_invalid > 0 then
      raise exception 'Todas las preguntas activas deben tener al menos dos opciones y exactamente una respuesta correcta.';
    end if;
  end if;
  return new;
end;
$$;

drop trigger if exists validate_course_before_publish on public.courses;
create trigger validate_course_before_publish
before insert or update of status on public.courses
for each row execute function public.validate_course_before_publish();
