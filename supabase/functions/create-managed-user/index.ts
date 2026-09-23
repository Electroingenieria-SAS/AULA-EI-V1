import { serve } from "https://deno.land/std@0.224.0/http/server.ts";
import { createClient } from "npm:@supabase/supabase-js@2.107.0";

type AppRole = "colaborador" | "creador_contenido" | "revisor" | "admin" | "super_admin";
const headers = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Content-Type": "application/json",
};
const reply = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers });
const fail = (error: string, code = "VALIDATION_ERROR") => reply({ ok: false, code, error });

function generateTemporaryPassword() {
  return `${crypto.randomUUID().replaceAll("-", "").slice(0, 16)}Aa1$`;
}
function normalizeRole(rawRole: unknown): AppRole | null {
  const role = String(rawRole || "colaborador").trim().toLowerCase();
  const map: Record<string, AppRole> = {
    visitor: "colaborador", visitante: "colaborador", worker: "colaborador", trabajador: "colaborador",
    learner: "colaborador", estudiante: "colaborador", usuario: "colaborador", colaborador: "colaborador",
    content_creator: "creador_contenido", creador: "creador_contenido", creador_contenido: "creador_contenido",
    "creador de contenido": "creador_contenido", "creador-contenido": "creador_contenido",
    reviewer: "revisor", revisor: "revisor", admin: "admin", administrador: "admin",
    super_admin: "super_admin", superadmin: "super_admin", "super admin": "super_admin",
    "super-administrador": "super_admin", "super administrador": "super_admin",
  };
  return map[role] || null;
}
function passwordError(password: string, email: string) {
  if (password.length < 10 || password.length > 128) return "La contraseña temporal debe tener entre 10 y 128 caracteres.";
  if (/\s/.test(password) || !/[a-z]/.test(password) || !/[A-Z]/.test(password) || !/[0-9]/.test(password) || !/[^A-Za-z0-9]/.test(password)) {
    return "La contraseña temporal debe incluir mayúscula, minúscula, número y símbolo, sin espacios.";
  }
  const local = email.split("@")[0]?.toLowerCase() || "";
  if (local.length >= 4 && password.toLowerCase().includes(local)) return "La contraseña temporal no debe contener el usuario del correo.";
  return null;
}

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { status: 200, headers });
  if (req.method !== "POST") return reply({ ok: false, error: "Método no permitido." }, 405);
  try {
    const url = Deno.env.get("SUPABASE_URL");
    const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || Deno.env.get("SERVICE_ROLE_KEY");
    if (!url || !serviceKey) return reply({ ok: false, code: "SERVER_CONFIG", error: "Configuración segura del servidor incompleta." }, 500);

    const token = (req.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "").trim();
    if (!token) return fail("Tu sesión no está disponible. Cierra sesión e ingresa nuevamente.", "SESSION_REQUIRED");

    const admin = createClient(url, serviceKey, { auth: { autoRefreshToken: false, persistSession: false } });
    const { data: authData, error: authError } = await admin.auth.getUser(token);
    const caller = authData?.user;
    if (authError || !caller) return fail("Tu sesión venció o no pudo validarse. Cierra sesión e ingresa nuevamente.", "SESSION_INVALID");

    const { data: profile, error: profileError } = await admin.from("profiles").select("id,email,full_name,role,is_active").eq("id", caller.id).single();
    if (profileError || !profile || profile.is_active !== true) return fail("Tu cuenta administradora no está activa en Aula EI.", "ADMIN_INACTIVE");
    const callerRole = normalizeRole(profile.role);
    const trustedRole = normalizeRole(caller.app_metadata?.aula_ei_role);
    if (caller.app_metadata?.aula_ei_active !== true || !callerRole || trustedRole !== callerRole) {
      return fail("Tu sesión no tiene una membresía confiable de Aula EI. Cierra sesión e ingresa nuevamente.", "AULA_MEMBERSHIP_INVALID");
    }
    if (!["admin", "super_admin"].includes(callerRole)) return fail("Solo Admin o Super Admin pueden crear usuarios.", "FORBIDDEN");

    const body = await req.json();
    const email = String(body.email || "").trim().toLowerCase();
    const fullName = String(body.full_name || body.fullName || "").trim();
    const requestedPassword = String(body.password || "").trim();
    const role = normalizeRole(body.role || "colaborador");
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return fail("Correo inválido.", "INVALID_EMAIL");
    if (fullName.length < 3 || fullName.length > 160) return fail("El nombre completo debe tener entre 3 y 160 caracteres.", "INVALID_NAME");
    if (!role) return fail("Rol inválido para Aula EI.", "INVALID_ROLE");
    if (callerRole === "admin" && ["admin", "super_admin"].includes(role)) return fail("Un Admin no puede crear usuarios Admin ni Super Admin.", "ROLE_FORBIDDEN");
    if (callerRole !== "super_admin" && role === "super_admin") return fail("Solo un Super Admin puede crear otro Super Admin.", "ROLE_FORBIDDEN");

    const finalPassword = requestedPassword || generateTemporaryPassword();
    const invalidPassword = passwordError(finalPassword, email);
    if (invalidPassword) return fail(invalidPassword, "INVALID_PASSWORD");

    const { data: created, error: createError } = await admin.auth.admin.createUser({
      email,
      password: finalPassword,
      email_confirm: true,
      user_metadata: {
        full_name: fullName,
        created_by: caller.id,
        managed_account: true,
        managed_role: role,
        must_change_password: true,
      },
      app_metadata: {
        aula_ei_role: role,
        aula_ei_active: true,
        aula_ei_must_change_password: true,
      },
    });
    if (createError || !created?.user) {
      const raw = String(createError?.message || "No fue posible crear el usuario en Authentication.");
      const duplicate = /already|registered|exists|duplicate/i.test(raw);
      return fail(duplicate ? "Ya existe una cuenta con ese correo. Revísala en Usuarios y roles antes de volver a crearla." : raw, duplicate ? "USER_EXISTS" : "AUTH_CREATE_FAILED");
    }

    const userId = created.user.id;
    const { error: upsertError } = await admin.from("profiles").upsert({
      id: userId, email, full_name: fullName, role, is_active: true,
      deactivated_at: null, deactivated_by: null, updated_at: new Date().toISOString(),
    }, { onConflict: "id" });
    if (upsertError) {
      const { error: rollbackError } = await admin.auth.admin.deleteUser(userId, false);
      return reply({ ok: false, code: "PROFILE_CREATE_FAILED", error: "Falló la creación del perfil: " + upsertError.message + (rollbackError ? " No fue posible revertir Authentication: " + rollbackError.message : " La cuenta de Authentication fue revertida.") }, 500);
    }

    await admin.from("audit_logs").insert({
      actor_id: caller.id,
      action: "create_managed_user",
      entity_type: "profile",
      entity_id: userId,
      metadata: { email, full_name: fullName, role, password_change_required: true, created_by_email: profile.email },
    });
    return reply({ ok: true, message: "Usuario creado correctamente.", temporary_password: finalPassword, user: { id: userId, email, full_name: fullName, role } });
  } catch (error) {
    return reply({ ok: false, code: "UNEXPECTED_ERROR", error: error instanceof Error ? error.message : "Error inesperado creando usuario." }, 500);
  }
});