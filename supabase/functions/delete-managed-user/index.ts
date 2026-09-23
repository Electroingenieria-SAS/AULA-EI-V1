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
function normalizeRole(raw: unknown): AppRole | null {
  const v = String(raw || "").trim().toLowerCase();
  const m: Record<string, AppRole> = {
    colaborador:"colaborador",learner:"colaborador",estudiante:"colaborador",usuario:"colaborador",
    creador_contenido:"creador_contenido",content_creator:"creador_contenido",creador:"creador_contenido",
    revisor:"revisor",reviewer:"revisor",admin:"admin",administrador:"admin",
    super_admin:"super_admin",superadmin:"super_admin","super admin":"super_admin",
  };
  return m[v] || null;
}
const rank: Record<AppRole, number> = { colaborador:10, creador_contenido:20, revisor:30, admin:40, super_admin:50 };

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers });
  if (req.method !== "POST") return reply({ ok:false, error:"Método no permitido." }, 405);
  try {
    const url = Deno.env.get("SUPABASE_URL");
    const key = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || Deno.env.get("SERVICE_ROLE_KEY");
    if (!url || !key) return reply({ ok:false, error:"Configuración segura incompleta." }, 500);
    const token = (req.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "").trim();
    if (!token) return reply({ ok:false, error:"Sesión requerida." }, 401);
    const admin = createClient(url, key, { auth:{ autoRefreshToken:false, persistSession:false } });
    const { data: callerAuth, error: callerAuthError } = await admin.auth.getUser(token);
    const caller = callerAuth?.user;
    if (callerAuthError || !caller) return reply({ ok:false, error:"Sesión inválida." }, 401);

    const { data: callerProfile } = await admin.from("profiles").select("id,role,is_active").eq("id",caller.id).single();
    if (!callerProfile || callerProfile.is_active !== true) return reply({ ok:false, error:"Cuenta administradora no activa." }, 403);
    const callerRole = normalizeRole(callerProfile.role);
    const trustedCallerRole = normalizeRole(caller.app_metadata?.aula_ei_role);
    if (caller.app_metadata?.aula_ei_active !== true || !callerRole || trustedCallerRole !== callerRole) {
      return reply({ ok:false, error:"La membresía o el rol del administrador no están sincronizados en Aula EI." }, 403);
    }
    if (!["admin","super_admin"].includes(callerRole)) return reply({ ok:false, error:"Solo Admin o Super Admin pueden administrar accesos." }, 403);

    const body = await req.json();
    const targetId = String(body.user_id || "").trim();
    const desiredActive = body.active === true;
    if (!targetId) return reply({ ok:false, error:"Falta user_id." }, 400);
    if (targetId === caller.id) return reply({ ok:false, error:"No puedes desactivar tu propia cuenta." }, 400);

    const { data: targetProfile, error: targetProfileError } = await admin.from("profiles").select("id,email,full_name,role,is_active").eq("id",targetId).single();
    if (targetProfileError || !targetProfile) return reply({ ok:false, error:"Usuario no encontrado." }, 404);
    const targetRole = normalizeRole(targetProfile.role);
    if (!targetRole) return reply({ ok:false, error:"El usuario objetivo tiene un rol inválido." }, 409);
    if (rank[callerRole] <= rank[targetRole]) return reply({ ok:false, error:"Solo puedes administrar usuarios con un nivel inferior al tuyo." }, 403);

    const { data: targetAuthData, error: targetAuthError } = await admin.auth.admin.getUserById(targetId);
    const targetAuth = targetAuthData?.user;
    if (targetAuthError || !targetAuth) return reply({ ok:false, error:"Cuenta Auth no encontrada." }, 404);

    const { error: authUpdateError } = await admin.auth.admin.updateUserById(targetId, {
      ban_duration: desiredActive ? "none" : "876000h",
      app_metadata: { ...targetAuth.app_metadata, aula_ei_role:targetRole, aula_ei_active:desiredActive },
    });
    if (authUpdateError) return reply({ ok:false, error:authUpdateError.message }, 400);

    const now = new Date().toISOString();
    const { error: profileUpdateError } = await admin.from("profiles").update({
      is_active:desiredActive,
      deactivated_at:desiredActive ? null : now,
      deactivated_by:desiredActive ? null : caller.id,
      updated_at:now,
    }).eq("id",targetId);
    if (profileUpdateError) {
      await admin.auth.admin.updateUserById(targetId, {
        ban_duration: desiredActive ? "876000h" : "none",
        app_metadata:{ ...targetAuth.app_metadata },
      });
      return reply({ ok:false, error:"No fue posible actualizar el perfil: " + profileUpdateError.message }, 500);
    }

    await admin.from("audit_logs").insert({
      actor_id:caller.id,
      action:desiredActive ? "reactivate_managed_user" : "deactivate_managed_user",
      entity_type:"profile",
      entity_id:targetId,
      metadata:{ target_email:targetProfile.email, target_role:targetRole, previous_active:targetProfile.is_active, new_active:desiredActive },
    });
    return reply({ ok:true, active:desiredActive, preserved_history:true, message:desiredActive ? "Usuario reactivado. Se conservó todo su historial." : "Usuario desactivado. Se conservaron matrículas, progreso y certificados." });
  } catch (error) {
    return reply({ ok:false, error:error instanceof Error ? error.message : "Error inesperado." }, 500);
  }
});