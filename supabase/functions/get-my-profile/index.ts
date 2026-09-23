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
  const value = String(raw || "").trim().toLowerCase();
  const map: Record<string, AppRole> = {
    colaborador: "colaborador", learner: "colaborador", estudiante: "colaborador", usuario: "colaborador",
    creador_contenido: "creador_contenido", content_creator: "creador_contenido", creador: "creador_contenido",
    revisor: "revisor", reviewer: "revisor", admin: "admin", administrador: "admin",
    super_admin: "super_admin", superadmin: "super_admin", "super admin": "super_admin",
  };
  return map[value] || null;
}
serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { status: 200, headers });
  if (req.method !== "POST") return reply({ ok: false, error: "Método no permitido." }, 405);
  try {
    const url = Deno.env.get("SUPABASE_URL");
    const key = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") || Deno.env.get("SERVICE_ROLE_KEY");
    if (!url || !key) return reply({ ok: false, error: "Configuración segura incompleta." }, 500);
    const token = (req.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "").trim();
    if (!token) return reply({ ok: false, error: "Sesión requerida." }, 401);
    const admin = createClient(url, key, { auth: { autoRefreshToken: false, persistSession: false } });
    const { data: authData, error: authError } = await admin.auth.getUser(token);
    const user = authData?.user;
    if (authError || !user) return reply({ ok: false, error: "Sesión inválida o vencida." }, 401);

    const trustedRole = normalizeRole(user.app_metadata?.aula_ei_role);
    if (user.app_metadata?.aula_ei_active !== true || !trustedRole) {
      return reply({ ok: false, not_member: true, error: "Esta cuenta no está habilitada para Aula EI." });
    }

    const { data: profile, error: profileError } = await admin.from("profiles")
      .select("id,email,full_name,avatar_url,role,is_active,created_at,updated_at")
      .eq("id", user.id).maybeSingle();
    if (profileError) return reply({ ok: false, error: profileError.message });
    if (!profile || profile.is_active !== true) return reply({ ok: false, inactive: true, error: "La cuenta no está activa en Aula EI." });
    const profileRole = normalizeRole(profile.role);
    if (!profileRole || profileRole !== trustedRole) {
      return reply({ ok: false, not_member: true, error: "El rol de la cuenta no está sincronizado. Solicita revisión a un Super Admin." });
    }

    return reply({
      ok: true,
      profile: {
        id: profile.id,
        email: profile.email,
        full_name: profile.full_name,
        avatar_url: profile.avatar_url,
        role: profileRole,
        created_at: profile.created_at,
        updated_at: profile.updated_at,
      },
      must_change_password: user.app_metadata?.aula_ei_must_change_password === true,
    });
  } catch (error) {
    return reply({ ok: false, error: error instanceof Error ? error.message : "Error inesperado cargando el perfil." }, 500);
  }
});