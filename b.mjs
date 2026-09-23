import { createHash } from 'node:crypto';
import { cp, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import JavaScriptObfuscator from 'javascript-obfuscator';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)));
const dist = path.join(root, 'dist');

function replaceExactly(source, before, after, code) {
  const count = source.split(before).length - 1;
  if (count !== 1) throw new Error(`${code}: expected exactly one match, got ${count}`);
  return source.replace(before, after);
}

await rm(dist, { recursive: true, force: true });
await mkdir(dist, { recursive: true });
for (const name of ['index.html', '404.html', 'favicon.svg', 'assets', 'brand']) {
  await cp(path.join(root, name), path.join(dist, name), { recursive: true });
}

const assetsDir = path.join(dist, 'assets');
const jsFiles = (await readdir(assetsDir)).filter((name) => /^index-.*\.js$/.test(name));
if (jsFiles.length !== 1) throw new Error(`E1: expected one application bundle, found ${jsFiles.length}`);

const originalName = jsFiles[0];
const originalPath = path.join(assetsDir, originalName);
let bundle = await readFile(originalPath, 'utf8');


bundle = replaceExactly(
  bundle,
  're=Uw(Lw,Bw,{auth:{persistSession:!0,autoRefreshToken:!0,detectSessionInUrl:!0}})',
  're=Uw(Lw,Bw,{auth:{persistSession:!0,autoRefreshToken:!0,detectSessionInUrl:!0,storageKey:"aula-ei-pre21-operativa"}})',
  'E1A'
);

const oldProfileLoader = 'g=async(v,S)=>{const x=S??a?.user??null,w=v??x?.id;if(!w){o(null);return}const{data:C,error:A}=await Dr(re.from("profiles").select("*").eq("id",w).maybeSingle(),Cc,"Supabase tardó demasiado cargando el perfil del usuario.");if(A)throw A;if(C){const M=C;o({...M,role:ry(M.role)});return}if(x){const M=Rc(x);o(M),m("Tu sesión inició, pero el perfil no estaba sincronizado. Se cargó un perfil temporal de colaborador.");return}o(null)}';
const newProfileLoader = 'g=async(v,S)=>{const x=S??a?.user??null,w=v??x?.id;if(!w){o(null);return}const{data:C,error:A}=await Dr(re.functions.invoke("get-my-profile",{body:{}}),Cc,"Supabase tardó demasiado cargando el perfil del usuario.");if(A)throw A;if(C?.ok&&C.profile){const M=C.profile;o({...M,role:ry(M.role)});return}if(C?.inactive||C?.not_member){await re.auth.signOut().catch(()=>{}),o(null),m(C.error||"Esta cuenta no está habilitada para Aula EI.");return}if(x&&AULA_trustedUser(x)){const M=Rc(x);o(M),m(C?.error||"No fue posible validar el perfil en este momento. Se usó temporalmente la membresía confiable de la sesión.");return}await re.auth.signOut().catch(()=>{}),o(null),m(C?.error||"Esta cuenta no está habilitada para Aula EI.")}';
bundle = replaceExactly(bundle, oldProfileLoader, newProfileLoader, 'E2');

bundle = replaceExactly(
  bundle,
  'function Rc(n){',
  'function AULA_trustedUser(n){return n?.app_metadata?.aula_ei_active===true&&!!n?.app_metadata?.aula_ei_role}function Rc(n){',
  'E3'
);

const oldInitialFallback = 'await g(w.session.user.id,w.session.user).catch(A=>{console.warn("Aula EI: no fue posible cargar el perfil.",A),o(Rc(w.session.user)),m(jl(A,"No fue posible cargar el perfil. Se usó perfil temporal."))})';
const newInitialFallback = 'await g(w.session.user.id,w.session.user).catch(A=>{console.warn("Aula EI: no fue posible cargar el perfil.",A),AULA_trustedUser(w.session.user)?(o(Rc(w.session.user)),m(jl(A,"No fue posible validar el perfil. Se usó temporalmente la membresía confiable de la sesión."))):(o(null),m("Esta cuenta no está habilitada para Aula EI."),re.auth.signOut().catch(()=>{}))})';
bundle = replaceExactly(bundle, oldInitialFallback, newInitialFallback, 'E4');

const oldAuthListener = 're.auth.onAuthStateChange(async(w,C)=>{r(C),m(null),C?.user?await g(C.user.id,C.user).catch(A=>{console.warn("Aula EI: error al actualizar perfil.",A),o(Rc(C.user)),m(jl(A,"No fue posible actualizar el perfil. Se usó perfil temporal."))}):o(null),f(!1)})';
const newAuthListener = 're.auth.onAuthStateChange((w,C)=>{r(C),m(null),C?.user?setTimeout(()=>{v&&g(C.user.id,C.user).catch(A=>{console.warn("Aula EI: error al actualizar perfil.",A),AULA_trustedUser(C.user)?(o(Rc(C.user)),m(jl(A,"No fue posible validar el perfil. Se usó temporalmente la membresía confiable de la sesión."))):(o(null),m("Esta cuenta no está habilitada para Aula EI."),re.auth.signOut().catch(()=>{}))})},0):o(null),f(!1)})';
bundle = replaceExactly(bundle, oldAuthListener, newAuthListener, 'E5');

const oldFallbackRole = 'role:ry(n.user_metadata?.managed_role)';
const newFallbackRole = 'role:ry(n.app_metadata?.aula_ei_role)';
bundle = replaceExactly(bundle, oldFallbackRole, newFallbackRole, 'E6');

// Aula EI accounts are provisioned only by authorized administrators.
const signupToggle = 'd.jsx("button",{type:"button",className:"text-button",onClick:()=>c(o==="login"?"signup":"login"),children:o==="login"?"Crear una cuenta inicial":"Ya tengo una cuenta"})';
const signupNotice = 'd.jsx("p",{className:"helper-text",children:"Las cuentas de Aula EI son creadas y habilitadas por un Administrador autorizado."})';
bundle = replaceExactly(bundle, signupToggle, signupNotice, 'E7');

// Mandatory first-login password change for managed accounts.
const passwordGate = 'function AULA_PasswordGate(){const[n,a]=j.useState(""),[r,l]=j.useState(""),[o,c]=j.useState(""),[f,p]=j.useState(!1),m=async g=>{g.preventDefault(),c("");if(n!==r){c("Las contraseñas no coinciden.");return}if(n.length<12||n.length>128||/\\s/.test(n)||!/[a-z]/.test(n)||!/[A-Z]/.test(n)||!/[0-9]/.test(n)||!/[^A-Za-z0-9]/.test(n)){c("Usa entre 12 y 128 caracteres, con mayúscula, minúscula, número y símbolo, sin espacios.");return}p(!0);try{const{data:b,error:v}=await re.functions.invoke("complete-password-change",{body:{password:n}});if(v)throw new Error(String(b?.error||v.message||"No fue posible actualizar la contraseña."));if(b?.ok===!1)throw new Error(String(b?.error||"No fue posible actualizar la contraseña."));c("Contraseña actualizada. Por seguridad debes iniciar sesión nuevamente."),await re.auth.signOut(),window.location.hash="/login",setTimeout(()=>window.location.reload(),250)}catch(b){c(jl(b,"No fue posible actualizar la contraseña."))}finally{p(!1)}};return d.jsx("main",{className:"startup-page",children:d.jsxs("section",{className:"startup-card",children:[d.jsx("div",{className:"startup-logo",children:"EI"}),d.jsx("h1",{children:"Crea tu contraseña personal"}),d.jsx("p",{children:"Esta cuenta fue creada con una contraseña temporal. Antes de continuar debes establecer una contraseña personal segura."}),d.jsxs("form",{className:"auth-form",onSubmit:m,children:[d.jsxs("label",{children:["Nueva contraseña",d.jsx("input",{type:"password",autoComplete:"new-password",minLength:12,maxLength:128,value:n,onChange:g=>a(g.target.value),required:!0})]}),d.jsxs("label",{children:["Confirmar contraseña",d.jsx("input",{type:"password",autoComplete:"new-password",minLength:12,maxLength:128,value:r,onChange:g=>l(g.target.value),required:!0})]}),d.jsx("small",{className:"helper-text",children:"Mínimo 12 caracteres con mayúscula, minúscula, número y símbolo."}),d.jsx("button",{className:"primary-button",disabled:f,children:f?"Actualizando…":"Guardar contraseña y continuar"}),o&&d.jsx("p",{className:"form-message",children:o})]})]})})}';
const adminAuthGate = 'function AULA_AdminAuthGate({user:n,children:a}){const r=ry(n?.app_metadata?.aula_ei_role||n?.user_metadata?.managed_role),l=["admin","super_admin"].includes(r),[o,c]=j.useState("idle"),[f,p]=j.useState(null),[m,g]=j.useState(null),[b,v]=j.useState(""),[S,x]=j.useState(""),[w,C]=j.useState(!1);j.useEffect(()=>{if(!l){c("ready");return}let A=!0;(async()=>{try{const{data:M,error:q}=await re.auth.mfa.getAuthenticatorAssuranceLevel();if(q)throw q;if(A&&M?.currentLevel==="aal2")c("ready")}catch{}})();return()=>{A=!1}},[l,n?.id]);const A=async()=>{C(!0),x("");try{const{data:M,error:q}=await re.auth.mfa.getAuthenticatorAssuranceLevel();if(q)throw q;if(M?.currentLevel==="aal2"){c("ready");return}const{data:z,error:K}=await re.auth.mfa.listFactors();if(K)throw K;const I=(z?.totp||[]).find(B=>B.status==="verified");if(I){p(I),c("challenge");return}for(const B of(z?.totp||[]).filter(R=>R.status!=="verified"))await re.auth.mfa.unenroll({factorId:B.id}).catch(()=>{});const B=await re.auth.mfa.enroll({factorType:"totp",friendlyName:"Aula EI · Administración"});if(B.error)throw B.error;p(B.data),g(B.data),c("enroll")}catch(M){x(jl(M,"No fue posible preparar la autenticación administrativa."))}finally{C(!1)}},M=async q=>{q.preventDefault();const z=b.replace(/\\D/g,"").slice(0,6);if(z.length!==6||!f?.id){x("Ingresa el código de 6 dígitos.");return}C(!0),x("");try{const K=await re.auth.mfa.challenge({factorId:f.id});if(K.error)throw K.error;const I=await re.auth.mfa.verify({factorId:f.id,challengeId:K.data.id,code:z});if(I.error)throw I.error;const B=await re.auth.refreshSession();if(B.error)throw B.error;const R=await re.auth.mfa.getAuthenticatorAssuranceLevel();if(R.error)throw R.error;if(R.data?.currentLevel!=="aal2")throw new Error("La sesión no alcanzó el nivel de seguridad requerido.");v(""),c("ready")}catch(K){x(jl(K,"No fue posible verificar el código."))}finally{C(!1)}};if(!l||o==="ready")return d.jsx(d.Fragment,{children:a});return d.jsx("main",{className:"startup-page",children:d.jsxs("section",{className:"startup-card",children:[d.jsx("div",{className:"startup-logo",children:"EI"}),d.jsx("h1",{children:o==="idle"?"Autenticación del módulo administrativo":o==="enroll"?"Configura tu autenticación":"Confirma tu autenticación"}),d.jsx("p",{children:o==="idle"?"Para entrar a Gestión Aula EI debes autenticar nuevamente el módulo administrativo. Esto no afecta el uso normal de las capacitaciones.":o==="enroll"?"Escanea el QR con Google Authenticator o Microsoft Authenticator y escribe el código de 6 dígitos.":"Escribe el código actual de 6 dígitos de tu aplicación autenticadora."}),o==="idle"&&d.jsx("button",{className:"primary-button",disabled:w,onClick:A,children:w?"Validando…":"Autenticar módulo administrativo"}),o==="enroll"&&m?.totp?.qr_code&&d.jsx("img",{src:m.totp.qr_code,alt:"QR de autenticación",style:{width:"220px",maxWidth:"100%",display:"block",margin:"16px auto",padding:"10px",background:"#fff",borderRadius:"14px"}}),(o==="enroll"||o==="challenge")&&d.jsxs("form",{className:"auth-form",onSubmit:M,children:[d.jsxs("label",{children:["Código de 6 dígitos",d.jsx("input",{inputMode:"numeric",autoComplete:"one-time-code",pattern:"[0-9]*",maxLength:6,value:b,onChange:q=>v(q.target.value.replace(/\\D/g,"").slice(0,6)),required:!0})]}),d.jsx("button",{className:"primary-button",disabled:w,children:w?"Verificando…":"Verificar y entrar"})]}),S&&d.jsx("p",{className:"form-message",children:S})]})})}';
bundle = replaceExactly(bundle, 'function cg({children:n,admin:a=!1}){', passwordGate + adminAuthGate + 'function cg({children:n,admin:a=!1}){', 'E8');
bundle = replaceExactly(
  bundle,
  '):r?a&&!l?d.jsx(Cl,{to:"/",replace:!0}):d.jsx(d.Fragment,{children:n}):d.jsx(Cl,{to:"/login",replace:!0,state:{authError:c}})}',
  '):r?(r.app_metadata?.aula_ei_must_change_password===true||r.user_metadata?.must_change_password===true)?d.jsx(AULA_PasswordGate,{}):a&&!l?d.jsx(Cl,{to:"/",replace:!0}):a?d.jsx(AULA_AdminAuthGate,{user:r,children:n}):d.jsx(d.Fragment,{children:n}):d.jsx(Cl,{to:"/login",replace:!0,state:{authError:c}})}',
  'E9'
);

// Block completion is server-owned; direct REST writes are forbidden.
const directProgressWrite = 'const{error:Se}=await re.from("block_progress").upsert({user_id:a.id,block_id:he,status:"completed",progress_percent:100,completed_at:new Date().toISOString(),data:_e},{onConflict:"user_id,block_id"});';
const rpcProgressWrite = 'const{error:Se}=await re.rpc("complete_block",{p_block_id:he,p_data:_e});';
bundle = replaceExactly(bundle, directProgressWrite, rpcProgressWrite, 'E10');

// Sanitize staff-authored HTML and external links before rendering.
const safeHelpers = 'function AULA_safeExternalUrl(n){try{const a=new URL(String(n||""),window.location.origin);return a.protocol==="https:"||a.protocol==="http:"?a.toString():""}catch{return""}}function AULA_safeHtml(n){if(typeof document==="undefined")return String(n??"");const a=document.createElement("template");a.innerHTML=String(n??""),a.content.querySelectorAll("script,style,iframe,object,embed,form,input,button,textarea,select,meta,link,base").forEach(r=>r.remove());const l=document.createTreeWalker(a.content,NodeFilter.SHOW_ELEMENT);let o;for(;o=l.nextNode();)for(const c of[...o.attributes]){const f=c.name.toLowerCase(),p=c.value.trim();f.startsWith("on")||f==="style"?o.removeAttribute(c.name):(f==="href"||f==="src")&&!AULA_safeExternalUrl(p)&&!p.startsWith("#")&&o.removeAttribute(c.name)}return a.content.querySelectorAll("a").forEach(r=>{r.setAttribute("rel","noopener noreferrer"),r.setAttribute("target","_blank")}),a.innerHTML}';
bundle = replaceExactly(bundle, 'function gx(n,a){', safeHelpers + 'function gx(n,a){', 'E11');
bundle = replaceExactly(bundle, 'function gx(n,a){const r=n.trim();', 'function gx(n,a){const r=AULA_safeExternalUrl(n.trim());', 'E12');
bundle = replaceExactly(
  bundle,
  'dangerouslySetInnerHTML:{__html:String(g.html??g.text??"Agrega contenido desde el Super Admin.")}',
  'dangerouslySetInnerHTML:{__html:AULA_safeHtml(String(g.html??g.text??"Agrega contenido desde el Super Admin."))}',
  'E13'
);
bundle = replaceExactly(
  bundle,
  'href:String(g.url??"#")',
  'href:AULA_safeExternalUrl(String(g.url??""))||"#"',
  'E14'
);

// Staff may manage learning content, but only Admin/Super Admin see global user, assignment and certificate controls.
bundle = replaceExactly(
  bundle,
  'function Ax(){const{profile:n}=ln(),[a,r]=j.useState("courses"),',
  'function Ax(){const{profile:n}=ln(),AULA_canAdmin=["admin","super_admin"].includes(n?.role??""),[a,r]=j.useState("courses"),',
  'E15'
);
bundle = replaceExactly(bundle, 'children:"Super Admin · Constructor Aula EI"', 'children:"Gestión de contenidos · Aula EI"', 'E16');
bundle = replaceExactly(
  bundle,
  'd.jsxs("button",{className:a==="assignments"?"active":"",onClick:()=>r("assignments"),children:[d.jsx(Vr,{})," Asignaciones"]})',
  'AULA_canAdmin&&d.jsxs("button",{className:a==="assignments"?"active":"",onClick:()=>r("assignments"),children:[d.jsx(Vr,{})," Asignaciones"]})',
  'E17'
);
bundle = replaceExactly(
  bundle,
  'd.jsxs("button",{className:a==="users"?"active":"",onClick:()=>r("users"),children:[d.jsx(my,{})," Usuarios y roles"]})',
  'AULA_canAdmin&&d.jsxs("button",{className:a==="users"?"active":"",onClick:()=>r("users"),children:[d.jsx(my,{})," Usuarios y roles"]})',
  'E18'
);
bundle = replaceExactly(
  bundle,
  'd.jsxs("button",{className:a==="certificates"?"active":"",onClick:()=>r("certificates"),children:[d.jsx(kn,{})," Ranking y certificados"]})',
  'AULA_canAdmin&&d.jsxs("button",{className:a==="certificates"?"active":"",onClick:()=>r("certificates"),children:[d.jsx(kn,{})," Ranking y certificados"]})',
  'E19'
);
bundle = replaceExactly(bundle, 'a==="assignments"&&d.jsx(Ux,', 'AULA_canAdmin&&a==="assignments"&&d.jsx(Ux,', 'E20');
bundle = replaceExactly(bundle, 'a==="users"&&d.jsx(zx,', 'AULA_canAdmin&&a==="users"&&d.jsx(zx,', 'E21');
bundle = replaceExactly(bundle, 'a==="certificates"&&d.jsx(Dx,', 'AULA_canAdmin&&a==="certificates"&&d.jsx(Dx,', 'E22');
bundle = replaceExactly(
  bundle,
  'a&&d.jsxs(Ca,{to:"/studio",children:[d.jsx(ug,{size:18}),"Super Admin"]})',
  'a&&d.jsxs(Ca,{to:"/studio",children:[d.jsx(ug,{size:18}),"Gestión Aula EI"]})',
  'E23'
);
bundle = replaceExactly(
  bundle,
  'a&&d.jsxs(Ca,{to:"/studio",children:[d.jsx(ug,{size:18}),d.jsx("span",{children:"Admin"})]})',
  'a&&d.jsxs(Ca,{to:"/studio",children:[d.jsx(ug,{size:18}),d.jsx("span",{children:"Gestión"})]})',
  'E24'
);

// Role changes are Super Admin-only in both UI and database.
bundle = replaceExactly(
  bundle,
  'function zx({profiles:n,onRefresh:a,setMessage:r}){const{profile:l}=ln(),[o,c]=j.useState({full_name:"",email:"",password:"",role:"colaborador"}),',
  'function zx({profiles:n,onRefresh:a,setMessage:r}){const{profile:l}=ln(),AULA_canChangeRoles=l?.role==="super_admin",[o,c]=j.useState({full_name:"",email:"",password:"",role:"colaborador"}),',
  'E25'
);
bundle = replaceExactly(
  bundle,
  'd.jsxs("select",{value:K.role,onChange:C=>w(K.id,C.target.value),children:[',
  'd.jsxs("select",{value:K.role,disabled:!AULA_canChangeRoles||K.id===l?.id,onChange:C=>w(K.id,C.target.value),children:[',
  'E26'
);

// Safe deactivation/reactivation instead of destructive deletion language.
const oldUserAction = 'H=async K=>{if(!x(K)){r("Solo puedes eliminar usuarios con un nivel inferior al tuyo.");return}if(!window.confirm("¿Eliminar a "+(K.full_name||K.email||"este usuario")+"? Esta acción revoca su acceso y elimina sus registros asociados. No se puede deshacer."))return;y(K.id);try{const{data:C,error:I}=await re.functions.invoke("delete-managed-user",{body:{user_id:K.id}});if(I)throw new Error(String(C?.error||I.message||"No fue posible eliminar el usuario."));if(C?.ok===!1)throw new Error(String(C?.error||"No fue posible eliminar el usuario."));r("Usuario eliminado: "+(K.full_name||K.email||K.id)),await a()}catch(C){r(C instanceof Error?C.message:"No fue posible eliminar el usuario.")}finally{y(null)}}';
const newUserAction = 'H=async K=>{if(!x(K)){r("Solo puedes administrar usuarios con un nivel inferior al tuyo.");return}const C=K.is_active===false;if(!window.confirm(C?"¿Reactivar a "+(K.full_name||K.email||"este usuario")+"?":"¿Desactivar a "+(K.full_name||K.email||"este usuario")+"? Se revocará su acceso, pero se conservarán matrículas, progreso, intentos y certificados."))return;y(K.id);try{const{data:I,error:B}=await re.functions.invoke("delete-managed-user",{body:{user_id:K.id,active:C}});if(B)throw new Error(String(I?.error||B.message||"No fue posible actualizar el usuario."));if(I?.ok===!1)throw new Error(String(I?.error||"No fue posible actualizar el usuario."));r(String(I?.message||(C?"Usuario reactivado.":"Usuario desactivado."))),await a()}catch(I){r(I instanceof Error?I.message:"No fue posible actualizar el usuario.")}finally{y(null)}}';
bundle = replaceExactly(bundle, oldUserAction, newUserAction, 'E27');
bundle = replaceExactly(
  bundle,
  'className:"danger-button",disabled:b===K.id,onClick:()=>H(K),children:b===K.id?"Eliminando…":"Eliminar"',
  'className:K.is_active===false?"secondary-button":"danger-button",disabled:b===K.id,onClick:()=>H(K),children:b===K.id?"Procesando…":K.is_active===false?"Reactivar":"Desactivar"',
  'E28'
);

// Creation password hint matches server policy.
bundle = replaceExactly(
  bundle,
  'children:"La contraseña se muestra una sola vez para compartirla con el usuario."',
  'children:"Se muestra una sola vez. Si la escribes manualmente debe tener mínimo 12 caracteres, mayúscula, minúscula, número y símbolo."',
  'E29'
);

// Defensive build assertions: all risky legacy paths must be gone before obfuscation.
if (bundle.includes('re.from("profiles").select("*").eq("id",w).maybeSingle()')) throw new Error('E30: direct current-profile REST lookup still present');
if (bundle.includes('onAuthStateChange(async(w,C)=>') || !bundle.includes('onAuthStateChange((w,C)=>')) throw new Error('E31: auth listener patch failed');
if (bundle.includes(oldFallbackRole)) throw new Error('E32: fallback role patch failed');
if (bundle.includes('re.from("block_progress").upsert(')) throw new Error('E33: direct block progress write still present');
if (bundle.includes('"Crear una cuenta inicial"')) throw new Error('E34: public signup toggle still present');
if (bundle.includes('dangerouslySetInnerHTML:{__html:String(')) throw new Error('E35: unsanitized HTML renderer still present');
if (!bundle.includes('complete-password-change') || !bundle.includes('complete_block')) throw new Error('E36: mandatory security flows missing');
if (!bundle.includes('AULA_AdminAuthGate') || !bundle.includes('Autenticar módulo administrativo') || !bundle.includes('aula-ei-pre21-operativa')) throw new Error('E36A: pre-21 admin auth compatibility missing');

bundle = JavaScriptObfuscator.obfuscate(bundle, {
  compact: true,
  target: 'browser',
  identifierNamesGenerator: 'hexadecimal',
  renameGlobals: false,
  renameProperties: false,
  stringArray: true,
  stringArrayEncoding: ['base64'],
  stringArrayThreshold: 0.82,
  stringArrayCallsTransform: true,
  stringArrayCallsTransformThreshold: 0.7,
  stringArrayIndexShift: true,
  stringArrayRotate: true,
  stringArrayShuffle: true,
  stringArrayWrappersCount: 2,
  stringArrayWrappersChainedCalls: true,
  stringArrayWrappersParametersMaxCount: 4,
  stringArrayWrappersType: 'function',
  splitStrings: true,
  splitStringsChunkLength: 8,
  numbersToExpressions: true,
  simplify: true,
  controlFlowFlattening: false,
  deadCodeInjection: false,
  selfDefending: false,
  debugProtection: false,
  disableConsoleOutput: false,
  unicodeEscapeSequence: false,
  sourceMap: false,
  seed: 731902,
}).getObfuscatedCode();

if (!bundle || bundle.length < 100000) throw new Error('E37: generated bundle is unexpectedly small');

const nextName = `index-${createHash('sha256').update(bundle).digest('hex').slice(0, 12)}.js`;
const nextPath = path.join(assetsDir, nextName);
await writeFile(nextPath, bundle, 'utf8');
if (nextName !== originalName) await rm(originalPath, { force: true });

for (const name of ['index.html', '404.html']) {
  const htmlPath = path.join(dist, name);
  let html = await readFile(htmlPath, 'utf8');
  if (!html.includes(originalName)) throw new Error(`E38: ${name} does not reference ${originalName}`);
  html = html.split(originalName).join(nextName);
  await writeFile(htmlPath, html, 'utf8');
}
