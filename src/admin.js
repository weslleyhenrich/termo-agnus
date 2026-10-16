// Área administrativa: lista os termos LGPD enviados ao Autentique, mostra quem já
// assinou, gera link de assinatura e baixa o PDF.
//
// Acesso protegido por senha (segredo ADMIN_SENHA no Cloudflare). Depois do login,
// o navegador recebe um cookie HttpOnly assinado (HMAC) válido por 12 horas.
// Nada fica guardado no site: a lista vem sempre direto do Autentique.

const AUTENTIQUE_URL = "https://api.autentique.com.br/v2/graphql";
const COOKIE = "agnus_adm";
const SESSAO_SEGUNDOS = 12 * 60 * 60;
const SIGNATARIO_CORRETORA = "talita@aglb.com.br";
const POR_PAGINA = 60;
const PDF_MAX_BYTES = 10 * 1024 * 1024;

function json(obj, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...extraHeaders,
    },
  });
}

// ------------------------------------------------------------------ sessão

const enc = new TextEncoder();

async function hmac(segredo, texto) {
  const chave = await crypto.subtle.importKey(
    "raw", enc.encode(segredo), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const assinatura = await crypto.subtle.sign("HMAC", chave, enc.encode(texto));
  return [...new Uint8Array(assinatura)].map(b => b.toString(16).padStart(2, "0")).join("");
}

function iguais(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let dif = 0;
  for (let i = 0; i < a.length; i++) dif |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return dif === 0;
}

function lerCookie(request, nome) {
  const cab = request.headers.get("Cookie") || "";
  for (const parte of cab.split(";")) {
    const [k, ...v] = parte.trim().split("=");
    if (k === nome) return v.join("=");
  }
  return null;
}

async function sessaoValida(request, env) {
  const senha = env.ADMIN_SENHA;
  const valor = lerCookie(request, COOKIE);
  if (!senha || !valor) return false;
  const [exp, assinatura] = valor.split(".");
  if (!/^\d+$/.test(exp || "") || Number(exp) < Date.now() / 1000) return false;
  return iguais(assinatura, await hmac(senha, "adm:" + exp));
}

async function login(request, env) {
  const senha = env.ADMIN_SENHA;
  if (!senha) {
    return json({ ok: false, error: "Senha de administração não configurada (segredo ADMIN_SENHA no Cloudflare)." }, 500);
  }
  let body;
  try { body = await request.json(); } catch { body = {}; }
  const digitada = typeof body.senha === "string" ? body.senha : "";

  // Compara pelo hash para não depender do tamanho da senha.
  const ok = iguais(await hmac("cmp", digitada), await hmac("cmp", senha));
  if (!ok) {
    await new Promise(r => setTimeout(r, 800)); // freia tentativas em sequência
    return json({ ok: false, error: "Senha incorreta." }, 401);
  }
  const exp = Math.floor(Date.now() / 1000) + SESSAO_SEGUNDOS;
  const valor = exp + "." + (await hmac(senha, "adm:" + exp));
  return json({ ok: true }, 200, {
    "Set-Cookie": `${COOKIE}=${valor}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSAO_SEGUNDOS}`,
  });
}

function logout() {
  return json({ ok: true }, 200, {
    "Set-Cookie": `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`,
  });
}

// ------------------------------------------------------------------ Autentique

async function autentique(token, query) {
  const resp = await fetch(AUTENTIQUE_URL, {
    method: "POST",
    headers: { Authorization: "Bearer " + token, "Content-Type": "application/json" },
    body: JSON.stringify({ query, variables: {} }),
  });
  const corpo = await resp.json().catch(() => ({}));
  if (!resp.ok || (corpo.errors && corpo.errors.length) || !corpo.data) {
    const msg = (corpo.errors || []).map(e => e.message).filter(Boolean).join(" | ");
    throw new Error(msg || "Autentique HTTP " + resp.status);
  }
  return corpo.data;
}

function idSeguro(id) {
  if (typeof id !== "string" || !/^[A-Za-z0-9_-]{1,100}$/.test(id)) throw new Error("ID inválido.");
  return id;
}

function situacao(a) {
  if (!a) return { status: "sem_signatario" };
  const s = a.signed && a.signed.created_at;
  const r = a.rejected && a.rejected.created_at;
  const v = a.viewed && a.viewed.created_at;
  return {
    nome: a.name || (a.user && a.user.name) || "",
    email: (a.email || (a.user && a.user.email) || "").toLowerCase(),
    public_id: a.public_id,
    status: s ? "assinado" : r ? "recusado" : v ? "visualizado" : "pendente",
    em: s || r || v || null,
    link: (a.link && a.link.short_link) || null,
  };
}

/** Separa o titular (quem recebeu o termo) da assinatura da corretora. */
function resumir(doc) {
  const assinaturas = doc.signatures || [];
  const emailDe = a => (a.email || (a.user && a.user.email) || "").toLowerCase();
  const corretora = assinaturas.find(a => emailDe(a) === SIGNATARIO_CORRETORA);
  // A conta dona do documento também aparece na lista, sem ação de assinatura.
  const candidatos = assinaturas.filter(a => a !== corretora);
  const titular =
    candidatos.find(a => a.action && a.action.name && a.link && a.link.short_link) ||
    candidatos.find(a => a.action && a.action.name) ||
    candidatos[candidatos.length - 1];

  const t = situacao(titular);
  const c = corretora ? situacao(corretora) : null;
  const concluido = t.status === "assinado" && (!c || c.status === "assinado");
  return {
    id: doc.id,
    nome: doc.name,
    criadoEm: doc.created_at,
    titular: t,
    corretora: c,
    concluido,
    temAssinado: !!(doc.files && doc.files.signed),
  };
}

async function listar(request, env) {
  const token = env.AUTENTIQUE_TOKEN;
  if (!token) return json({ ok: false, error: "Falta o segredo AUTENTIQUE_TOKEN." }, 500);
  const url = new URL(request.url);
  const pagina = Math.max(1, Math.min(500, parseInt(url.searchParams.get("pagina") || "1", 10) || 1));
  const todos = url.searchParams.get("todos") === "1";

  try {
    const dados = await autentique(token, `query {
      documents(limit: ${POR_PAGINA}, page: ${pagina}) {
        total
        data {
          id name created_at
          files { signed }
          signatures {
            public_id name email
            user { name email }
            action { name }
            link { short_link }
            viewed { created_at } signed { created_at } rejected { created_at }
          }
        }
      }
    }`);
    const bloco = dados.documents || { total: 0, data: [] };
    const docs = (bloco.data || [])
      .filter(d => todos || /lgpd/i.test(d.name || ""))
      .map(resumir);
    return json({
      ok: true,
      pagina,
      total: bloco.total || 0,
      temMais: pagina * POR_PAGINA < (bloco.total || 0),
      documentos: docs,
    });
  } catch (e) {
    return json({ ok: false, error: "Não foi possível consultar o Autentique: " + e.message }, 502);
  }
}

async function gerarLink(request, env) {
  const token = env.AUTENTIQUE_TOKEN;
  if (!token) return json({ ok: false, error: "Falta o segredo AUTENTIQUE_TOKEN." }, 500);
  let body;
  try { body = await request.json(); } catch { body = {}; }
  try {
    const dados = await autentique(
      token,
      `mutation { createLinkToSignature(public_id: "${idSeguro(body.public_id)}") { short_link } }`
    );
    const link = dados.createLinkToSignature && dados.createLinkToSignature.short_link;
    if (!link) return json({ ok: false, error: "O Autentique não devolveu o link." }, 502);
    return json({ ok: true, link });
  } catch (e) {
    return json({ ok: false, error: "Não foi possível gerar o link: " + e.message }, 502);
  }
}

function nomeArquivo(nome, assinado) {
  const base = (nome || "Termo_LGPD")
    .normalize("NFD").replace(/[̀-ͯ]/g, "")
    .replace(/[^a-zA-Z0-9]+/g, "_").replace(/^_+|_+$/g, "") || "Termo_LGPD";
  return base + (assinado ? "_assinado" : "") + ".pdf";
}

async function baixar(request, env) {
  const token = env.AUTENTIQUE_TOKEN;
  if (!token) return json({ ok: false, error: "Falta o segredo AUTENTIQUE_TOKEN." }, 500);
  const url = new URL(request.url);
  try {
    const dados = await autentique(
      token,
      `query { document(id: "${idSeguro(url.searchParams.get("id"))}") { name files { original signed } } }`
    );
    const doc = dados.document;
    const arquivoUrl = doc && doc.files && (doc.files.signed || doc.files.original);
    if (!arquivoUrl || !/^https:\/\//i.test(arquivoUrl)) {
      return json({ ok: false, error: "O Autentique não devolveu o arquivo." }, 502);
    }
    // O token só vai para o próprio Autentique.
    const host = new URL(arquivoUrl).hostname.toLowerCase();
    const doAutentique = host === "autentique.com.br" || host.endsWith(".autentique.com.br");
    const resp = await fetch(arquivoUrl, doAutentique ? { headers: { Authorization: "Bearer " + token } } : undefined);
    if (!resp.ok) return json({ ok: false, error: "Falha ao baixar o PDF no Autentique." }, 502);
    const bytes = new Uint8Array(await resp.arrayBuffer());
    if (bytes.length > PDF_MAX_BYTES || bytes[0] !== 0x25 || bytes[1] !== 0x50) {
      return json({ ok: false, error: "O arquivo recebido não é um PDF válido." }, 502);
    }
    return new Response(bytes, {
      headers: {
        "Content-Type": "application/pdf",
        "Content-Disposition": `attachment; filename="${nomeArquivo(doc.name, !!doc.files.signed)}"`,
        "Cache-Control": "no-store",
      },
    });
  } catch (e) {
    return json({ ok: false, error: "Não foi possível baixar: " + e.message }, 502);
  }
}

// ------------------------------------------------------------------ rotas

/** Trata /api/admin/*. Devolve null se a rota não for da administração. */
export async function rotaAdmin(request, env, url) {
  const p = url.pathname;
  if (!p.startsWith("/api/admin/")) return null;

  if (p === "/api/admin/login" && request.method === "POST") return login(request, env);
  if (p === "/api/admin/logout" && request.method === "POST") return logout();

  if (!(await sessaoValida(request, env))) {
    return json({ ok: false, error: "Sessão expirada. Entre com a senha novamente." }, 401);
  }
  if (p === "/api/admin/sessao" && request.method === "GET") return json({ ok: true });
  if (p === "/api/admin/documentos" && request.method === "GET") return listar(request, env);
  if (p === "/api/admin/link" && request.method === "POST") return gerarLink(request, env);
  if (p === "/api/admin/baixar" && request.method === "GET") return baixar(request, env);
  return json({ ok: false, error: "Rota não encontrada." }, 404);
}
