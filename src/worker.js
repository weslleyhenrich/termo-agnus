// Cloudflare Pages — MODO AVANÇADO (_worker.js)
//
// Este único arquivo substitui a pasta functions/ e FUNCIONA com o deploy
// por arrastar e soltar (Direct Upload) no painel do Cloudflare.
//
// - Requisições para /api/enviar  -> cria o documento no Autentique.
// - Qualquer outra rota           -> serve os arquivos estáticos (index.html).
//
// O TOKEN nunca fica no site: é lido da variável secreta AUTENTIQUE_TOKEN,
// configurada no painel do Cloudflare Pages.

const AUTENTIQUE_URL = "https://api.autentique.com.br/v2/graphql";

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" },
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/enviar") {
      if (request.method === "POST") return enviarAutentique(request, env);
      if (request.method === "GET")
        return json({ ok: true, info: "Endpoint de envio ativo. Use POST para enviar um documento." });
      return new Response("Método não permitido", { status: 405 });
    }

    // Demais rotas: entrega os arquivos estáticos (index.html etc.)
    return env.ASSETS.fetch(request);
  },
};

async function enviarAutentique(request, env) {
  const token = env.AUTENTIQUE_TOKEN;
  if (!token) {
    return json({ ok: false, error: "Token do Autentique não configurado no servidor (variável AUTENTIQUE_TOKEN)." }, 500);
  }

  let body;
  try { body = await request.json(); }
  catch { return json({ ok: false, error: "Requisição inválida." }, 400); }

  const { docName, signerName, signerEmail, pdfBase64, sandbox } = body || {};

  const emailOk = typeof signerEmail === "string" && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(signerEmail);
  if (!emailOk) return json({ ok: false, error: "E-mail do signatário inválido." }, 400);
  if (!pdfBase64 || typeof pdfBase64 !== "string") return json({ ok: false, error: "PDF ausente na requisição." }, 400);

  let bytes;
  try {
    const bin = atob(pdfBase64);
    bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  } catch {
    return json({ ok: false, error: "PDF corrompido (base64 inválido)." }, 400);
  }

  const query =
    "mutation CreateDocumentMutation($document: DocumentInput!, $signers: [SignerInput!]!, $file: Upload!) {" +
    "  createDocument(" + (sandbox ? "sandbox: true, " : "") + "document: $document, signers: $signers, file: $file) {" +
    "    id name" +
    "    signatures { public_id email action { name } link { short_link } }" +
    "  }" +
    "}";

  const signer = { email: signerEmail, action: "SIGN" };
  if (signerName) signer.name = signerName;

  const variables = {
    document: { name: docName || "Termo LGPD" },
    signers: [signer, { email: "talita@aglb.com.br", name: "Talita", action: "SIGN" }],
    file: null,
  };

  const form = new FormData();
  form.append("operations", JSON.stringify({ query, variables }));
  form.append("map", JSON.stringify({ file: ["variables.file"] }));
  form.append("file", new Blob([bytes], { type: "application/pdf" }), "termo-lgpd.pdf");

  let data;
  try {
    const apiResp = await fetch(AUTENTIQUE_URL, {
      method: "POST",
      headers: { Authorization: "Bearer " + token }, // sem Content-Type: boundary automático
      body: form,
    });
    data = await apiResp.json();
  } catch (e) {
    return json({ ok: false, error: "Erro ao contatar o Autentique: " + (e && e.message ? e.message : String(e)) }, 502);
  }

  if (data && Array.isArray(data.errors) && data.errors.length) {
    return json({ ok: false, error: data.errors.map(e => e.message).join(" | ") }, 400);
  }

  const created = data && data.data && data.data.createDocument;
  if (!created) return json({ ok: false, error: "Resposta inesperada do Autentique." }, 502);

  const sigs = created.signatures || [];
  const sig = sigs.find(s => s.email === signerEmail) || sigs[0];
  const link = sig && sig.link ? sig.link.short_link : null;

  return json({ ok: true, id: created.id, name: created.name, link });
}
