/* Moracle Console — SPA vanilla, sem framework/bundler.
 * Roteamento client-side via history.pushState, servido pelo
 * fallback SPA de admin_api/static_files.py (spa_fallback=True). */

const CHAVE_LOCALSTORAGE = "moracle_console_token";
const raiz = document.getElementById("app");

/* ---------- Utilitários ---------- */

function escapeHtml(valor) {
  if (valor === null || valor === undefined) return "";
  return String(valor)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function obterToken() {
  return localStorage.getItem(CHAVE_LOCALSTORAGE) || "";
}
function salvarToken(token) {
  localStorage.setItem(CHAVE_LOCALSTORAGE, token);
}
function limparToken() {
  localStorage.removeItem(CHAVE_LOCALSTORAGE);
}

/* ---------- Toasts ---------- */

let containerToast = null;
function garantirContainerToast() {
  if (!containerToast) {
    containerToast = document.createElement("div");
    containerToast.className = "toast-container";
    document.body.appendChild(containerToast);
  }
  return containerToast;
}

function toast(mensagem, tipo) {
  const container = garantirContainerToast();
  const el = document.createElement("div");
  el.className = `toast ${tipo === "erro" ? "toast-erro" : "toast-sucesso"}`;
  el.textContent = mensagem;
  container.appendChild(el);
  setTimeout(() => el.remove(), 3500);
}
const toastSucesso = (msg) => toast(msg, "sucesso");
const toastErro = (msg) => toast(msg, "erro");

/* ---------- Modal genérico de confirmação ---------- */

function confirmarAcao({ titulo, mensagem, textoBotao = "Confirmar", perigo = false }) {
  return new Promise((resolve) => {
    const overlay = document.createElement("div");
    overlay.className = "overlay";
    overlay.innerHTML = `
      <div class="modal">
        <h2>${escapeHtml(titulo)}</h2>
        <div class="modal-sub">${escapeHtml(mensagem)}</div>
        <div class="modal-acoes">
          <button class="btn" id="conf-cancelar">Cancelar</button>
          <button class="btn ${perigo ? "btn-perigo" : "btn-primario"}" id="conf-ok">${escapeHtml(textoBotao)}</button>
        </div>
      </div>
    `;
    document.body.appendChild(overlay);

    const fechar = (resultado) => {
      overlay.remove();
      resolve(resultado);
    };
    overlay.addEventListener("click", (e) => { if (e.target === overlay) fechar(false); });
    document.getElementById("conf-cancelar").addEventListener("click", () => fechar(false));
    document.getElementById("conf-ok").addEventListener("click", () => fechar(true));
  });
}

/* ---------- Skeletons ---------- */

function skeletonCards(n = 3) {
  return `<div class="grid-cards">${Array(n).fill('<div class="skeleton skeleton-card"></div>').join("")}</div>`;
}
function skeletonLinhas(n = 4) {
  return Array(n).fill('<div class="skeleton-linha"></div>').join("");
}

/* ---------- Cliente HTTP ---------- */

async function api(metodo, path, corpo) {
  const resp = await fetch(path, {
    method: metodo,
    headers: {
      Authorization: `Bearer ${obterToken()}`,
      "Content-Type": "application/json",
    },
    body: corpo !== undefined ? JSON.stringify(corpo) : undefined,
  });

  if (resp.status === 401) {
    limparToken();
    navegar("/console/login");
    throw new Error("sessao expirada");
  }

  const dados = resp.status !== 204 ? await resp.json().catch(() => ({})) : {};
  return { status: resp.status, dados };
}

/* ---------- Roteador ---------- */

function navegar(path) {
  if (location.pathname !== path) {
    history.pushState({}, "", path);
  }
  renderizarRota();
}

document.addEventListener("click", (evento) => {
  const link = evento.target.closest("[data-link]");
  if (!link) return;
  evento.preventDefault();
  navegar(link.getAttribute("href"));
});

window.addEventListener("popstate", renderizarRota);

function rotaAtual() {
  const path = location.pathname.replace(/^\/console\/?/, "");
  const partes = path.split("/").filter(Boolean);
  return partes;
}

async function renderizarRota() {
  pararLiveAccessLogs(); // garante que nenhum polling orfao sobrevive a uma navegacao
  const token = obterToken();
  const partes = rotaAtual();

  if (partes[0] === "login") {
    return renderizarLogin();
  }
  if (!token) {
    return navegar("/console/login");
  }
  if (partes.length === 0) {
    return renderizarListaApps();
  }
  if (partes[0] === "apps" && partes[1]) {
    return renderizarDetalheApp(partes[1], partes[2] || "overview");
  }
  if (partes[0] === "keys") {
    return renderizarKeys();
  }
  if (partes[0] === "roles") {
    return renderizarRoles();
  }

  raiz.innerHTML = `<div class="vazio"><div class="titulo">Página não encontrada</div></div>`;
}

/* ---------- Layout comum ---------- */

function layout(paginaAtiva, conteudoHtml) {
  const itemNav = (path, rotulo, chave) => `
    <a href="${path}" data-link class="${paginaAtiva === chave ? "ativo" : ""}">${rotulo}</a>
  `;
  return `
    <div class="topbar">
      <div class="topbar-marca"><span class="ponto"></span> Moracle Console</div>
      <div class="topbar-nav">
        ${itemNav("/console", "Apps", "apps")}
        ${itemNav("/console/keys", "Keys", "keys")}
        ${itemNav("/console/roles", "Roles", "roles")}
        <button class="btn btn-pequeno" id="btn-sair" style="margin-left:12px;">Sair</button>
      </div>
    </div>
    <div class="container">${conteudoHtml}</div>
  `;
}

function anexarSair() {
  const btn = document.getElementById("btn-sair");
  if (btn) {
    btn.addEventListener("click", () => {
      limparToken();
      navegar("/console/login");
    });
  }
}

/* ---------- Login ---------- */

function renderizarLogin() {
  raiz.innerHTML = `
    <div class="tela-login">
      <div class="caixa-login">
        <div class="marca"><span class="ponto"></span> <strong>Moracle Console</strong></div>
        <h1>Entrar</h1>
        <div class="sub">Cole sua API Key para continuar</div>
        <div class="campo">
          <label>Authorization Bearer token</label>
          <input type="password" id="input-token" placeholder="mk_..." autofocus>
        </div>
        <button class="btn btn-primario btn-full" id="btn-entrar">Entrar</button>
        <div class="erro-msg" id="login-erro" style="display:none;"></div>
      </div>
    </div>
  `;

  document.getElementById("btn-entrar").addEventListener("click", tentarLogin);
  document.getElementById("input-token").addEventListener("keydown", (e) => {
    if (e.key === "Enter") tentarLogin();
  });
}

async function tentarLogin() {
  const input = document.getElementById("input-token");
  const btn = document.getElementById("btn-entrar");
  const erroEl = document.getElementById("login-erro");
  const token = input.value.trim();
  if (!token) return;

  erroEl.style.display = "none";
  btn.disabled = true;
  btn.innerHTML = `<span class="spinner"></span> Entrando…`;

  try {
    const resp = await fetch("/admin/apps", { headers: { Authorization: `Bearer ${token}` } });

    if (resp.status === 401) {
      erroEl.textContent = "Token inválido, revogado ou expirado.";
      erroEl.style.display = "block";
      btn.disabled = false;
      btn.textContent = "Entrar";
      return;
    }

    salvarToken(token);
    navegar("/console");
  } catch (e) {
    erroEl.textContent = "Não foi possível conectar ao servidor.";
    erroEl.style.display = "block";
    btn.disabled = false;
    btn.textContent = "Entrar";
  }
}

/* ---------- Apps: lista ---------- */

function tagEstado(estado) {
  const classe = "tag-" + String(estado || "outro").toLowerCase();
  return `<span class="tag ${classe}">${escapeHtml(estado || "-")}</span>`;
}

async function renderizarListaApps() {
  raiz.innerHTML = layout("apps", `
    <div class="cabecalho-pagina"><div><h1>Applications</h1></div></div>
    ${skeletonCards(3)}
  `);
  anexarSair();

  const { status, dados } = await api("GET", "/admin/apps");

  if (status === 403) {
    raiz.innerHTML = layout("apps", `<div class="vazio"><div class="titulo">Sem permissão</div>Sua chave não tem permissão para ver aplicações.</div>`);
    anexarSair();
    return;
  }

  const apps = dados.applications || [];

  const statusPorApp = {};
  for (const a of apps) {
    try {
      const r = await api("GET", `/admin/apps/${encodeURIComponent(a.name)}/status`);
      if (r.status === 200) statusPorApp[a.name] = r.dados.lifecycle_state;
    } catch (e) { /* ignora -- chave pode nao ter app.read para status, ou 401 ja redirecionou */ }
  }

  const cardCriar = `
    <button class="card card-criar" id="btn-criar-app">
      <span class="mais">+</span>
      <span>Nova aplicação</span>
    </button>
  `;

  const cardsApps = apps.map((a) => `
    <a href="/console/apps/${encodeURIComponent(a.name)}" data-link class="card">
      <div class="card-app-nome">${escapeHtml(a.name)}</div>
      <div class="card-app-dominio">${escapeHtml(a.domain || "sem domínio")}</div>
      ${tagEstado(statusPorApp[a.name])}
    </a>
  `).join("");

  raiz.innerHTML = layout("apps", `
    <div class="cabecalho-pagina">
      <div>
        <h1>Applications</h1>
        <div class="sub">${apps.length} aplicaç${apps.length === 1 ? "ão" : "ões"}</div>
      </div>
    </div>
    <div class="grid-cards">${cardCriar}${cardsApps}</div>
  `);
  anexarSair();

  document.getElementById("btn-criar-app").addEventListener("click", abrirModalCriarApp);
}

async function abrirModalCriarApp() {
  const overlay = document.createElement("div");
  overlay.className = "overlay";
  overlay.innerHTML = `
    <div class="modal">
      <h2>Nova aplicação</h2>
      <div class="modal-sub">Registra uma aplicação — o deploy é feito depois, na página da aplicação.</div>

      <div class="campo">
        <label>Nome *</label>
        <input type="text" id="ca-nome" placeholder="minha-api">
      </div>
      <div class="campo">
        <label>Working directory *</label>
        <input type="text" id="ca-workdir" placeholder="/data/data/com.termux/files/home/minha-api">
      </div>
      <div class="campo">
        <label>Start command *</label>
        <input type="text" id="ca-startcmd" placeholder="python3 app.py">
        <div class="campo-ajuda">Separado por espaços — será convertido em lista de argumentos.</div>
      </div>
      <div class="form-grid-2">
        <div class="campo">
          <label>Domínio</label>
          <input type="text" id="ca-dominio" placeholder="minha-api.local">
        </div>
        <div class="campo">
          <label>Porta</label>
          <input type="number" id="ca-porta" placeholder="8000">
        </div>
      </div>
      <div class="campo">
        <label>Health check path</label>
        <input type="text" id="ca-healthcheck" placeholder="/health" value="/health">
      </div>
      <div class="campo">
        <label>Environment (uma variável por linha, formato CHAVE=valor)</label>
        <textarea id="ca-env" placeholder="MINHA_VAR=valor"></textarea>
      </div>

      <div id="ca-resultado"></div>
      <div class="modal-acoes">
        <button class="btn" id="ca-cancelar">Cancelar</button>
        <button class="btn btn-primario" id="ca-criar">Criar aplicação</button>
      </div>
    </div>
  `;
  document.body.appendChild(overlay);

  document.getElementById("ca-cancelar").addEventListener("click", () => overlay.remove());
  overlay.addEventListener("click", (e) => { if (e.target === overlay) overlay.remove(); });

  document.getElementById("ca-criar").addEventListener("click", async () => {
    const nome = document.getElementById("ca-nome").value.trim();
    const workdir = document.getElementById("ca-workdir").value.trim();
    const startCmdTexto = document.getElementById("ca-startcmd").value.trim();
    const dominio = document.getElementById("ca-dominio").value.trim();
    const portaTexto = document.getElementById("ca-porta").value.trim();
    const healthcheck = document.getElementById("ca-healthcheck").value.trim() || "/health";
    const envTexto = document.getElementById("ca-env").value.trim();

    const resultadoEl = document.getElementById("ca-resultado");
    resultadoEl.innerHTML = "";

    if (!nome || !workdir || !startCmdTexto) {
      resultadoEl.innerHTML = `<div class="erro-msg">Nome, working directory e start command são obrigatórios.</div>`;
      return;
    }

    const environment = {};
    if (envTexto) {
      for (const linha of envTexto.split("\n")) {
        const [chave, ...resto] = linha.split("=");
        if (chave && resto.length) environment[chave.trim()] = resto.join("=").trim();
      }
    }

    const corpo = {
      name: nome,
      working_directory: workdir,
      start_command: startCmdTexto.split(/\s+/).filter(Boolean),
      health_check_path: healthcheck,
      environment,
    };
    if (dominio) corpo.domain = dominio;
    if (portaTexto) corpo.port = parseInt(portaTexto, 10);

    const btnCriar = document.getElementById("ca-criar");
    btnCriar.disabled = true;
    btnCriar.innerHTML = `<span class="spinner"></span> Criando…`;

    const { status, dados } = await api("POST", "/admin/apps", corpo);

    if (status !== 201) {
      resultadoEl.innerHTML = `<div class="erro-msg">${escapeHtml(dados.error || "Erro ao criar aplicação")}</div>`;
      btnCriar.disabled = false;
      btnCriar.textContent = "Criar aplicação";
      return;
    }

    overlay.remove();
    toastSucesso(`Aplicação "${nome}" criada.`);
    navegar(`/console/apps/${encodeURIComponent(nome)}`);
  });
}

/* ---------- App: detalhe com abas ---------- */

async function renderizarDetalheApp(nome, abaAtiva) {
  raiz.innerHTML = layout("apps", `
    <div class="breadcrumb"><a href="/console" data-link>Apps</a> / ${escapeHtml(nome)}</div>
    ${skeletonLinhas(3)}
  `);
  anexarSair();

  const { status, dados: app } = await api("GET", `/admin/apps/${encodeURIComponent(nome)}`);

  if (status === 404) {
    raiz.innerHTML = layout("apps", `<div class="vazio"><div class="titulo">Não encontrada</div>Aplicação não encontrada.</div>`);
    anexarSair();
    return;
  }
  if (status === 403) {
    raiz.innerHTML = layout("apps", `<div class="vazio"><div class="titulo">Sem permissão</div>Sem permissão para ver esta aplicação.</div>`);
    anexarSair();
    return;
  }

  const aba = (id, rotulo) => `<button class="${abaAtiva === id ? "ativa" : ""}" data-aba="${id}">${rotulo}</button>`;

  raiz.innerHTML = layout("apps", `
    <div class="breadcrumb"><a href="/console" data-link>Apps</a> / ${escapeHtml(nome)}</div>
    <div class="cabecalho-pagina">
      <div>
        <h1>${escapeHtml(nome)}</h1>
        <div class="sub">${escapeHtml(app.domain || "sem domínio")}</div>
      </div>
      <div style="display:flex; gap:8px; flex-wrap:wrap;">
        <button class="btn btn-primario" data-acao="deploy">Deploy</button>
        <button class="btn" data-acao="stop">Stop</button>
        <button class="btn btn-perigo" data-acao="delete">Delete</button>
      </div>
    </div>
    <div class="abas">
      ${aba("overview", "Overview")}
      ${aba("deployments", "Deployments")}
      ${aba("logs", "Logs")}
      ${aba("access-logs", "Access Logs")}
      ${aba("settings", "Settings")}
    </div>
    <div id="conteudo-aba">${skeletonLinhas(4)}</div>
  `);
  anexarSair();

  document.querySelectorAll("[data-aba]").forEach((btn) => {
    btn.addEventListener("click", () => navegar(`/console/apps/${encodeURIComponent(nome)}/${btn.dataset.aba}`));
  });

  document.querySelector('[data-acao="deploy"]').addEventListener("click", async (e) => {
    const ok = await confirmarAcao({
      titulo: "Confirmar deploy",
      mensagem: `Criar um novo deployment para "${nome}"? Isto irá reiniciar a aplicação.`,
      textoBotao: "Deploy",
    });
    if (!ok) return;
    const btn = e.target;
    btn.disabled = true;
    const { status } = await api("POST", `/admin/apps/${encodeURIComponent(nome)}/deploy`);
    btn.disabled = false;
    if (status === 200) {
      toastSucesso("Deploy concluído.");
    } else {
      toastErro("Falha ao fazer deploy.");
    }
    renderizarDetalheApp(nome, abaAtiva);
  });

  document.querySelector('[data-acao="stop"]').addEventListener("click", async () => {
    const ok = await confirmarAcao({
      titulo: "Parar aplicação",
      mensagem: `Parar o processo de "${nome}"?`,
      textoBotao: "Parar",
    });
    if (!ok) return;
    await api("POST", `/admin/apps/${encodeURIComponent(nome)}/stop`);
    toastSucesso("Aplicação parada.");
    renderizarDetalheApp(nome, abaAtiva);
  });

  document.querySelector('[data-acao="delete"]').addEventListener("click", async () => {
    const ok = await confirmarAcao({
      titulo: "Apagar aplicação",
      mensagem: `Apagar "${nome}" permanentemente? Esta ação não pode ser desfeita.`,
      textoBotao: "Apagar",
      perigo: true,
    });
    if (!ok) return;
    const { status, dados } = await api("DELETE", `/admin/apps/${encodeURIComponent(nome)}`);
    if (status === 204) {
      toastSucesso(`"${nome}" apagada.`);
      navegar("/console");
    } else {
      toastErro(dados.error || "Falha ao apagar — pare o processo primeiro.");
    }
  });

  renderizarConteudoAba(nome, abaAtiva, app);
}

async function renderizarConteudoAba(nome, aba, app) {
  const alvo = document.getElementById("conteudo-aba");
  if (!alvo) return;

  if (aba === "overview") {
    let statusTexto = "-";
    try {
      const r = await api("GET", `/admin/apps/${encodeURIComponent(nome)}/status`);
      if (r.status === 200) statusTexto = r.dados.lifecycle_state || "-";
    } catch (e) {}

    alvo.innerHTML = `
      <div class="linha-detalhe"><span class="rotulo">Status</span> <span class="valor">${tagEstado(statusTexto)}</span></div>
      <div class="linha-detalhe"><span class="rotulo">Working directory</span> <span class="valor mono">${escapeHtml(app.working_directory)}</span></div>
      <div class="linha-detalhe"><span class="rotulo">Start command</span> <span class="valor mono">${escapeHtml(JSON.stringify(app.start_command))}</span></div>
      <div class="linha-detalhe"><span class="rotulo">Port</span> <span class="valor">${escapeHtml(app.port || "-")}</span></div>
      <div class="linha-detalhe"><span class="rotulo">Deployment atual</span> <span class="valor mono">${escapeHtml(app.current_deployment_id || "-")}</span></div>
    `;
  }

  if (aba === "deployments") {
    const { status, dados } = await api("GET", `/admin/deployments?app=${encodeURIComponent(nome)}`);
    if (status !== 200) {
      alvo.innerHTML = `<div class="vazio">Sem permissão para ver deployments.</div>`;
      return;
    }
    const deployments = dados.deployments || [];
    alvo.innerHTML = deployments.length ? `
      <div class="tabela-scroll">
        <table>
          <thead><tr><th>ID</th><th>Status</th><th>Criado em</th><th></th></tr></thead>
          <tbody>
            ${deployments.map((d) => `
              <tr>
                <td class="mono">${escapeHtml(d.deployment_id)}</td>
                <td>${tagEstado(d.status)}</td>
                <td>${escapeHtml(new Date(d.created_at * 1000).toLocaleString())}</td>
                <td><button class="btn btn-pequeno" data-rollback="${escapeHtml(d.deployment_id)}">Rollback</button></td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      </div>
    ` : `<div class="vazio"><div class="titulo">Nenhum deployment</div>Use o botão "Deploy" acima para criar o primeiro.</div>`;

    alvo.querySelectorAll("[data-rollback]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const ok = await confirmarAcao({
          titulo: "Confirmar rollback",
          mensagem: `Reverter para o deployment ${btn.dataset.rollback}?`,
          textoBotao: "Rollback",
        });
        if (!ok) return;
        const { status } = await api("POST", `/admin/deployments/${btn.dataset.rollback}/rollback`);
        if (status === 200) {
          toastSucesso("Rollback concluído.");
        } else {
          toastErro("Falha no rollback.");
        }
        renderizarConteudoAba(nome, "deployments", app);
      });
    });
  }

  if (aba === "logs") {
    const { status, dados } = await api("GET", `/admin/apps/${encodeURIComponent(nome)}/logs?lines=200`);
    if (status !== 200) {
      alvo.innerHTML = `<div class="vazio">Sem permissão para ver logs.</div>`;
      return;
    }
    alvo.innerHTML = `
      <h3 style="font-size:13px; color:var(--texto-fraco);">stdout</h3>
      <pre class="log">${escapeHtml(dados.stdout || "(vazio)")}</pre>
      <h3 style="font-size:13px; color:var(--texto-fraco);">stderr</h3>
      <pre class="log">${escapeHtml(dados.stderr || "(vazio)")}</pre>
    `;
  }

  if (aba === "access-logs") {
    return montarAccessLogs(nome, alvo);
  }

  if (aba === "settings") {
    alvo.innerHTML = `
      <div class="aviso-readonly">Esta aba é somente leitura nesta versão do Console — edição de configurações ainda não está disponível.</div>
      <div class="linha-detalhe"><span class="rotulo">Health check path</span> <span class="valor mono">${escapeHtml(app.health_check_path)}</span></div>
      <div class="linha-detalhe"><span class="rotulo">Restart policy</span> <span class="valor">${escapeHtml(app.restart_policy_mode)}</span></div>
      <div class="linha-detalhe"><span class="rotulo">Environment</span> <span class="valor mono">${escapeHtml(JSON.stringify(app.environment || {}))}</span></div>
    `;
  }
}

/* ---------- Access Logs ---------- */

function _alConverterParaIso(valorDatetimeLocal) {
  if (!valorDatetimeLocal) return "";
  const d = new Date(valorDatetimeLocal);
  if (isNaN(d.getTime())) return "";
  return d.toISOString().slice(0, 19) + "Z";
}

function _alConstruirQuery(filtros, limit, cursor) {
  const params = new URLSearchParams();
  if (filtros.from) params.set("from", filtros.from);
  if (filtros.to) params.set("to", filtros.to);
  if (filtros.status) params.set("status", filtros.status);
  if (filtros.method) params.set("method", filtros.method);
  if (filtros.pathContains) params.set("path_contains", filtros.pathContains);
  params.set("limit", String(limit));
  if (cursor) params.set("cursor", cursor);
  return params.toString();
}

function tagStatusHttp(status) {
  let classe = "al-status-outro";
  if (status >= 200 && status < 300) classe = "al-status-ok";
  else if (status >= 400 && status < 500) classe = "al-status-clienterro";
  else if (status >= 500) classe = "al-status-servererro";
  return `<span class="tag ${classe}">${escapeHtml(status)}</span>`;
}

function _alLinhaTabela(r) {
  return `
    <tr>
      <td class="mono">${escapeHtml(new Date(r.timestamp).toLocaleString())}</td>
      <td>${tagStatusHttp(r.status)}</td>
      <td class="mono">${escapeHtml(r.method)}</td>
      <td class="al-celula-truncavel" data-al-expandir title="${escapeHtml(r.path)}">${escapeHtml(r.path)}</td>
      <td class="mono">${escapeHtml(r.latency_ms != null ? r.latency_ms.toFixed(1) + "ms" : "-")}</td>
    </tr>
  `;
}

function _alCard(r) {
  return `
    <div class="al-card">
      <div class="al-card-topo">
        <span class="mono">${escapeHtml(new Date(r.timestamp).toLocaleString())}</span>
        ${tagStatusHttp(r.status)}
      </div>
      <div class="al-card-linha mono">${escapeHtml(r.method)} <span class="al-celula-truncavel" data-al-expandir title="${escapeHtml(r.path)}">${escapeHtml(r.path)}</span></div>
      <div class="al-card-linha texto-fraco">${escapeHtml(r.remote_address)} · ${escapeHtml(r.latency_ms != null ? r.latency_ms.toFixed(1) + "ms" : "-")}</div>
    </div>
  `;
}

function _alBaixarArquivo(nomeArquivo, conteudo, tipoMime) {
  const blob = new Blob([conteudo], { type: tipoMime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = nomeArquivo;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

let _alIntervalo = null;

function pararLiveAccessLogs() {
  if (_alIntervalo) {
    clearInterval(_alIntervalo);
    _alIntervalo = null;
  }
}

async function montarAccessLogs(nomeApp, alvo) {
  pararLiveAccessLogs();

  const estado = {
    filtros: { from: "", to: "", status: "", method: "", pathContains: "" },
    registros: [],
    cursor: null,
    ultimaAtualizacao: null,
  };

  alvo.innerHTML = `
    <div class="al-filtros">
      <input type="text" id="al-path" placeholder="Buscar em path…" aria-label="Buscar em path">
      <input type="number" id="al-status" placeholder="Status" aria-label="Filtrar por status" style="width:90px;">
      <select id="al-method" aria-label="Filtrar por método">
        <option value="">Method</option>
        <option value="GET">GET</option>
        <option value="POST">POST</option>
        <option value="PUT">PUT</option>
        <option value="PATCH">PATCH</option>
        <option value="DELETE">DELETE</option>
        <option value="OPTIONS">OPTIONS</option>
      </select>
      <input type="datetime-local" id="al-from" aria-label="A partir de">
      <input type="datetime-local" id="al-to" aria-label="Até">
      <label class="al-live-toggle">
        <input type="checkbox" id="al-live" aria-label="Atualização automática">
        <span>Live</span>
      </label>
    </div>
    <div class="al-acoes">
      <span class="texto-fraco" id="al-last-update"></span>
      <div class="al-botoes-export">
        <button class="btn btn-pequeno" id="al-export-csv">Export CSV</button>
        <button class="btn btn-pequeno" id="al-export-md">Export MD</button>
        <button class="btn btn-pequeno" id="al-export-pdf">Export PDF</button>
      </div>
    </div>
    <div id="al-resultado">${skeletonLinhas(4)}</div>
    <div class="al-paginacao" id="al-paginacao"></div>
  `;

  const elResultado = document.getElementById("al-resultado");
  const elPaginacao = document.getElementById("al-paginacao");
  const elUltimaAtualizacao = document.getElementById("al-last-update");

  function lerFiltrosDoFormulario() {
    estado.filtros.pathContains = document.getElementById("al-path").value.trim();
    estado.filtros.status = document.getElementById("al-status").value.trim();
    estado.filtros.method = document.getElementById("al-method").value;
    estado.filtros.from = _alConverterParaIso(document.getElementById("al-from").value);
    estado.filtros.to = _alConverterParaIso(document.getElementById("al-to").value);
  }

  function renderizarRegistros() {
    if (estado.registros.length === 0) {
      elResultado.innerHTML = `<div class="vazio"><div class="titulo">Nenhum registro</div>Nenhuma requisição encontrada para os filtros atuais.</div>`;
      elPaginacao.innerHTML = "";
      return;
    }

    elResultado.innerHTML = `
      <div class="al-tabela-desktop">
        <table>
          <thead><tr><th>Time</th><th>Status</th><th>Method</th><th>Path</th><th>Latency</th></tr></thead>
          <tbody>${estado.registros.map(_alLinhaTabela).join("")}</tbody>
        </table>
      </div>
      <div class="al-cards-mobile">
        ${estado.registros.map(_alCard).join("")}
      </div>
    `;

    elResultado.querySelectorAll("[data-al-expandir]").forEach((el) => {
      el.addEventListener("click", () => el.classList.toggle("al-expandido"));
    });

    elPaginacao.innerHTML = estado.cursor
      ? `<button class="btn" id="al-carregar-mais">Carregar mais</button>`
      : `<span class="texto-fraco">Fim dos resultados.</span>`;

    const btnMais = document.getElementById("al-carregar-mais");
    if (btnMais) btnMais.addEventListener("click", () => buscar({ reiniciar: false }));
  }

  async function buscar({ reiniciar }) {
    if (reiniciar) {
      estado.registros = [];
      estado.cursor = null;
      elResultado.innerHTML = skeletonLinhas(4);
    }
    const qs = _alConstruirQuery(estado.filtros, 100, reiniciar ? null : estado.cursor);
    const { status, dados } = await api("GET", `/admin/apps/${encodeURIComponent(nomeApp)}/access-logs?${qs}`);

    if (status === 403) {
      elResultado.innerHTML = `<div class="vazio">Sem permissão para ver o access log.</div>`;
      elPaginacao.innerHTML = "";
      return;
    }
    if (status !== 200) {
      elResultado.innerHTML = `<div class="vazio">Não foi possível carregar o access log.</div>`;
      elPaginacao.innerHTML = "";
      return;
    }

    estado.registros = reiniciar ? dados.records : estado.registros.concat(dados.records);
    estado.cursor = dados.next_cursor;
    estado.ultimaAtualizacao = new Date();
    const rotuloLive = document.getElementById("al-live").checked ? "● Live — " : "";
    elUltimaAtualizacao.textContent = `${rotuloLive}última atualização: ${estado.ultimaAtualizacao.toLocaleTimeString()}`;
    renderizarRegistros();
  }

  async function exportarTudo(formato) {
    const TETO_SEGURANCA = 5000;
    let todos = [];
    let cursor = null;
    do {
      const qs = _alConstruirQuery(estado.filtros, 500, cursor);
      const { status, dados } = await api("GET", `/admin/apps/${encodeURIComponent(nomeApp)}/access-logs?${qs}`);
      if (status !== 200) { toastErro("Falha ao exportar."); return; }
      todos = todos.concat(dados.records);
      cursor = dados.next_cursor;
    } while (cursor && todos.length < TETO_SEGURANCA);

    if (todos.length === 0) {
      toastErro("Nada para exportar com os filtros atuais.");
      return;
    }

    if (formato === "csv") {
      const cabecalho = "timestamp,status,method,path,remote_address,latency_ms,request_id\n";
      const linhas = todos.map((r) => [
        r.timestamp, r.status, r.method,
        `"${String(r.path).replace(/"/g, '""')}"`,
        r.remote_address, r.latency_ms, r.request_id,
      ].join(","));
      _alBaixarArquivo(`access-log-${nomeApp}.csv`, cabecalho + linhas.join("\n"), "text/csv");
    } else if (formato === "md") {
      const linhas = ["| Time | Status | Method | Path | Latency |", "|---|---|---|---|---|"];
      todos.forEach((r) => linhas.push(`| ${r.timestamp} | ${r.status} | ${r.method} | ${r.path} | ${r.latency_ms}ms |`));
      _alBaixarArquivo(`access-log-${nomeApp}.md`, linhas.join("\n"), "text/markdown");
    }
    toastSucesso(`${todos.length} registros exportados.`);
  }

  function exportarPdf() {
    window.print();
  }

  document.getElementById("al-export-csv").addEventListener("click", () => exportarTudo("csv"));
  document.getElementById("al-export-md").addEventListener("click", () => exportarTudo("md"));
  document.getElementById("al-export-pdf").addEventListener("click", exportarPdf);

  ["al-path", "al-status", "al-method", "al-from", "al-to"].forEach((id) => {
    const el = document.getElementById(id);
    const eventoTipo = el.tagName === "SELECT" || el.type === "datetime-local" ? "change" : "input";
    let debounce = null;
    el.addEventListener(eventoTipo, () => {
      clearTimeout(debounce);
      debounce = setTimeout(() => {
        lerFiltrosDoFormulario();
        buscar({ reiniciar: true });
      }, eventoTipo === "input" ? 400 : 0);
    });
  });

  document.getElementById("al-live").addEventListener("change", (e) => {
    if (e.target.checked) {
      _alIntervalo = setInterval(() => buscar({ reiniciar: true }), 4000);
    } else {
      pararLiveAccessLogs();
      elUltimaAtualizacao.textContent = estado.ultimaAtualizacao
        ? `Última atualização: ${estado.ultimaAtualizacao.toLocaleTimeString()}`
        : "";
    }
  });

  await buscar({ reiniciar: true });
}

/* ---------- Keys ---------- */

async function renderizarKeys() {
  raiz.innerHTML = layout("keys", `<div class="cabecalho-pagina"><div><h1>API Keys</h1></div></div>${skeletonLinhas(3)}`);
  anexarSair();

  const { status, dados } = await api("GET", "/admin/keys");

  if (status === 403) {
    raiz.innerHTML = layout("keys", `<div class="vazio"><div class="titulo">Sem permissão</div>Sua chave não tem permissão para gerenciar API Keys (requer server.admin).</div>`);
    anexarSair();
    return;
  }

  const keys = dados.keys || [];

  raiz.innerHTML = layout("keys", `
    <div class="cabecalho-pagina">
      <div><h1>API Keys</h1><div class="sub">${keys.length} chave${keys.length === 1 ? "" : "s"}</div></div>
      <button class="btn btn-primario" id="btn-nova-key">Nova Key</button>
    </div>
    ${keys.length ? `
      <div class="tabela-scroll">
        <table>
          <thead><tr><th>Nome</th><th>Role</th><th>Escopo</th><th>Status</th><th>Último uso</th><th></th></tr></thead>
          <tbody>
            ${keys.map((k) => `
              <tr>
                <td>${escapeHtml(k.name)}</td>
                <td>${escapeHtml(k.role)}</td>
                <td>${k.scoped_app_names.length ? escapeHtml(k.scoped_app_names.join(", ")) : "todas"}</td>
                <td>${k.revoked ? '<span class="tag tag-failed">revoked</span>' : '<span class="tag tag-active">active</span>'}</td>
                <td>${escapeHtml(k.last_used_at || "nunca")}</td>
                <td>${k.revoked ? "" : `<button class="btn btn-pequeno btn-perigo" data-revoke="${escapeHtml(k.id)}" data-nome="${escapeHtml(k.name)}">Revoke</button>`}</td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      </div>
    ` : `<div class="vazio"><div class="titulo">Nenhuma chave ainda</div><button class="btn btn-primario" id="btn-nova-key-vazio">Criar primeira chave</button></div>`}
  `);
  anexarSair();

  const anexarBtnNova = (id) => {
    const el = document.getElementById(id);
    if (el) el.addEventListener("click", abrirModalNovaKey);
  };
  anexarBtnNova("btn-nova-key");
  anexarBtnNova("btn-nova-key-vazio");

  document.querySelectorAll("[data-revoke]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const ok = await confirmarAcao({
        titulo: "Revogar chave",
        mensagem: `Revogar "${btn.dataset.nome}"? Esta ação não pode ser desfeita.`,
        textoBotao: "Revogar",
        perigo: true,
      });
      if (!ok) return;
      const { status, dados } = await api("DELETE", `/admin/keys/${btn.dataset.revoke}`);
      if (status === 409) {
        toastErro(dados.error || "Não é possível revogar a última chave server.admin.");
        return;
      }
      toastSucesso("Chave revogada.");
      renderizarKeys();
    });
  });
}

async function abrirModalNovaKey() {
  const { dados: rolesDados } = await api("GET", "/admin/roles");
  const roles = rolesDados.roles || [];

  const overlay = document.createElement("div");
  overlay.className = "overlay";
  overlay.innerHTML = `
    <div class="modal">
      <h2>Nova API Key</h2>
      <div class="campo">
        <label>Nome</label>
        <input type="text" id="nk-nome" placeholder="deploy-producao">
      </div>
      <div class="campo">
        <label>Role</label>
        <select id="nk-role">
          ${roles.map((r) => `<option value="${escapeHtml(r.name)}">${escapeHtml(r.name)}</option>`).join("")}
        </select>
      </div>
      <div class="campo">
        <label>Scoped app names (separado por vírgula, vazio = todas)</label>
        <input type="text" id="nk-scope" placeholder="app-a, app-b">
      </div>
      <div id="nk-resultado"></div>
      <div class="modal-acoes">
        <button class="btn" id="nk-cancelar">Cancelar</button>
        <button class="btn btn-primario" id="nk-criar">Criar</button>
      </div>
    </div>
  `;
  document.body.appendChild(overlay);

  document.getElementById("nk-cancelar").addEventListener("click", () => { overlay.remove(); renderizarKeys(); });
  overlay.addEventListener("click", (e) => { if (e.target === overlay) { overlay.remove(); renderizarKeys(); } });

  document.getElementById("nk-criar").addEventListener("click", async () => {
    const nome = document.getElementById("nk-nome").value.trim();
    const role = document.getElementById("nk-role").value;
    const scopeTexto = document.getElementById("nk-scope").value.trim();
    const scoped_app_names = scopeTexto ? scopeTexto.split(",").map((s) => s.trim()).filter(Boolean) : [];
    if (!nome) return;

    const { status, dados } = await api("POST", "/admin/keys", { name: nome, role, scoped_app_names });

    if (status !== 201) {
      document.getElementById("nk-resultado").innerHTML = `<div class="erro-msg">${escapeHtml(dados.error || "Erro ao criar chave")}</div>`;
      return;
    }

    document.querySelector(".modal").innerHTML = `
      <h2>Chave criada</h2>
      <div class="campo-ajuda">Copie o segredo agora — ele não será mostrado novamente.</div>
      <div class="secret-box">${escapeHtml(dados.secret)}</div>
      <div class="modal-acoes">
        <button class="btn btn-primario" id="nk-fechar">Fechar</button>
      </div>
    `;
    document.getElementById("nk-fechar").addEventListener("click", () => { overlay.remove(); renderizarKeys(); });
  });
}

/* ---------- Roles ---------- */

async function renderizarRoles() {
  raiz.innerHTML = layout("roles", `<div class="cabecalho-pagina"><div><h1>Roles</h1></div></div>${skeletonLinhas(3)}`);
  anexarSair();

  const { status, dados } = await api("GET", "/admin/roles");

  if (status === 403) {
    raiz.innerHTML = layout("roles", `<div class="vazio"><div class="titulo">Sem permissão</div>Sua chave não tem permissão para gerenciar Roles (requer server.admin).</div>`);
    anexarSair();
    return;
  }

  const roles = dados.roles || [];

  raiz.innerHTML = layout("roles", `
    <div class="cabecalho-pagina">
      <div><h1>Roles</h1><div class="sub">${roles.length} role${roles.length === 1 ? "" : "s"}</div></div>
      <button class="btn btn-primario" id="btn-nova-role">Nova Role</button>
    </div>
    <div class="tabela-scroll">
      <table>
        <thead><tr><th>Nome</th><th>Descrição</th><th>Permissions</th></tr></thead>
        <tbody>
          ${roles.map((r) => `
            <tr>
              <td>${escapeHtml(r.name)}</td>
              <td>${escapeHtml(r.description || "-")}</td>
              <td class="mono">${escapeHtml(r.permissions.join(", "))}</td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    </div>
  `);
  anexarSair();

  document.getElementById("btn-nova-role").addEventListener("click", () => abrirModalNovaRole());
}

function abrirModalNovaRole() {
  const overlay = document.createElement("div");
  overlay.className = "overlay";
  overlay.innerHTML = `
    <div class="modal">
      <h2>Nova Role</h2>
      <div class="campo">
        <label>Nome</label>
        <input type="text" id="nr-nome" placeholder="monitoring">
      </div>
      <div class="campo">
        <label>Descrição</label>
        <input type="text" id="nr-desc" placeholder="Read-only monitoring">
      </div>
      <div class="campo">
        <label>Permissions (separado por vírgula)</label>
        <textarea id="nr-permissions" placeholder="app.read, app.logs, deployment.read"></textarea>
      </div>
      <div id="nr-resultado"></div>
      <div class="modal-acoes">
        <button class="btn" id="nr-cancelar">Cancelar</button>
        <button class="btn btn-primario" id="nr-criar">Criar</button>
      </div>
    </div>
  `;
  document.body.appendChild(overlay);

  document.getElementById("nr-cancelar").addEventListener("click", () => { overlay.remove(); renderizarRoles(); });
  overlay.addEventListener("click", (e) => { if (e.target === overlay) { overlay.remove(); renderizarRoles(); } });

  document.getElementById("nr-criar").addEventListener("click", async () => {
    const nome = document.getElementById("nr-nome").value.trim();
    const description = document.getElementById("nr-desc").value.trim();
    const permTexto = document.getElementById("nr-permissions").value.trim();
    const permissions = permTexto.split(",").map((s) => s.trim()).filter(Boolean);
    if (!nome || !permissions.length) return;

    const { status, dados } = await api("POST", "/admin/roles", { name: nome, description, permissions });

    if (status !== 201) {
      document.getElementById("nr-resultado").innerHTML = `<div class="erro-msg">${escapeHtml(dados.error || "Erro ao criar role")}</div>`;
      return;
    }

    overlay.remove();
    toastSucesso(`Role "${nome}" criada.`);
    renderizarRoles();
  });
}

/* ---------- Início ---------- */

renderizarRota();
