/* ==========================================================================
   Sitecrack Modern Glass UI Controller (app.js)
   Incluye Banners Glass, Anillo SVG Animado, Salud Global, Auditor Web Real,
   Generador de Código de Solución, Repetidor en Vivo y Notificaciones Toast.
   ========================================================================== */

const state = {
  flows: [],
  selectedFlowId: null,
  activeTab: "security",
  activeStack: "fastapi",
  remediationCache: {},
  hostFilter: "",
  methodFilter: "",
  gradeFilter: "",
  lastComparison: null,
};

const PROTECTIONS_GUIDE = [
  {
    header: "Strict-Transport-Security",
    title: "Cifrado obligatorio (HSTS)",
    desc: "Obliga a que la conexión viaje siempre cifrada para que nadie pueda espiar tus datos en redes Wi-Fi.",
  },
  {
    header: "Content-Security-Policy",
    title: "Escudo contra código malicioso (CSP)",
    desc: "Bloquea la ejecución de scripts intrusos inyectados por atacantes en la página.",
  },
  {
    header: "X-Frame-Options",
    title: "Bloqueo de trampas visuales",
    desc: "Evita que otra página falsa incruste esta web en un marco invisible para engañar tus clics.",
  },
  {
    header: "X-Content-Type-Options",
    title: "Verificación de archivos",
    desc: "Impide que el navegador ejecute archivos de texto o imágenes como si fueran programas.",
  },
  {
    header: "Referrer-Policy",
    title: "Privacidad de navegación",
    desc: "Evita filtrar la dirección privada que estabas visitando cuando haces clic en un enlace externo.",
  },
  {
    header: "Permissions-Policy",
    title: "Control de cámara y micrófono",
    desc: "Restringe el acceso a sensores del dispositivo como geolocalización, cámara o micrófono.",
  },
];

const QUICK_SHIELD_VALUES = {
  "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
  "Content-Security-Policy": "default-src 'self'",
  "X-Frame-Options": "DENY",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Permissions-Policy": "geolocation=(), microphone=()",
};

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function showToast(message, tone = "safe") {
  const container = document.getElementById("toast-container");
  if (!container) return;
  const toast = document.createElement("div");
  const toneClass =
    tone === "danger"
      ? "toast-danger"
      : tone === "warn"
      ? "toast-warn"
      : "toast-safe";
  const icon = tone === "danger" ? "🚨" : tone === "warn" ? "⚠" : "✔";
  toast.className = `glass-toast ${toneClass}`;
  toast.innerHTML = `<span>${icon}</span><span>${escapeHtml(message)}</span>`;
  container.appendChild(toast);
  setTimeout(() => {
    toast.remove();
  }, 3600);
}

function getToneByGrade(grade) {
  if (grade === "A" || grade === "B") return "safe";
  if (grade === "C" || grade === "D") return "warn";
  return "danger";
}

function getToneByStatus(statusCode) {
  if (statusCode >= 200 && statusCode < 400) return "safe";
  if (statusCode >= 400 && statusCode < 500) return "warn";
  return "danger";
}

function getPlainVerdict(flow) {
  const grade = flow.security_audit.grade;
  const missingCount = flow.security_audit.missing_headers.length;
  if (flow.scheme !== "https") {
    return "🚨 Peligro: Conexión sin cifrar (HTTP). Los datos viajan en texto abierto.";
  }
  if (grade === "A") {
    return "✔ Conexión blindada: cuenta con cifrado HTTPS y escudos activos.";
  }
  if (grade === "B" || grade === "C") {
    return `⚠ Aviso de seguridad: conexión cifrada, pero faltan ${missingCount} escudos recomendados.`;
  }
  return `🚨 Riesgo alto: esta respuesta tiene ${missingCount} carencias críticas de protección.`;
}

function buildScoreRingSvg(grade, score, tone) {
  const radius = 28;
  const circumference = 2 * Math.PI * radius;
  const clamped = Math.max(0, Math.min(100, Number(score) || 0));
  const offset = circumference - (clamped / 100) * circumference;

  return `
    <div class="score-ring-wrap" aria-label="Puntuación ${clamped} sobre 100, Nota ${escapeHtml(grade)}">
      <svg class="score-ring-svg" viewBox="0 0 72 72">
        <circle class="score-ring-bg" cx="36" cy="36" r="${radius}"></circle>
        <circle
          class="score-ring-fill ${tone}"
          cx="36"
          cy="36"
          r="${radius}"
          stroke-dasharray="${circumference.toFixed(1)}"
          stroke-dashoffset="${offset.toFixed(1)}"
        ></circle>
      </svg>
      <div class="score-ring-center">
        <span class="score-ring-grade">${escapeHtml(grade)}</span>
        <span class="score-ring-pts">${clamped}/100</span>
      </div>
    </div>
  `;
}

function updateGlobalHealthBar() {
  const total = state.flows.length;
  const safeSeg = document.getElementById("health-seg-safe");
  const warnSeg = document.getElementById("health-seg-warn");
  const dangerSeg = document.getElementById("health-seg-danger");
  const pctText = document.getElementById("health-pct-text");
  if (!safeSeg || !warnSeg || !dangerSeg || !pctText) return;

  if (total === 0) {
    safeSeg.style.width = "100%";
    warnSeg.style.width = "0%";
    dangerSeg.style.width = "0%";
    pctText.textContent = "100%";
    return;
  }

  let safeCount = 0;
  let warnCount = 0;
  let dangerCount = 0;
  state.flows.forEach((f) => {
    const tone = getToneByGrade(f.security_audit.grade);
    if (tone === "safe") safeCount += 1;
    else if (tone === "warn") warnCount += 1;
    else dangerCount += 1;
  });

  const safePct = Math.round((safeCount / total) * 100);
  const warnPct = Math.round((warnCount / total) * 100);
  const dangerPct = Math.max(0, 100 - safePct - warnPct);

  safeSeg.style.width = `${safePct}%`;
  warnSeg.style.width = `${warnPct}%`;
  dangerSeg.style.width = `${dangerPct}%`;
  pctText.textContent = `${safePct}% seguras`;
}

function getFilteredFlows() {
  if (!state.gradeFilter) return state.flows;
  return state.flows.filter((f) => {
    const g = f.security_audit.grade;
    if (state.gradeFilter === "safe") return g === "A" || g === "B";
    if (state.gradeFilter === "risk") return g === "C" || g === "D" || g === "F";
    return true;
  });
}

async function fetchTelemetry() {
  const params = new URLSearchParams({ limit: "100" });
  if (state.hostFilter) params.set("host", state.hostFilter);
  if (state.methodFilter) params.set("method", state.methodFilter);

  const [flowsResp, statsResp] = await Promise.all([
    fetch(`/api/v1/flows?${params.toString()}`),
    fetch("/api/v1/stats"),
  ]);

  state.flows = await flowsResp.json();
  const stats = await statsResp.json();

  document.getElementById("stat-total").textContent = stats.total_flows;
  document.getElementById("stat-https").textContent = stats.https_count;
  document.getElementById("stat-low-sec").textContent = stats.low_security_count;
  document.getElementById("stat-latency").textContent = `${stats.avg_duration_ms} ms`;

  updateGlobalHealthBar();
  renderFlowList();

  const visibleFlows = getFilteredFlows();
  if (visibleFlows.length > 0) {
    const exists = visibleFlows.some((f) => f.id === state.selectedFlowId);
    if (!exists) {
      state.selectedFlowId = visibleFlows[0].id;
    }
    renderInspector();
  } else {
    state.selectedFlowId = null;
    renderEmptyInspector();
  }
}

function renderFlowList() {
  const container = document.getElementById("flow-list");
  const visibleFlows = getFilteredFlows();

  if (visibleFlows.length === 0) {
    container.innerHTML = `
      <div class="empty-placeholder">
        <p style="font-weight:700; color:var(--text-main); margin-bottom:0.35rem;">Sin peticiones para este filtro</p>
        <p style="font-size:0.84rem;">Pulsa <strong>"🌐 Auditar Web Real"</strong> o <strong>"Cargar ejemplos"</strong>.</p>
      </div>
    `;
    return;
  }

  container.innerHTML = visibleFlows
    .map((flow) => {
      const selectedCls = flow.id === state.selectedFlowId ? "selected" : "";
      const gradeTone = getToneByGrade(flow.security_audit.grade);
      const lockIcon = flow.scheme === "https" ? "🔒" : "🔓";
      const pillIcon =
        gradeTone === "safe" ? "✔" : gradeTone === "warn" ? "⚠" : "🚨";
      return `
        <div class="flow-item tone-${gradeTone} ${selectedCls}" data-flow-id="${flow.id}" role="listitem" tabindex="0">
          <div class="flow-item-left">
            <div class="flow-top-line">
              <span class="method-tag">${escapeHtml(flow.method)}</span>
              <span class="host-text">${lockIcon} ${escapeHtml(flow.host)}</span>
            </div>
            <div class="path-text">${escapeHtml(flow.path)}</div>
          </div>

          <div class="flow-item-right">
            <span class="pill pill-${gradeTone}">
              ${pillIcon} Nota ${escapeHtml(flow.security_audit.grade)} · ${flow.security_audit.score}
            </span>
            <span class="latency-label">HTTP ${flow.status_code} · ${flow.duration_ms.toFixed(0)} ms</span>
          </div>
        </div>
      `;
    })
    .join("");

  container.querySelectorAll(".flow-item").forEach((el) => {
    const selectThis = () => {
      state.selectedFlowId = Number(el.dataset.flowId);
      renderFlowList();
      renderInspector();
    };
    el.addEventListener("click", selectThis);
    el.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        selectThis();
      }
    });
  });
}

function renderEmptyInspector() {
  document.getElementById("inspector-scroll").innerHTML = `
    <div class="empty-placeholder">
      Selecciona una petición a la izquierda o pulsa <strong>"🌐 Auditar Web Real"</strong> arriba.
    </div>
  `;
}

function buildComparisonBannerHtml(flowId) {
  const cmp = state.lastComparison;
  if (!cmp || cmp.new_flow.id !== flowId || cmp.previous_grade === null) {
    return "";
  }
  const deltaSign =
    cmp.score_delta >= 0 ? `+${cmp.score_delta}` : `${cmp.score_delta}`;
  const fixedBadges =
    cmp.fixed_headers.length > 0
      ? cmp.fixed_headers
          .map(
            (h) =>
              `<span class="pill pill-safe">✔ Corregido: ${escapeHtml(h)}</span>`
          )
          .join("")
      : `<span class="pill pill-warn">Sin cambios en escudos</span>`;

  return `
    <div class="diff-banner">
      <div>
        <div class="diff-scores">
          <span>🔁 Resultado del Repetidor (Comparativa Antes vs. Después):</span>
          <span class="pill pill-danger">Antes: Nota ${escapeHtml(cmp.previous_grade)} (${cmp.previous_score} pts)</span>
          <span>➔</span>
          <span class="pill pill-safe">Ahora: Nota ${escapeHtml(cmp.new_flow.security_audit.grade)} (${cmp.new_flow.security_audit.score} pts)</span>
          <span class="diff-delta">${deltaSign} pts</span>
        </div>
        <div class="fixed-chips">${fixedBadges}</div>
      </div>
    </div>
  `;
}

function buildSessionCookieTabHtml(flow) {
  const reqAuth =
    flow.request_headers["Authorization"] ||
    flow.request_headers["authorization"] ||
    null;
  const reqCookie =
    flow.request_headers["Cookie"] || flow.request_headers["cookie"] || null;
  const setCookie =
    flow.response_headers["Set-Cookie"] ||
    flow.response_headers["set-cookie"] ||
    "";

  const hasSecure = /;\s*secure/i.test(setCookie) || flow.scheme === "https";
  const hasHttpOnly = /;\s*httponly/i.test(setCookie);
  const hasSameSite = /;\s*samesite=(strict|lax)/i.test(setCookie);

  const sessionBanner = reqAuth || reqCookie
    ? `<div class="alert-banner sev-SAFE">
         <span class="alert-badge-tag">🔒 CWE-532</span>
         <div class="alert-text-group">
           <span class="alert-title">Credenciales de sesión enmascaradas automáticamente</span>
           <span class="alert-desc">Sitecrack oculta tokens Bearer y cookies en la base de datos para impedir filtraciones accidentales.</span>
         </div>
       </div>`
    : `<div class="alert-banner sev-INFO">
         <span class="alert-badge-tag">ℹ SESIÓN</span>
         <div class="alert-text-group">
           <span class="alert-title">Petición anónima sin credenciales adjuntas</span>
           <span class="alert-desc">Esta transacción no envió cabeceras Cookie ni Authorization.</span>
         </div>
       </div>`;

  const cookieFlags = [
    {
      name: "Atributo Secure (Solo HTTPS)",
      ok: hasSecure,
      desc: "Garantiza que la cookie de sesión nunca se transmita por conexiones HTTP sin cifrar.",
    },
    {
      name: "Atributo HttpOnly (Anti-XSS)",
      ok: hasHttpOnly,
      desc: "Impide que scripts maliciosos en el navegador lean la cookie mediante document.cookie.",
    },
    {
      name: "Atributo SameSite (Anti-CSRF)",
      ok: hasSameSite,
      desc: "Evita que sitios externos disparen peticiones autenticadas en nombre del usuario.",
    },
  ];

  const cards = cookieFlags
    .map((flag) => {
      const cls = flag.ok ? "card-active" : "card-missing";
      const badge = flag.ok
        ? `<span class="pill pill-safe">✔ Activo</span>`
        : `<span class="pill pill-warn">⚠ No detectado</span>`;
      return `
        <div class="protection-card ${cls}">
          <div>
            <div class="protection-header">
              <span class="protection-name">${escapeHtml(flag.name)}</span>
              ${badge}
            </div>
            <p class="protection-desc" style="margin-top:0.4rem;">${escapeHtml(flag.desc)}</p>
          </div>
        </div>
      `;
    })
    .join("");

  return `
    <div class="alerts-banner-list">${sessionBanner}</div>
    <div class="protection-grid">${cards}</div>
    <div class="section-box">
      <div class="section-title">🍪 Detalle de Tokens y Cookies en esta Transacción</div>
      <div class="kv-list">
        <div class="kv-row">
          <span class="kv-key">Authorization (Cliente)</span>
          <span class="kv-val">${escapeHtml(reqAuth || "No enviado")}</span>
        </div>
        <div class="kv-row">
          <span class="kv-key">Cookie (Cliente)</span>
          <span class="kv-val">${escapeHtml(reqCookie || "No enviada")}</span>
        </div>
        <div class="kv-row">
          <span class="kv-key">Set-Cookie (Servidor)</span>
          <span class="kv-val">${escapeHtml(setCookie || "El servidor no asignó nueva cookie en esta respuesta")}</span>
        </div>
      </div>
    </div>
  `;
}

function buildRemediationTabHtml(flow) {
  const cached = state.remediationCache[flow.id];
  if (!cached) {
    return `
      <div class="remediation-card">
        <p style="font-size:0.88rem; color:var(--text-secondary);">⏳ Generando código de solución personalizado para <strong>${escapeHtml(flow.host)}</strong>...</p>
      </div>
    `;
  }

  const snippet = cached[state.activeStack] || cached.fastapi || "";
  const missingCount = cached.missing_headers.length;
  const summaryBadge =
    missingCount === 0
      ? `<span class="pill pill-safe">✔ Todos los escudos presentes</span>`
      : `<span class="pill pill-warn">🛠️ Corrige ${missingCount} cabeceras ausentes</span>`;

  return `
    <div class="remediation-card">
      <div class="remediation-toolbar">
        <div>
          <h3 style="font-size:0.98rem; font-weight:800;">🛠️ Generador Automático de Código de Solución (Copy & Paste)</h3>
          <p style="font-size:0.83rem; color:var(--text-secondary); margin-top:0.2rem;">
            Copia y pega este bloque en tu servidor para activar los escudos que le faltan a <strong>${escapeHtml(flow.host)}</strong>.
          </p>
        </div>
        ${summaryBadge}
      </div>

      <div class="remediation-toolbar">
        <div class="stack-selector" role="tablist">
          <button class="stack-btn ${state.activeStack === "fastapi" ? "active" : ""}" data-stack="fastapi" type="button">
            🐍 FastAPI (Python)
          </button>
          <button class="stack-btn ${state.activeStack === "nginx" ? "active" : ""}" data-stack="nginx" type="button">
            🟢 Nginx
          </button>
          <button class="stack-btn ${state.activeStack === "apache" ? "active" : ""}" data-stack="apache" type="button">
            🪶 Apache (.htaccess)
          </button>
          <button class="stack-btn ${state.activeStack === "express" ? "active" : ""}" data-stack="express" type="button">
            🟩 Node.js (Express)
          </button>
        </div>

        <button id="btn-copy-remediation" class="btn btn-primary" type="button">
          📋 Copiar código de solución
        </button>
      </div>

      <pre id="remediation-code-block" class="code-viewer">${escapeHtml(snippet)}</pre>
    </div>
  `;
}

async function ensureRemediationLoaded(flowId) {
  if (state.remediationCache[flowId]) return;
  const resp = await fetch(`/api/v1/flows/${flowId}/remediation`);
  if (resp.ok) {
    state.remediationCache[flowId] = await resp.json();
    if (state.selectedFlowId === flowId && state.activeTab === "remediation") {
      renderInspector();
    }
  }
}

function renderInspector() {
  const flow = state.flows.find((f) => f.id === state.selectedFlowId);
  if (!flow) {
    renderEmptyInspector();
    return;
  }

  const audit = flow.security_audit;
  const gradeTone = getToneByGrade(audit.grade);
  const statusTone = getToneByStatus(flow.status_code);
  const verdict = getPlainVerdict(flow);
  const comparisonHtml = buildComparisonBannerHtml(flow.id);
  const scoreRingHtml = buildScoreRingSvg(audit.grade, audit.score, gradeTone);

  let tabBodyHtml = "";

  if (state.activeTab === "security") {
    let alertsHtml = "";
    if (audit.findings.length === 0) {
      alertsHtml = `
        <div class="alerts-banner-list">
          <div class="alert-banner sev-SAFE">
            <span class="alert-badge-tag">✔ SEGURO</span>
            <div class="alert-text-group">
              <span class="alert-title">Sin avisos de riesgo detectados</span>
              <span class="alert-desc">Esta respuesta cumple todas las políticas de cabeceras seguras evaluadas.</span>
            </div>
          </div>
        </div>
      `;
    } else {
      const items = audit.findings
        .map((f) => {
          const label =
            f.severity === "HIGH"
              ? "🚨 CRÍTICO"
              : f.severity === "MEDIUM"
              ? "⚠ AVISO"
              : "ℹ INFO";
          return `
            <div class="alert-banner sev-${escapeHtml(f.severity)}">
              <span class="alert-badge-tag">${label}</span>
              <div class="alert-text-group">
                <span class="alert-title">${escapeHtml(f.header)}</span>
                <span class="alert-desc">${escapeHtml(f.description)}</span>
              </div>
            </div>
          `;
        })
        .join("");
      alertsHtml = `<div class="alerts-banner-list">${items}</div>`;
    }

    const cardsHtml = PROTECTIONS_GUIDE.map((item) => {
      const isMissing = audit.missing_headers.includes(item.header);
      const cardToneCls = isMissing ? "card-missing" : "card-active";
      const badgeHtml = isMissing
        ? `<span class="pill pill-danger">🚨 Falta escudo</span>`
        : `<span class="pill pill-safe">✔ Protegido</span>`;
      return `
        <div class="protection-card ${cardToneCls}">
          <div>
            <div class="protection-header">
              <span class="protection-name">${escapeHtml(item.title)}</span>
              ${badgeHtml}
            </div>
            <p class="protection-desc" style="margin-top:0.4rem;">${escapeHtml(item.desc)}</p>
          </div>
          <div style="font-family:var(--font-mono); font-size:0.74rem; color:var(--text-muted);">
            Cabecera: ${escapeHtml(item.header)}
          </div>
        </div>
      `;
    }).join("");

    tabBodyHtml = `
      ${alertsHtml}
      <div class="protection-grid">
        ${cardsHtml}
      </div>
    `;
  } else if (state.activeTab === "remediation") {
    ensureRemediationLoaded(flow.id);
    tabBodyHtml = buildRemediationTabHtml(flow);
  } else if (state.activeTab === "repeater") {
    const respHeadersJson = JSON.stringify(flow.response_headers, null, 2);
    const reqHeadersJson = JSON.stringify(flow.request_headers, null, 2);

    tabBodyHtml = `
      <div class="repeater-card">
        <div>
          <h3 style="font-size:0.98rem; font-weight:800;">🔁 Repetidor y Laboratorio de Corrección en Vivo</h3>
          <p style="font-size:0.83rem; color:var(--text-secondary); margin-top:0.2rem;">
            Modifica la dirección, el método o inyecta escudos de seguridad con 1 clic para reenviar la petición y comparar cómo sube su nota.
          </p>
        </div>

        <div>
          <div style="font-size:0.78rem; font-weight:700; color:var(--text-secondary); margin-bottom:0.4rem;">
            ⚡ Inyectar protecciones con 1 clic:
          </div>
          <div class="quick-shields-bar">
            <button class="chip-btn" type="button" data-quick-https="true">🔒 Cambiar a HTTPS</button>
            <button class="chip-btn" type="button" data-quick-header="Strict-Transport-Security">＋ Añadir HSTS</button>
            <button class="chip-btn" type="button" data-quick-header="Content-Security-Policy">＋ Añadir CSP</button>
            <button class="chip-btn" type="button" data-quick-header="X-Frame-Options">＋ Anti-Clickjacking</button>
            <button class="chip-btn" type="button" data-quick-header="X-Content-Type-Options">＋ Nosniff</button>
            <button class="chip-btn chip-magic" type="button" data-quick-all="true">✨ Blindar Todo (Nota A)</button>
          </div>
        </div>

        <div class="repeater-row">
          <div class="field">
            <label for="rep-method">Método</label>
            <select id="rep-method" class="method-select">
              <option value="GET" ${flow.method === "GET" ? "selected" : ""}>GET</option>
              <option value="POST" ${flow.method === "POST" ? "selected" : ""}>POST</option>
              <option value="PUT" ${flow.method === "PUT" ? "selected" : ""}>PUT</option>
              <option value="DELETE" ${flow.method === "DELETE" ? "selected" : ""}>DELETE</option>
            </select>
          </div>
          <div class="field">
            <label for="rep-url">Dirección URL a reenviar</label>
            <input id="rep-url" class="search-input" type="text" value="${escapeHtml(flow.url)}" />
          </div>
          <div class="field">
            <label for="rep-status">Estado HTTP</label>
            <input id="rep-status" class="search-input" type="number" min="100" max="599" value="${flow.status_code}" />
          </div>
        </div>

        <div style="display:grid; grid-template-columns: 1fr 1fr; gap: 0.85rem;">
          <div class="field">
            <label for="rep-resp-headers">🛡️ Cabeceras de Seguridad (Respuesta JSON)</label>
            <textarea id="rep-resp-headers" class="repeater-textarea">${escapeHtml(respHeadersJson)}</textarea>
          </div>
          <div class="field">
            <label for="rep-req-headers">📤 Cabeceras de Petición (Cliente JSON)</label>
            <textarea id="rep-req-headers" class="repeater-textarea">${escapeHtml(reqHeadersJson)}</textarea>
          </div>
        </div>

        <div class="field">
          <label for="rep-body">📦 Cuerpo / Payload enviado en la petición</label>
          <textarea id="rep-body" class="repeater-textarea" style="min-height:75px;">${escapeHtml(flow.request_preview)}</textarea>
        </div>

        <div style="display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:0.75rem;">
          <label style="display:inline-flex; align-items:center; gap:0.45rem; font-size:0.83rem; font-weight:600; cursor:pointer;">
            <input id="rep-live-net" type="checkbox" />
            🌐 Conectar por red real si el dominio es público (Con protección Anti-SSRF)
          </label>

          <button id="btn-run-repeater" class="btn btn-primary" type="button">
            🚀 Reenviar Petición y Comparar Nota
          </button>
        </div>
      </div>
    `;
  } else if (state.activeTab === "cookies") {
    tabBodyHtml = buildSessionCookieTabHtml(flow);
  } else if (state.activeTab === "headers") {
    const reqList = Object.entries(flow.request_headers)
      .map(
        ([k, v]) =>
          `<div class="kv-row"><span class="kv-key">${escapeHtml(k)}</span><span class="kv-val">${escapeHtml(v)}</span></div>`
      )
      .join("");
    const respList = Object.entries(flow.response_headers)
      .map(
        ([k, v]) =>
          `<div class="kv-row"><span class="kv-key">${escapeHtml(k)}</span><span class="kv-val">${escapeHtml(v)}</span></div>`
      )
      .join("");

    tabBodyHtml = `
      <div class="section-box">
        <div class="section-title">📤 Cabeceras enviadas por el navegador (Tokens ocultados por seguridad)</div>
        <div class="kv-list">${reqList || "Ninguna"}</div>
      </div>
      <div class="section-box">
        <div class="section-title">📥 Cabeceras respondidas por el servidor</div>
        <div class="kv-list">${respList || "Ninguna"}</div>
      </div>
    `;
  } else {
    tabBodyHtml = `
      <div class="section-box">
        <div class="section-title">📤 Datos enviados en la petición (${flow.request_size} bytes)</div>
        <pre class="code-viewer">${escapeHtml(flow.request_preview || "Esta petición no envió datos adjuntos.")}</pre>
      </div>
      <div class="section-box">
        <div class="section-title">📥 Respuesta recibida del servidor (${flow.response_size} bytes · ${escapeHtml(flow.content_type)})</div>
        <pre class="code-viewer">${escapeHtml(flow.response_preview || "Sin vista previa de texto.")}</pre>
      </div>
    `;
  }

  const container = document.getElementById("inspector-scroll");
  container.innerHTML = `
    ${comparisonHtml}

    <!-- Banner Hero en Estilo Glass Coloreado con Anillo SVG Animado -->
    <div class="score-hero hero-${gradeTone}">
      <div class="score-hero-left">
        ${scoreRingHtml}
        <div>
          <div class="hero-verdict">${escapeHtml(verdict)}</div>
          <div class="hero-url">${escapeHtml(flow.method)} ${escapeHtml(flow.url)}</div>
        </div>
      </div>

      <div style="display:flex; gap:0.5rem; align-items:center; flex-wrap:wrap;">
        <span class="pill pill-${statusTone}">HTTP ${flow.status_code}</span>
        <span class="pill" style="background:var(--glass-card-bg); border-color:var(--glass-outer-border);">
          ⏱ ${flow.duration_ms.toFixed(1)} ms
        </span>
        <button id="btn-hero-remediation" class="btn" type="button" style="padding:0.38rem 0.85rem; font-size:0.8rem;">
          🛠️ Ver Solución
        </button>
        <button id="btn-hero-repeater" class="btn btn-primary" type="button" style="padding:0.38rem 0.85rem; font-size:0.8rem;">
          🔁 Modificar y Reenviar
        </button>
      </div>
    </div>

    <!-- Pestañas Segmented Control -->
    <div class="segmented-tabs" role="tablist">
      <button class="seg-btn ${state.activeTab === "security" ? "active" : ""}" data-tab="security" type="button">
        🛡️ Avisos y Escudos (${audit.findings.length})
      </button>
      <button class="seg-btn ${state.activeTab === "remediation" ? "active" : ""}" data-tab="remediation" type="button">
        🛠️ Cómo Solucionarlo
      </button>
      <button class="seg-btn ${state.activeTab === "repeater" ? "active" : ""}" data-tab="repeater" type="button">
        🔁 Repetidor en Vivo
      </button>
      <button class="seg-btn ${state.activeTab === "cookies" ? "active" : ""}" data-tab="cookies" type="button">
        🍪 Sesiones y Cookies
      </button>
      <button class="seg-btn ${state.activeTab === "headers" ? "active" : ""}" data-tab="headers" type="button">
        📋 Cabeceras
      </button>
      <button class="seg-btn ${state.activeTab === "payload" ? "active" : ""}" data-tab="payload" type="button">
        📦 Datos
      </button>
    </div>

    <!-- Contenido de la Pestaña -->
    ${tabBodyHtml}
  `;

  container.querySelectorAll(".seg-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      state.activeTab = btn.dataset.tab;
      renderInspector();
    });
  });

  const heroRepBtn = document.getElementById("btn-hero-repeater");
  if (heroRepBtn) {
    heroRepBtn.addEventListener("click", () => {
      state.activeTab = "repeater";
      renderInspector();
    });
  }

  const heroRemBtn = document.getElementById("btn-hero-remediation");
  if (heroRemBtn) {
    heroRemBtn.addEventListener("click", () => {
      state.activeTab = "remediation";
      renderInspector();
    });
  }

  wireRemediationEvents(flow);
  wireRepeaterEvents(flow);
}

function wireRemediationEvents(flow) {
  if (state.activeTab !== "remediation") return;

  document.querySelectorAll(".stack-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      state.activeStack = btn.dataset.stack;
      renderInspector();
    });
  });

  const copyBtn = document.getElementById("btn-copy-remediation");
  if (copyBtn) {
    copyBtn.addEventListener("click", async () => {
      const codeEl = document.getElementById("remediation-code-block");
      if (!codeEl) return;
      try {
        await navigator.clipboard.writeText(codeEl.textContent);
        showToast(
          `Código de solución (${state.activeStack.toUpperCase()}) copiado al portapapeles`,
          "safe"
        );
      } catch {
        showToast("No se pudo copiar automáticamente al portapapeles", "warn");
      }
    });
  }
}

function wireRepeaterEvents(flow) {
  if (state.activeTab !== "repeater") return;

  const urlInput = document.getElementById("rep-url");
  const respTextarea = document.getElementById("rep-resp-headers");

  document.querySelectorAll("[data-quick-https]").forEach((btn) => {
    btn.addEventListener("click", () => {
      urlInput.value = urlInput.value.replace(/^http:\/\//i, "https://");
      showToast("URL actualizada a HTTPS", "safe");
    });
  });

  document.querySelectorAll("[data-quick-header]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const headerName = btn.getAttribute("data-quick-header");
      try {
        const current = JSON.parse(respTextarea.value || "{}");
        current[headerName] = QUICK_SHIELD_VALUES[headerName];
        respTextarea.value = JSON.stringify(current, null, 2);
        showToast(`Escudo ${headerName} inyectado`, "safe");
      } catch {
        showToast("Revisa el formato JSON de las cabeceras", "warn");
      }
    });
  });

  document.querySelectorAll("[data-quick-all]").forEach((btn) => {
    btn.addEventListener("click", () => {
      urlInput.value = urlInput.value.replace(/^http:\/\//i, "https://");
      try {
        const current = JSON.parse(respTextarea.value || "{}");
        Object.entries(QUICK_SHIELD_VALUES).forEach(([k, v]) => {
          current[k] = v;
        });
        delete current["Server"];
        delete current["server"];
        respTextarea.value = JSON.stringify(current, null, 2);
      } catch {
        respTextarea.value = JSON.stringify(QUICK_SHIELD_VALUES, null, 2);
      }
      showToast("Todos los escudos OWASP inyectados (Nota A)", "safe");
    });
  });

  const runBtn = document.getElementById("btn-run-repeater");
  if (runBtn) {
    runBtn.addEventListener("click", async () => {
      let parsedRespHeaders = {};
      let parsedReqHeaders = {};
      try {
        parsedRespHeaders = JSON.parse(respTextarea.value || "{}");
      } catch {
        showToast("El JSON de Cabeceras de Seguridad no es válido", "danger");
        return;
      }
      try {
        parsedReqHeaders = JSON.parse(
          document.getElementById("rep-req-headers").value || "{}"
        );
      } catch {
        showToast("El JSON de Cabeceras de Petición no es válido", "danger");
        return;
      }

      const payload = {
        original_flow_id: flow.id,
        method: document.getElementById("rep-method").value,
        url: urlInput.value.trim(),
        status_code: Number(document.getElementById("rep-status").value || 200),
        request_headers: parsedReqHeaders,
        response_headers: parsedRespHeaders,
        request_body: document.getElementById("rep-body").value,
        live_network: document.getElementById("rep-live-net").checked,
      };

      runBtn.textContent = "⏳ Procesando...";
      runBtn.disabled = true;

      const resp = await fetch("/api/v1/repeat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      if (resp.ok) {
        const result = await resp.json();
        state.lastComparison = result;
        state.selectedFlowId = result.new_flow.id;
        state.activeTab = "security";
        showToast(
          `Petición reenviada: Nota ${result.new_flow.security_audit.grade} (${result.new_flow.security_audit.score}/100)`,
          getToneByGrade(result.new_flow.security_audit.grade)
        );
        await fetchTelemetry();
      } else {
        showToast("Error al reenviar la petición", "danger");
        runBtn.textContent = "🚀 Reenviar Petición y Comparar Nota";
        runBtn.disabled = false;
      }
    });
  }
}

document.addEventListener("DOMContentLoaded", () => {
  document.getElementById("input-host-filter").addEventListener("input", (e) => {
    state.hostFilter = e.target.value.trim();
    fetchTelemetry();
  });

  document.getElementById("select-grade-filter").addEventListener("change", (e) => {
    state.gradeFilter = e.target.value;
    renderFlowList();
    const visible = getFilteredFlows();
    if (visible.length > 0) {
      state.selectedFlowId = visible[0].id;
      renderInspector();
    } else {
      state.selectedFlowId = null;
      renderEmptyInspector();
    }
  });

  document.getElementById("select-method-filter").addEventListener("change", (e) => {
    state.methodFilter = e.target.value;
    fetchTelemetry();
  });

  document.getElementById("btn-export-report").addEventListener("click", () => {
    window.open("/api/v1/report/html", "_blank");
    showToast("Informe ejecutivo abierto en nueva pestaña", "safe");
  });

  document.getElementById("btn-seed-demo").addEventListener("click", async () => {
    await fetch("/api/v1/demo-seed", { method: "POST" });
    showToast("Ejemplos de demostración cargados", "safe");
    await fetchTelemetry();
  });

  document.getElementById("btn-clear").addEventListener("click", async () => {
    state.lastComparison = null;
    state.remediationCache = {};
    await fetch("/api/v1/flows", { method: "DELETE" });
    showToast("Lista de peticiones vaciada", "warn");
    await fetchTelemetry();
  });

  document.getElementById("btn-toggle-theme").addEventListener("click", () => {
    const html = document.documentElement;
    const isDark = html.getAttribute("data-theme") === "dark";
    html.setAttribute("data-theme", isDark ? "light" : "dark");
  });

  document.getElementById("btn-toggle-scale").addEventListener("click", () => {
    const html = document.documentElement;
    const isLarge = html.getAttribute("data-scale") === "large";
    html.setAttribute("data-scale", isLarge ? "normal" : "large");
  });

  // Modal de Auditoría de Web Real en Vivo
  const liveModal = document.getElementById("live-scan-modal");
  const liveUrlInput = document.getElementById("live-scan-url");
  const submitLiveBtn = document.getElementById("btn-submit-live-scan");

  document.getElementById("btn-open-live-scan").addEventListener("click", () => {
    liveModal.hidden = false;
    liveUrlInput.focus();
  });

  document.getElementById("btn-close-live-modal").addEventListener("click", () => {
    liveModal.hidden = true;
  });

  document.querySelectorAll("[data-sample-url]").forEach((btn) => {
    btn.addEventListener("click", () => {
      liveUrlInput.value = btn.getAttribute("data-sample-url");
    });
  });

  submitLiveBtn.addEventListener("click", async () => {
    const targetUrl = liveUrlInput.value.trim();
    const method = document.getElementById("live-scan-method").value;
    if (!targetUrl) return;

    const origText = submitLiveBtn.textContent;
    submitLiveBtn.textContent = "⏳ Conectando con la web...";
    submitLiveBtn.disabled = true;

    try {
      const resp = await fetch("/api/v1/scan-live", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: targetUrl, method }),
      });

      if (resp.ok) {
        const scannedFlow = await resp.json();
        liveModal.hidden = true;
        state.selectedFlowId = scannedFlow.id;
        state.activeTab = "security";
        const g = scannedFlow.security_audit.grade;
        showToast(
          `Web auditada: ${scannedFlow.host} · Nota ${g} (${scannedFlow.security_audit.score}/100) en ${scannedFlow.duration_ms.toFixed(0)} ms`,
          getToneByGrade(g)
        );
        await fetchTelemetry();
      } else {
        const errData = await resp.json().catch(() => ({}));
        showToast(
          errData.detail || "No se pudo conectar o fue bloqueado por Anti-SSRF",
          "danger"
        );
      }
    } finally {
      submitLiveBtn.textContent = origText;
      submitLiveBtn.disabled = false;
    }
  });

  // Modal de Simulación Local
  const modal = document.getElementById("simulator-modal");
  document.getElementById("btn-open-simulator").addEventListener("click", () => {
    modal.hidden = false;
  });
  document.getElementById("btn-close-modal").addEventListener("click", () => {
    modal.hidden = true;
  });
  document.getElementById("btn-submit-sim").addEventListener("click", async () => {
    const urlValue = document.getElementById("sim-url").value.trim();
    const methodValue = document.getElementById("sim-method").value;
    const statusValue = Number(document.getElementById("sim-status").value);
    const presetValue = document.getElementById("sim-preset").value;

    await fetch("/api/v1/simulate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url: urlValue,
        method: methodValue,
        status_code: statusValue,
        preset: presetValue,
      }),
    });
    modal.hidden = true;
    showToast("Petición simulada añadida a la lista", "safe");
    await fetchTelemetry();
  });

  fetchTelemetry();
  setInterval(fetchTelemetry, 4000);
});
