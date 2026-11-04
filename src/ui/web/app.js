/* ==========================================================================
   Sitecrack Modern Glass UI Controller (app.js)
   Banners en estilo cristal esmerilado y avisos coloreados de alto impacto.
   ========================================================================== */

const state = {
  flows: [],
  selectedFlowId: null,
  activeTab: "security",
  hostFilter: "",
  methodFilter: "",
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

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
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

  renderFlowList();

  if (state.flows.length > 0) {
    const exists = state.flows.some((f) => f.id === state.selectedFlowId);
    if (!exists) {
      state.selectedFlowId = state.flows[0].id;
    }
    renderInspector();
  } else {
    state.selectedFlowId = null;
    renderEmptyInspector();
  }
}

function renderFlowList() {
  const container = document.getElementById("flow-list");
  if (state.flows.length === 0) {
    container.innerHTML = `
      <div class="empty-placeholder">
        <p style="font-weight:700; color:var(--text-main); margin-bottom:0.35rem;">Lista vacía</p>
        <p style="font-size:0.84rem;">Pulsa <strong>"Cargar ejemplos"</strong> o <strong>"＋ Nueva prueba"</strong> arriba a la derecha.</p>
      </div>
    `;
    return;
  }

  container.innerHTML = state.flows
    .map((flow) => {
      const selectedCls = flow.id === state.selectedFlowId ? "selected" : "";
      const gradeTone = getToneByGrade(flow.security_audit.grade);
      const lockIcon = flow.scheme === "https" ? "🔒" : "🔓";
      const pillIcon = gradeTone === "safe" ? "✔" : gradeTone === "warn" ? "⚠" : "🚨";
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
      Selecciona una petición a la izquierda para ver sus avisos y escudos de seguridad.
    </div>
  `;
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

  let tabBodyHtml = "";

  if (state.activeTab === "security") {
    // 1. Bloque de Avisos Coloreados de Alto Impacto
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

    // 2. Cuadrícula de Escudos con Borde Superior Coloreado
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
    <!-- Banner Hero en Estilo Glass Coloreado -->
    <div class="score-hero hero-${gradeTone}">
      <div class="score-hero-left">
        <div class="grade-circle ${gradeTone}">
          ${escapeHtml(audit.grade)}
          <span>${audit.score}/100</span>
        </div>
        <div>
          <div class="hero-verdict">${escapeHtml(verdict)}</div>
          <div class="hero-url">${escapeHtml(flow.method)} ${escapeHtml(flow.url)}</div>
        </div>
      </div>

      <div style="display:flex; gap:0.5rem; align-items:center;">
        <span class="pill pill-${statusTone}">HTTP ${flow.status_code}</span>
        <span class="pill" style="background:var(--glass-card-bg); border-color:var(--glass-outer-border);">
          ⏱ ${flow.duration_ms.toFixed(1)} ms
        </span>
      </div>
    </div>

    <!-- Pestañas Segmented Control -->
    <div class="segmented-tabs" role="tablist">
      <button class="seg-btn ${state.activeTab === "security" ? "active" : ""}" data-tab="security" type="button">
        🛡️ Avisos y Escudos (${audit.findings.length})
      </button>
      <button class="seg-btn ${state.activeTab === "headers" ? "active" : ""}" data-tab="headers" type="button">
        📋 Cabeceras Técnicas
      </button>
      <button class="seg-btn ${state.activeTab === "payload" ? "active" : ""}" data-tab="payload" type="button">
        📦 Contenido / Datos
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
}

document.addEventListener("DOMContentLoaded", () => {
  document.getElementById("input-host-filter").addEventListener("input", (e) => {
    state.hostFilter = e.target.value.trim();
    fetchTelemetry();
  });

  document.getElementById("select-method-filter").addEventListener("change", (e) => {
    state.methodFilter = e.target.value;
    fetchTelemetry();
  });

  document.getElementById("btn-seed-demo").addEventListener("click", async () => {
    await fetch("/api/v1/demo-seed", { method: "POST" });
    await fetchTelemetry();
  });

  document.getElementById("btn-clear").addEventListener("click", async () => {
    await fetch("/api/v1/flows", { method: "DELETE" });
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
    await fetchTelemetry();
  });

  fetchTelemetry();
  setInterval(fetchTelemetry, 4000);
});
