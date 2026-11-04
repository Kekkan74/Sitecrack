/* ==========================================================================
   Sitecrack Graphical Application Controller (app.js)
   Consume los endpoints REST de FastAPI con bajo acoplamiento.
   ========================================================================== */

const state = {
  flows: [],
  selectedFlowId: null,
  activeTab: "security",
  hostFilter: "",
  methodFilter: "",
};

const HEADER_EXPLANATIONS = {
  "Strict-Transport-Security":
    "Obliga al navegador a conectarse siempre usando cifrado HTTPS, evitando que alguien intercepte la conexión en redes Wi-Fi públicas.",
  "Content-Security-Policy":
    "Controla desde qué orígenes se pueden ejecutar scripts en la página, bloqueando ataques de inyección de código (XSS).",
  "X-Content-Type-Options":
    "Impide que el navegador adivine el tipo de archivo por su cuenta (nosniff), evitando que un archivo de texto se ejecute como código.",
  "X-Frame-Options":
    "Evita que otra web maliciosa incruste esta página dentro de un recuadro invisible para engañar los clics del usuario (Clickjacking).",
  "Referrer-Policy":
    "Protege la privacidad evitando que la dirección completa de la página actual se filtre al pulsar enlaces hacia otros sitios.",
  "Permissions-Policy":
    "Bloquea el uso no autorizado de cámara, micrófono o geolocalización dentro de la aplicación web.",
};

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function renderStatusBadge(statusCode) {
  if (statusCode >= 200 && statusCode < 300) {
    return `<span class="badge badge-ok">✔ ${statusCode} Correcto</span>`;
  }
  if (statusCode >= 300 && statusCode < 400) {
    return `<span class="badge badge-info">↪ ${statusCode} Redirección</span>`;
  }
  if (statusCode >= 400 && statusCode < 500) {
    return `<span class="badge badge-warn">⚠ ${statusCode} Aviso Cliente</span>`;
  }
  return `<span class="badge badge-danger">✖ ${statusCode} Error Servidor</span>`;
}

function renderSchemeBadge(scheme) {
  if (String(scheme).toLowerCase() === "https") {
    return `<span class="badge badge-ok" title="Tráfico protegido con TLS">🔒 HTTPS</span>`;
  }
  return `<span class="badge badge-danger" title="Tráfico en texto claro sin cifrar">🔓 HTTP</span>`;
}

function renderGradeBadge(grade, score) {
  const map = {
    A: { cls: "badge-ok", icon: "★", label: "Excelente" },
    B: { cls: "badge-info", icon: "◆", label: "Buena" },
    C: { cls: "badge-warn", icon: "▲", label: "Mejorable" },
    D: { cls: "badge-warn", icon: "▼", label: "Débil" },
    F: { cls: "badge-danger", icon: "✖", label: "Riesgo Alto" },
  };
  const info = map[grade] || map.C;
  return `<span class="badge ${info.cls}">${info.icon} Nota ${escapeHtml(grade)} (${score}/100 · ${info.label})</span>`;
}

async function fetchTelemetry() {
  const params = new URLSearchParams({ limit: "150" });
  if (state.hostFilter) params.set("host", state.hostFilter);
  if (state.methodFilter) params.set("method", state.methodFilter);

  const [flowsResp, statsResp] = await Promise.all([
    fetch(`/api/v1/flows?${params.toString()}`),
    fetch("/api/v1/stats"),
  ]);

  state.flows = await flowsResp.json();
  const stats = await statsResp.json();

  updateStatsStrip(stats);
  renderFlowsTable();

  if (state.flows.length > 0) {
    const stillExists = state.flows.some((f) => f.id === state.selectedFlowId);
    if (!stillExists) {
      state.selectedFlowId = state.flows[0].id;
    }
    renderInspector();
  } else {
    state.selectedFlowId = null;
    renderEmptyInspector();
  }
}

function updateStatsStrip(stats) {
  document.getElementById("stat-total").textContent = stats.total_flows;
  document.getElementById("stat-https").textContent = stats.https_count;
  document.getElementById("stat-http").textContent = stats.http_count;
  document.getElementById("stat-low-sec").textContent = stats.low_security_count;
  document.getElementById("stat-latency").textContent = `${stats.avg_duration_ms} ms`;
}

function renderFlowsTable() {
  const tbody = document.getElementById("flows-tbody");
  if (state.flows.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="7" class="empty-state">
          <p style="font-weight:700; font-size:1rem; margin-bottom:0.4rem;">
            Aún no hay peticiones en la lista
          </p>
          <p>
            Pulsa el botón <strong>"＋ Cargar tráfico de muestra"</strong> arriba a la derecha para explorar ejemplos reales al instante, o usa <strong>"⚡ Simular petición"</strong>.
          </p>
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = state.flows
    .map((flow) => {
      const isSelected = flow.id === state.selectedFlowId ? "selected" : "";
      return `
        <tr class="flow-row ${isSelected}" data-flow-id="${flow.id}" tabindex="0">
          <td class="mono-cell">#${flow.id}</td>
          <td>${renderSchemeBadge(flow.scheme)}</td>
          <td class="mono-cell"><strong>${escapeHtml(flow.method)}</strong></td>
          <td class="host-cell">
            <span class="host-primary">${escapeHtml(flow.host)}</span>
            <span class="path-secondary">${escapeHtml(flow.path)}</span>
          </td>
          <td>${renderStatusBadge(flow.status_code)}</td>
          <td class="mono-cell">${flow.duration_ms.toFixed(1)} ms</td>
          <td>${renderGradeBadge(flow.security_audit.grade, flow.security_audit.score)}</td>
        </tr>
      `;
    })
    .join("");

  tbody.querySelectorAll(".flow-row").forEach((row) => {
    row.addEventListener("click", () => {
      state.selectedFlowId = Number(row.dataset.flowId);
      renderFlowsTable();
      renderInspector();
    });
    row.addEventListener("keydown", (ev) => {
      if (ev.key === "Enter" || ev.key === " ") {
        ev.preventDefault();
        state.selectedFlowId = Number(row.dataset.flowId);
        renderFlowsTable();
        renderInspector();
      }
    });
  });
}

function renderEmptyInspector() {
  document.getElementById("detail-badges").textContent = "Ninguna petición seleccionada";
  document.getElementById("detail-timestamp").textContent = "";
  document.getElementById("detail-url").textContent = "—";
  document.getElementById("inspector-content").innerHTML = `
    <div class="card empty-state">
      Selecciona cualquier fila en la tabla de la izquierda o carga el tráfico de muestra para ver su diagnóstico visual de seguridad.
    </div>
  `;
}

function renderInspector() {
  const flow = state.flows.find((f) => f.id === state.selectedFlowId);
  if (!flow) {
    renderEmptyInspector();
    return;
  }

  document.getElementById("detail-badges").innerHTML = `
    ${renderSchemeBadge(flow.scheme)}
    <span class="badge badge-info">${escapeHtml(flow.method)}</span>
    ${renderStatusBadge(flow.status_code)}
    ${renderGradeBadge(flow.security_audit.grade, flow.security_audit.score)}
  `;
  document.getElementById("detail-timestamp").textContent = flow.timestamp;
  document.getElementById("detail-url").textContent = flow.url;

  const container = document.getElementById("inspector-content");

  if (state.activeTab === "security") {
    const audit = flow.security_audit;
    const findingsHtml =
      audit.findings.length === 0
        ? `<div class="finding-item" style="border-left-color:var(--ok-border); background:var(--ok-bg); color:var(--ok-ink);">
             <div class="finding-title">✔ Excelente postura defensiva</div>
             <div class="finding-desc">Esta respuesta incluye cifrado HTTPS y todas las cabeceras de seguridad recomendadas por OWASP.</div>
           </div>`
        : audit.findings
            .map(
              (f) => `
              <div class="finding-item sev-${escapeHtml(f.severity)}">
                <div class="finding-title">
                  ${f.severity === "HIGH" ? "✖ Riesgo Alto" : f.severity === "MEDIUM" ? "⚠ Aviso Medio" : "ℹ Información"}
                  — ${escapeHtml(f.header)}
                </div>
                <div class="finding-desc">${escapeHtml(f.description)}</div>
              </div>
            `
            )
            .join("");

    const checklistHtml = Object.entries(HEADER_EXPLANATIONS)
      .map(([headerName, explanation]) => {
        const isMissing = audit.missing_headers.includes(headerName);
        const badge = isMissing
          ? `<span class="badge badge-danger">✖ Falta</span>`
          : `<span class="badge badge-ok">✔ Presente</span>`;
        return `
          <div style="padding:0.65rem 0; border-bottom:1px solid var(--border-subtle); display:flex; justify-content:space-between; align-items:flex-start; gap:1rem;">
            <div>
              <div style="font-weight:700; font-family:var(--font-mono); font-size:0.86rem;">${escapeHtml(headerName)}</div>
              <div style="font-size:0.83rem; color:var(--ink-secondary); margin-top:0.15rem;">${escapeHtml(explanation)}</div>
            </div>
            <div>${badge}</div>
          </div>
        `;
      })
      .join("");

    container.innerHTML = `
      <div class="card">
        <div class="card-title">
          <span>Hallazgos detectados en esta respuesta</span>
          <span>Puntuación: ${audit.score} / 100</span>
        </div>
        <div class="finding-list">${findingsHtml}</div>
      </div>

      <div class="card">
        <div class="card-title">
          <span>Lista de comprobación de protecciones web (Guía clara)</span>
        </div>
        <div>${checklistHtml}</div>
      </div>
    `;
  } else if (state.activeTab === "headers") {
    const reqRows = Object.entries(flow.request_headers)
      .map(
        ([k, v]) =>
          `<div class="kv-key">${escapeHtml(k)}</div><div class="kv-val">${escapeHtml(v)}</div>`
      )
      .join("");
    const respRows = Object.entries(flow.response_headers)
      .map(
        ([k, v]) =>
          `<div class="kv-key">${escapeHtml(k)}</div><div class="kv-val">${escapeHtml(v)}</div>`
      )
      .join("");

    container.innerHTML = `
      <div class="card">
        <div class="card-title">
          <span>📤 Cabeceras enviadas por el cliente (Credenciales ocultadas automáticamente)</span>
        </div>
        <div class="kv-grid">${reqRows || "<div>Sin cabeceras</div>"}</div>
      </div>
      <div class="card">
        <div class="card-title">
          <span>📥 Cabeceras devueltas por el servidor</span>
        </div>
        <div class="kv-grid">${respRows || "<div>Sin cabeceras</div>"}</div>
      </div>
    `;
  } else {
    container.innerHTML = `
      <div class="card">
        <div class="card-title">
          <span>📤 Cuerpo enviado en la petición (${flow.request_size} bytes)</span>
        </div>
        <pre class="code-block">${escapeHtml(flow.request_preview || "(Sin datos enviados en el cuerpo de la petición)")}</pre>
      </div>
      <div class="card">
        <div class="card-title">
          <span>📥 Cuerpo recibido en la respuesta (${flow.response_size} bytes · ${escapeHtml(flow.content_type)})</span>
        </div>
        <pre class="code-block">${escapeHtml(flow.response_preview || "(Respuesta sin contenido textual)")}</pre>
      </div>
    `;
  }
}

document.addEventListener("DOMContentLoaded", () => {
  // Pestañas del inspector
  document.querySelectorAll(".tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".tab-btn").forEach((b) => {
        b.classList.remove("active");
        b.setAttribute("aria-selected", "false");
      });
      btn.classList.add("active");
      btn.setAttribute("aria-selected", "true");
      state.activeTab = btn.dataset.tab;
      renderInspector();
    });
  });

  // Filtros en vivo
  document.getElementById("input-host-filter").addEventListener("input", (e) => {
    state.hostFilter = e.target.value.trim();
    fetchTelemetry();
  });

  document.getElementById("select-method-filter").addEventListener("change", (e) => {
    state.methodFilter = e.target.value;
    fetchTelemetry();
  });

  // Botón Cargar Tráfico de Muestra
  document.getElementById("btn-seed-demo").addEventListener("click", async () => {
    await fetch("/api/v1/demo-seed", { method: "POST" });
    await fetchTelemetry();
  });

  // Botón Actualizar
  document.getElementById("btn-refresh").addEventListener("click", () => {
    fetchTelemetry();
  });

  // Botón Limpiar
  document.getElementById("btn-clear").addEventListener("click", async () => {
    await fetch("/api/v1/flows", { method: "DELETE" });
    await fetchTelemetry();
  });

  // Conmutador Alto Contraste
  const themeBtn = document.getElementById("btn-toggle-theme");
  themeBtn.addEventListener("click", () => {
    const html = document.documentElement;
    const isHigh = html.getAttribute("data-theme") === "high-contrast";
    html.setAttribute("data-theme", isHigh ? "daylight" : "high-contrast");
    themeBtn.setAttribute("aria-pressed", String(!isHigh));
  });

  // Conmutador Tamaño de Letra Grande
  const scaleBtn = document.getElementById("btn-toggle-scale");
  scaleBtn.addEventListener("click", () => {
    const html = document.documentElement;
    const isLarge = html.getAttribute("data-scale") === "large";
    html.setAttribute("data-scale", isLarge ? "normal" : "large");
    scaleBtn.setAttribute("aria-pressed", String(!isLarge));
  });

  // Modal Simulador
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

  // Carga inicial
  fetchTelemetry();
  setInterval(fetchTelemetry, 4000);
});
