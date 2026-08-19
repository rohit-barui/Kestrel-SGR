let apiToken = localStorage.getItem("apcs_token") || "";

function setAuthHeader() {
  return apiToken ? { "Authorization": `Bearer ${apiToken}` } : {};
}

async function apiFetch(url, options = {}) {
  const headers = { ...options.headers, ...setAuthHeader() };
  return fetch(url, { ...options, headers });
}

async function checkAuth() {
  if (!apiToken) {
    const res = await fetch("/api/scenarios");
    if (res.status === 401) {
      document.getElementById("loginOverlay").style.display = "flex";
      return false;
    }
    return true;
  }

  const res = await fetch("/api/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json", ...setAuthHeader() },
    body: JSON.stringify({ token: apiToken }),
  });
  if (!res.ok) {
    localStorage.removeItem("apcs_token");
    apiToken = "";
    document.getElementById("loginOverlay").style.display = "flex";
    return false;
  }
  return true;
}

document.getElementById("loginBtn")?.addEventListener("click", async () => {
  const token = document.getElementById("tokenInput").value;
  const res = await fetch("/api/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token }),
  });
  if (res.ok) {
    apiToken = token;
    localStorage.setItem("apcs_token", token);
    document.getElementById("loginOverlay").style.display = "none";
    loadScenarios();
    loadAnalytics();
    loadIntegrations();
  } else {
    document.getElementById("loginError").style.display = "block";
  }
});

const GRAPH_NODES = [
  { id: "ingest", plane: "perception", label: "Ingest", deps: [] },
  { id: "extract_urls", plane: "perception", label: "Extract URLs", deps: ["ingest"] },
  { id: "scan_qr_codes", plane: "perception", label: "Scan QR", deps: ["ingest"] },
  { id: "extract_archive_password", plane: "perception", label: "Extract Pwd", deps: ["ingest"] },
  { id: "whois_lookup", plane: "perception", label: "WHOIS", deps: ["extract_urls"] },
  { id: "enrich_dns", plane: "perception", label: "DNS Enrich", deps: ["extract_urls"] },
  { id: "detect_typo_squatting", plane: "perception", label: "Typo Detect", deps: ["extract_urls"] },
  { id: "extract_entities", plane: "perception", label: "Entities", deps: ["ingest"] },
  { id: "validate_spf_dkim", plane: "perception", label: "SPF/DKIM", deps: ["ingest"] },
  { id: "detonate_urls", plane: "perception", label: "Detonate", deps: ["extract_urls"] },
  { id: "check_ip_reputation", plane: "perception", label: "IP Reputation", deps: ["extract_urls"] },
  { id: "check_file_reputation", plane: "perception", label: "File Reputation", deps: ["ingest"] },
  { id: "threat_intel_lookup", plane: "perception", label: "Threat Intel", deps: ["extract_urls"] },
  { id: "owasp_analysis", plane: "perception", label: "OWASP Scan", deps: ["extract_urls", "ingest"] },
  { id: "phishing_validation", plane: "perception", label: "Phish Validate", deps: ["ingest", "validate_spf_dkim"] },
  { id: "aggregate_risk", plane: "decision", label: "Risk Score", deps: ["extract_urls", "scan_qr_codes", "extract_archive_password", "whois_lookup", "enrich_dns", "detect_typo_squatting", "detonate_urls", "check_ip_reputation", "check_file_reputation", "threat_intel_lookup", "owasp_analysis", "phishing_validation"] },
  { id: "apply_veto", plane: "decision", label: "Veto", deps: ["aggregate_risk"] },
  { id: "recommend_actions", plane: "decision", label: "Actions", deps: ["apply_veto"] },
  { id: "deploy_honey_credentials", plane: "dominance", label: "Honey Creds", deps: ["recommend_actions", "apply_veto"] },
  { id: "rewrite_links", plane: "dominance", label: "Rewrite Links", deps: ["recommend_actions", "extract_urls"] },
  { id: "containment_actions", plane: "dominance", label: "Containment", deps: ["recommend_actions", "apply_veto"] },
  { id: "block_ip", plane: "dominance", label: "Block IP", deps: ["recommend_actions"] },
  { id: "quarantine_email", plane: "dominance", label: "Quarantine Email", deps: ["recommend_actions"] },
  { id: "trigger_mfa_reset", plane: "dominance", label: "MFA Reset", deps: ["recommend_actions", "apply_veto"] },
];

const PLANE_COLORS = {
  perception: { fill: "#1E3A5F", stroke: "#3B82F6", done: "#3B82F6" },
  decision: { fill: "#5F3A1E", stroke: "#F97316", done: "#F97316" },
  dominance: { fill: "#5F1E1E", stroke: "#F43F5E", done: "#F43F5E" },
};

const state = {
  scenarios: [],
  selectedScenario: null,
  scanId: null,
  nodeStatus: {},
  edgesActive: {},
};

const selectEl = document.getElementById("scenarioSelect");
const runBtn = document.getElementById("runBtn");
const statusBadge = document.getElementById("statusBadge");
const payloadPreview = document.getElementById("payloadPreview");
const riskScoreEl = document.getElementById("riskScore");
const policyStatusEl = document.getElementById("policyStatus");
const mlConfidenceEl = document.getElementById("mlConfidence");
const logEntries = document.getElementById("logEntries");
const detonationArea = document.getElementById("detonationArea");
const enrichmentArea = document.getElementById("enrichmentArea");
const replayBtn = document.getElementById("replayBtn");
const prevBtn = document.getElementById("prevBtn");
const nextBtn = document.getElementById("nextBtn");
const replayStep = document.getElementById("replayStep");
const replayPayload = document.getElementById("replayPayload");

let replayEvents = [];
let replayIndex = -1;

function log(msg, type = "info") {
  const entry = document.createElement("div");
  entry.className = `log-entry ${type}`;
  const time = new Date().toLocaleTimeString();
  entry.innerHTML = `<span class="timestamp">${time}</span>${msg}`;
  logEntries.appendChild(entry);
  logEntries.scrollTop = logEntries.scrollHeight;
}

async function loadScenarios() {
  try {
    const res = await apiFetch("/api/scenarios");
    const data = await res.json();
    state.scenarios = data;
    data.forEach((s) => {
      const opt = document.createElement("option");
      opt.value = s.id;
      opt.textContent = s.name;
      selectEl.appendChild(opt);
    });
  } catch (e) {
    log("Failed to load scenarios", "error");
  }
}

selectEl.addEventListener("change", () => {
  const id = selectEl.value;
  const scenario = state.scenarios.find((s) => s.id === id);
  state.selectedScenario = scenario;
  runBtn.disabled = !scenario;
  if (scenario) {
    payloadPreview.textContent = JSON.stringify(scenario.payload, null, 2);
  } else {
    payloadPreview.textContent = "{ }";
  }
});

runBtn.addEventListener("click", runScan);

let pendingCustomScan = null;

document.getElementById("runCustomBtn").addEventListener("click", runCustomScan);

async function runCustomScan() {
  const textarea = document.getElementById("customScanInput");
  const text = textarea.value.trim();
  if (!text) {
    log("Please enter text to scan.", "error");
    return;
  }

  let body;
  try {
    body = JSON.parse(text);
  } catch {
    body = { email: text };
  }

  if (!body.email && !body.sms && !body.voice) {
    log("Custom scan payload must contain 'email', 'sms', or 'voice' field", "error");
    return;
  }
  try {
    const piiRes = await apiFetch("/api/check-pii", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text: body.email || body.sms || body.voice }),
    });
    const piiData = await piiRes.json();
    if (piiData.contains_pii) {
      pendingCustomScan = body;
      document.getElementById("piiOverlay").style.display = "flex";
      return;
    }
  } catch {
  }
  performCustomScan(body);
}

document.getElementById("piiProceed").addEventListener("click", () => {
  document.getElementById("piiOverlay").style.display = "none";
  if (pendingCustomScan) {
    pendingCustomScan.override_pii = true;
    performCustomScan(pendingCustomScan);
    pendingCustomScan = null;
  }
});

document.getElementById("piiCancel").addEventListener("click", () => {
  document.getElementById("piiOverlay").style.display = "none";
  pendingCustomScan = null;
});

async function performCustomScan(payload) {
  statusBadge.textContent = "Running";
  statusBadge.style.background = "var(--accent-cyan)";
  resetGraph();
  log("Custom scan started...", "info");
  try {
    const res = await apiFetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const result = await res.json();
    if (result.error) {
      log(`Error: ${result.error}`, "error");
      statusBadge.textContent = "Error";
      statusBadge.style.background = "var(--accent-rose)";
    }
  } catch (e) {
    log(`Request failed: ${e.message}`, "error");
    statusBadge.textContent = "Error";
    statusBadge.style.background = "var(--accent-rose)";
  }
}

document.getElementById("runUrlScanBtn").addEventListener("click", runUrlDetonation);

async function runUrlDetonation() {
  const input = document.getElementById("urlDomainInput");
  const raw = input.value.trim();
  if (!raw) {
    log("Please enter URLs or domains to detonate.", "error");
    return;
  }
  const items = raw.split(",").map(s => s.trim()).filter(Boolean);
  log(`Submitting ${items.length} URLs/domains for detonation...`, "info");
  statusBadge.textContent = "Detonating";
  statusBadge.style.background = "var(--accent-amber)";
  try {
    const res = await apiFetch("/api/detonate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ urls: items }),
    });
    const data = await res.json();
    if (data.error) {
      log(`Detonation error: ${data.error}`, "error");
      statusBadge.textContent = "Error";
      statusBadge.style.background = "var(--accent-rose)";
    } else {
      renderDetonationResults(data);
      log(`Detonation complete: ${data.malicious_count} malicious, ${data.suspicious_count} suspicious, ${data.safe_count} safe`, data.malicious_count > 0 ? "error" : data.suspicious_count > 0 ? "action" : "success");
      statusBadge.textContent = data.malicious_count > 0 ? "Threats Found" : "Clean";
      statusBadge.style.background = data.malicious_count > 0 ? "var(--accent-rose)" : data.suspicious_count > 0 ? "var(--accent-amber)" : "var(--accent-emerald)";
    }
  } catch (e) {
    log(`Detonation request failed: ${e.message}`, "error");
    statusBadge.textContent = "Error";
    statusBadge.style.background = "var(--accent-rose)";
  }
}

document.getElementById("runFileUploadBtn").addEventListener("click", runFileUploadScan);

async function runFileUploadScan() {
  const fileInput = document.getElementById("fileUploadInput");
  const file = fileInput.files[0];
  if (!file) {
    log("Please select a file to upload.", "error");
    return;
  }
  log(`Uploading ${file.name} for analysis...`, "info");
  statusBadge.textContent = "Uploading";
  statusBadge.style.background = "var(--accent-cyan)";
  const formData = new FormData();
  formData.append("file", file);
  try {
    const res = await fetch("/api/scan/upload", {
      method: "POST",
      headers: { "Authorization": `Bearer ${apiToken}` },
      body: formData,
    });
    const result = await res.json();
    if (result.error) {
      log(`Upload error: ${result.error}`, "error");
      statusBadge.textContent = "Error";
      statusBadge.style.background = "var(--accent-rose)";
    } else {
      log(`File uploaded: ${file.name}. Scan submitted as ${result.scan_id}`, "success");
      statusBadge.textContent = "Submitted";
      statusBadge.style.background = "var(--accent-emerald)";
    }
  } catch (e) {
    log(`Upload failed: ${e.message}`, "error");
    statusBadge.textContent = "Error";
    statusBadge.style.background = "var(--accent-rose)";
  }
  fileInput.value = "";
}

function renderDetonationResults(data) {
  if (!detonationArea) return;
  if (!data || data.total_urls === 0) {
    detonationArea.innerHTML = '<span style="color: var(--text-dim); font-size: 11px;">No results.</span>';
    return;
  }
  let html = '<div class="detonation-summary">';
  html += `<div class="detonation-stat malicious"><span class="stat-value">${data.malicious_count}</span><span class="stat-label">Malicious</span></div>`;
  html += `<div class="detonation-stat suspicious"><span class="stat-value">${data.suspicious_count}</span><span class="stat-label">Suspicious</span></div>`;
  html += `<div class="detonation-stat safe"><span class="stat-value">${data.safe_count}</span><span class="stat-label">Safe</span></div>`;
  html += `<div class="detonation-stat"><span class="stat-value" style="color: var(--accent-cyan);">${data.aggregate_score}</span><span class="stat-label">Score</span></div>`;
  html += '</div>';

  (data.results || []).forEach(r => {
    const cls = r.reputation;
    html += `<div class="detonation-url ${cls}">`;
    html += `<div><span class="url-domain">${r.domain}</span> <span style="color: var(--text-dim);">${r.score}/100</span></div>`;
    if (r.reasons && r.reasons.length) {
      html += `<div class="url-reasons">${r.reasons.join(", ")}</div>`;
    }
    if (r.detonation_links && r.detonation_links.length) {
      html += r.detonation_links.map(l => `<a class="detonation-link" href="${l}" target="_blank">View on CyberWatch</a>`).join("");
    }
    html += '</div>';
  });

  detonationArea.innerHTML = html;
}

function renderEnrichmentResults(enrichment) {
  if (!enrichmentArea) return;
  if (!enrichment || Object.keys(enrichment).length === 0) {
    enrichmentArea.innerHTML = '<span style="color: var(--text-dim); font-size: 11px;">No enrichment data.</span>';
    return;
  }
  let html = '';
  const ipRep = enrichment.ip_reputation || {};
  const fileRep = enrichment.file_reputation || {};
  const owasp = enrichment.owasp_findings || [];
  const phish = enrichment.phishing_signals || {};
  const ti = enrichment.threat_intel || [];

  const ipKeys = Object.keys(ipRep);
  if (ipKeys.length > 0) {
    html += '<div style="margin-top: 8px;"><strong>IP Reputation</strong><div class="detonation-summary">';
    ipKeys.forEach(d => {
      const info = ipRep[d];
      html += `<div class="detonation-url ${info.malicious ? 'malicious' : 'safe'}">${d}: ${info.aggregate_score}/100 (${info.malicious ? 'MALICIOUS' : 'Clean'})</div>`;
    });
    html += '</div></div>';
  }

  if (fileRep.sha256) {
    html += '<div style="margin-top: 8px;"><strong>File Reputation</strong><div class="detonation-summary">';
    html += `<div class="detonation-url ${fileRep.malicious ? 'malicious' : 'safe'}">${fileRep.sha256.slice(0,16)}... Score: ${fileRep.aggregate_score}/100</div>`;
    html += '</div></div>';
  }

  if (owasp.length > 0) {
    html += '<div style="margin-top: 8px;"><strong>OWASP Findings</strong><div class="detonation-summary">';
    owasp.slice(0,5).forEach(f => {
      html += `<div class="detonation-url ${f.severity === 'critical' || f.severity === 'high' ? 'malicious' : 'suspicious'}">[${f.severity.toUpperCase()}] ${f.name}: ${f.description}</div>`;
    });
    if (owasp.length > 5) html += `<div style="color: var(--text-dim); font-size: 11px;">...and ${owasp.length - 5} more</div>`;
    html += '</div></div>';
  }

  if (phish.brand_impersonation || phish.missing_ssl || phish.header_mismatch) {
    html += '<div style="margin-top: 8px;"><strong>Phishing Signals</strong><div class="detonation-summary">';
    if (phish.brand_impersonation) html += '<div class="detonation-url malicious">Brand impersonation detected: ' + (phish.impersonated_brands || []).join(", ") + '</div>';
    if (phish.missing_ssl) html += '<div class="detonation-url suspicious">Missing SSL on URL</div>';
    if (phish.header_mismatch) html += '<div class="detonation-url malicious">Header mismatch / SPF spoof</div>';
    html += '</div></div>';
  }

  if (ti.length > 0) {
    html += '<div style="margin-top: 8px;"><strong>Threat Intelligence IoCs</strong><div class="detonation-summary">';
    ti.slice(0,5).forEach(ioc => {
      html += `<div class="detonation-url malicious">${ioc.type.toUpperCase()}: ${ioc.value}</div>`;
    });
    html += '</div></div>';
  }

  enrichmentArea.innerHTML = html || '<span style="color: var(--text-dim); font-size: 11px;">No enrichment data.</span>';
}

async function runScan() {
  if (!state.selectedScenario) return;
  runBtn.disabled = true;
  statusBadge.textContent = "Running";
  statusBadge.style.background = "var(--accent-cyan)";
  resetGraph();
  log("Scan started...", "info");
  try {
    const res = await apiFetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(state.selectedScenario.payload),
    });
    const result = await res.json();
    if (result.error) {
      log(`Error: ${result.error}`, "error");
      statusBadge.textContent = "Error";
      statusBadge.style.background = "var(--accent-rose)";
    }
  } catch (e) {
    log(`Request failed: ${e.message}`, "error");
    statusBadge.textContent = "Error";
    statusBadge.style.background = "var(--accent-rose)";
  }
  runBtn.disabled = false;
}

function resetGraph() {
  state.nodeStatus = {};
  state.edgesActive = {};
  document.querySelectorAll(".edge-line").forEach((el) => el.classList.remove("active"));
  updateAllNodeColors();
  riskScoreEl.textContent = "-";
  riskScoreEl.className = "metric-value";
  policyStatusEl.textContent = "-";
  const confidenceEl = document.getElementById("mlConfidence");
  if (confidenceEl) confidenceEl.textContent = "-";
  const actionsEl = document.getElementById("actionsArea");
  if (actionsEl) actionsEl.innerHTML = '<span style="color: var(--text-dim); font-size: 11px;">Waiting for scan...</span>';
  if (enrichmentArea) enrichmentArea.innerHTML = '<span style="color: var(--text-dim); font-size: 11px;">Waiting for scan results...</span>';
}

function updateNodeColor(id, done = false, error = false) {
  const node = GRAPH_NODES.find((n) => n.id === id);
  if (!node) return;
  const colors = PLANE_COLORS[node.plane];
  let fill, stroke;
  if (error) {
    fill = "#7F1D1D";
    stroke = "#F43F5E";
  } else if (done) {
    fill = colors.done;
    stroke = colors.done;
  } else {
    fill = colors.fill;
    stroke = colors.stroke;
  }
  d3.select(`.node-rect[data-id="${id}"]`)
    .transition().duration(300)
    .attr("fill", fill)
    .attr("stroke", stroke);
}

function updateAllNodeColors() {
  GRAPH_NODES.forEach((n) => {
    const status = state.nodeStatus[n.id];
    updateNodeColor(n.id, status === "done", status === "error");
  });
}

function setupSSE() {
  const evtSource = new EventSource("/events?token=" + apiToken);
  evtSource.addEventListener("skill_done", (e) => {
    const data = JSON.parse(e.data);
    const isError = data.error || data.output?.error;
    state.nodeStatus[data.node] = isError ? "error" : "done";
    updateNodeColor(data.node, !isError, !!isError);
    activateEdgesForNode(data.node);
    log(`${data.node} done (confidence: ${data.confidence})`, isError ? "error" : "success");
  });
  evtSource.addEventListener("run_complete", (e) => {
    const data = JSON.parse(e.data);
      riskScoreEl.textContent = data.risk_score;
      riskScoreEl.className = "metric-value" + (data.risk_score >= 70 ? " risk-high" : data.risk_score >= 30 ? " risk-medium" : " risk-low");
      policyStatusEl.textContent = data.decision;
      policyStatusEl.style.color = data.decision === "ALLOW" ? "var(--accent-emerald)" : "var(--accent-rose)";
      const confidenceEl = document.getElementById("mlConfidence");
      if (confidenceEl) confidenceEl.textContent = data.confidence + "%";
      const actionsEl = document.getElementById("actionsArea");
      if (actionsEl) {
        actionsEl.innerHTML = "";
        data.actions.forEach(action => {
          const btn = document.createElement("button");
          btn.textContent = action;
          btn.style.marginRight = "5px";
          btn.style.padding = "4px 8px";
          btn.style.fontSize = "10px";
          btn.onclick = async () => {
            btn.disabled = true;
            await apiFetch("/api/action", { method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({action, target: state.scanId}) });
            btn.textContent = "Executed";
          };
          actionsEl.appendChild(btn);
        });
      }
    if (data.dominance) {
      if (data.dominance.honey_credentials.length) log("Honey creds deployed", "action");
      if (Object.keys(data.dominance.rewritten_urls).length) log("Links rewritten to proxy", "action");
      if (data.dominance.blocked_ips.length) log("IPs blocked: " + data.dominance.blocked_ips.join(", "), "action");
      if (data.dominance.quarantined) log("Email quarantined", "action");
      if (data.dominance.mfa_reset) log("MFA reset triggered", "action");
    }
    if (data.enrichment) {
      renderEnrichmentResults(data.enrichment);
      const ipRep = data.enrichment.ip_reputation || {};
      const fileRep = data.enrichment.file_reputation || {};
      const owasp = data.enrichment.owasp_findings || [];
      const phish = data.enrichment.phishing_signals || {};
      const ti = data.enrichment.threat_intel || [];
      if (Object.keys(ipRep).length > 0) log("IP reputation checked for " + Object.keys(ipRep).length + " domains", "info");
      if (fileRep.sha256) log("File reputation: " + (fileRep.malicious ? "MALICIOUS" : "clean"), fileRep.malicious ? "error" : "success");
      if (owasp.length > 0) log("OWASP: " + owasp.length + " findings (" + owasp.filter(f => f.severity === 'critical' || f.severity === 'high').length + " critical/high)", "action");
      if (phish.brand_impersonation) log("Phishing: brand impersonation detected", "error");
      if (ti.length > 0) log("Threat intel: " + ti.length + " IoC matches", "error");
    }
    if (data.pii_redacted) {
      log("Training Notice: PII was automatically redacted from this payload before external processing.", "action");
    }
    statusBadge.textContent = data.decision;
    statusBadge.style.background = data.decision === "ALLOW" ? "var(--accent-emerald)" : "var(--accent-rose)";
    loadAnalytics();
    replayBtn.disabled = false;
    replayEvents = [];
    replayIndex = -1;
    replayStep.textContent = "Replay ready";
    replayPayload.textContent = "{ }";
    document.getElementById("fpBtn").disabled = false;
    document.getElementById("fpBtn").textContent = "Mark as False Positive";
    log(`Run complete: ${data.decision} (risk: ${data.risk_score})`, data.decision === "ALLOW" ? "success" : "action");
  });
  evtSource.addEventListener("run_error", (e) => {
    const data = JSON.parse(e.data);
    log(`Error: ${data.error}`, "error");
    statusBadge.textContent = "Error";
    statusBadge.style.background = "var(--accent-rose)";
  });
  evtSource.addEventListener("scan_start", (e) => {
    const data = JSON.parse(e.data);
    state.scanId = data.scan_id;
  });
  evtSource.onerror = () => {
    log("SSE connection lost, reconnecting...", "error");
  };
}

replayBtn.addEventListener("click", async () => {
  if (!state.scanId) return;
  replayBtn.disabled = true;
  try {
    const res = await apiFetch(`/api/replay/${state.scanId}`);
    const data = await res.json();
    replayEvents = data.events || [];
    replayIndex = -1;
    if (replayEvents.length > 0) {
      prevBtn.disabled = false;
      nextBtn.disabled = false;
      replayStep.textContent = `0 / ${replayEvents.length}`;
      updateReplay();
    } else {
      replayStep.textContent = "No events found";
    }
  } catch (e) {
    log("Replay load failed", "error");
  }
  replayBtn.disabled = false;
});

prevBtn.addEventListener("click", () => {
  if (replayIndex > 0) {
    replayIndex--;
    updateReplay();
  }
});

nextBtn.addEventListener("click", () => {
  if (replayIndex < replayEvents.length - 1) {
    replayIndex++;
    updateReplay();
  }
});

function updateReplay() {
  if (replayIndex < 0 || replayIndex >= replayEvents.length) return;
  const evt = replayEvents[replayIndex];
  replayStep.textContent = `${replayIndex + 1} / ${replayEvents.length} - ${evt.node}`;
  replayPayload.textContent = JSON.stringify(evt.output, null, 2);
  prevBtn.disabled = replayIndex <= 0;
  nextBtn.disabled = replayIndex >= replayEvents.length - 1;
}

function activateEdgesForNode(nodeId) {
  const node = GRAPH_NODES.find((n) => n.id === nodeId);
  if (!node) return;
  node.deps.forEach((dep) => {
    const edgeId = `${dep}->${nodeId}`;
    const el = document.querySelector(`.edge-line[data-id="${edgeId}"]`);
    if (el) el.classList.add("active");
  });
}

async function loadAnalytics() {
  try {
    const [statsRes, trendRes] = await Promise.all([
      apiFetch("/api/stats"),
      apiFetch("/api/trend"),
    ]);
    const stats = await statsRes.json();
    const trend = await trendRes.json();
    renderStats(stats);
    renderTrendChart(trend);
    renderAlertHistory(trend);
  } catch (e) {
  }
}

function renderStats(stats) {
  document.getElementById("totalScans").textContent = stats.total_scans;
  document.getElementById("avgRisk").textContent = stats.avg_risk;
  const total = stats.allow_count + stats.deny_count;
  document.getElementById("allowRate").textContent = total > 0 ? Math.round(stats.allow_count / total * 100) + "%" : "-";
  document.getElementById("blockRate").textContent = total > 0 ? Math.round(stats.deny_count / total * 100) + "%" : "-";
}

function renderTrendChart(trend) {
  const svg = document.getElementById("trendSvg");
  if (!svg || trend.length === 0) return;
  const width = svg.clientWidth || 400;
  const height = 120;
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);

  const maxRisk = Math.max(...trend.map(t => t.risk_score), 1);
  const barWidth = Math.max(4, (width - 20) / trend.length - 2);

  svg.innerHTML = "";
  trend.forEach((t, i) => {
    const bar = document.createElementNS("http://www.w3.org/2000/svg", "rect");
    const barH = (t.risk_score / maxRisk) * (height - 20);
    const x = 10 + i * (barWidth + 2);
    const y = height - 10 - barH;
    bar.setAttribute("x", x);
    bar.setAttribute("y", y);
    bar.setAttribute("width", barWidth);
    bar.setAttribute("height", barH);
    bar.setAttribute("class", "bar" + (t.risk_score >= 70 ? " risk-high" : t.risk_score >= 30 ? " risk-medium" : ""));
    svg.appendChild(bar);
  });
}

function renderAlertHistory(trend) {
  const alerts = document.getElementById("alertList");
  if (!alerts) return;
  const highRisk = trend.filter(t => t.risk_score >= 30).slice(-10).reverse();
  alerts.innerHTML = highRisk.map(t => {
    const level = t.risk_score >= 70 ? "high" : "medium";
    return `<div class="alert-entry"><span class="risk-badge ${level}">${t.risk_score}</span>${t.decision} (${t.scan_id.slice(0,8)})</div>`;
  }).join("");
}

function drawGraph() {
  const svg = d3.select("#graphSvg");
  const container = document.getElementById("graphContainer");
  const width = container.clientWidth || 600;
  const height = container.clientHeight || 400;

  svg.attr("viewBox", `0 0 ${width} ${height}`);

  const links = [];
  GRAPH_NODES.forEach((node) => {
    node.deps.forEach((dep) => {
      links.push({ source: dep, target: node.id, id: `${dep}->${node.id}` });
    });
  });

  const nodes = GRAPH_NODES.map((n) => ({ ...n }));

  svg.selectAll("g.graph-group").remove();
  const g = svg.append("g").attr("class", "graph-group");

  const zoom = d3.zoom()
    .scaleExtent([0.3, 3])
    .on("zoom", (event) => {
      g.attr("transform", event.transform);
    });
  svg.call(zoom);

  const simulation = d3.forceSimulation(nodes)
    .force("link", d3.forceLink(links).id((d) => d.id).distance(180))
    .force("charge", d3.forceManyBody().strength(-400))
    .force("center", d3.forceCenter(width / 2, height / 2))
    .force("x", d3.forceX(width / 2).strength(0.05))
    .force("y", d3.forceY(height / 2).strength(0.05));

  const link = g.append("g")
    .selectAll("line")
    .data(links)
    .join("line")
    .attr("data-id", (d) => d.id)
    .attr("class", "edge-line");

  const nodeGroup = g.append("g")
    .selectAll("g")
    .data(nodes)
    .join("g")
    .call(d3.drag()
      .on("start", (event, d) => {
        if (!event.active) simulation.alphaTarget(0.3).restart();
        d.fx = d.x;
        d.fy = d.y;
      })
      .on("drag", (event, d) => {
        d.fx = event.x;
        d.fy = event.y;
      })
      .on("end", (event, d) => {
        if (!event.active) simulation.alphaTarget(0);
        d.fx = null;
        d.fy = null;
      }));

  nodeGroup.append("rect")
    .attr("data-id", (d) => d.id)
    .attr("class", "node-rect")
    .attr("width", 120)
    .attr("height", 36)
    .attr("x", -60)
    .attr("y", -18)
    .attr("rx", 8)
    .attr("ry", 8)
    .attr("fill", (d) => PLANE_COLORS[d.plane].fill)
    .attr("stroke", (d) => PLANE_COLORS[d.plane].stroke)
    .attr("stroke-width", 2);

  nodeGroup.append("text")
    .attr("class", "node-label")
    .attr("text-anchor", "middle")
    .attr("dominant-baseline", "central")
    .attr("dy", 4)
    .text((d) => d.label);

  simulation.on("tick", () => {
    link
      .attr("x1", (d) => d.source.x)
      .attr("y1", (d) => d.source.y)
      .attr("x2", (d) => d.target.x)
      .attr("y2", (d) => d.target.y);
    nodeGroup
      .attr("transform", (d) => `translate(${d.x},${d.y})`);
  });

  window.__simulation = simulation;
}

document.getElementById("exportCsvBtn").addEventListener("click", async () => {
  const res = await apiFetch("/api/export/csv");
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "apcs_export.csv";
  a.click();
  URL.revokeObjectURL(url);
});

document.getElementById("exportReportBtn").addEventListener("click", async () => {
  const res = await apiFetch("/api/export/report");
  const text = await res.text();
  const output = document.getElementById("exportOutput");
  output.textContent = text;
  output.style.display = "block";
});

document.getElementById("sendWebhookBtn")?.addEventListener("click", async () => {
  const eventType = document.getElementById("webhookEvent").value;
  let payload;
  try {
    payload = JSON.parse(document.getElementById("webhookPayload").value);
  } catch {
    document.getElementById("webhookResult").textContent = "Invalid JSON payload";
    return;
  }
  payload.event = eventType;
  const res = await fetch("/api/webhook", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const result = await res.json();
  document.getElementById("webhookResult").textContent = JSON.stringify(result, null, 2);
});

// ===================== REPUTATION TAB =====================
document.getElementById("ipRepBtn")?.addEventListener("click", async () => {
  const input = document.getElementById("ipRepInput");
  const raw = input.value.trim();
  if (!raw) return;
  const ips = raw.split(",").map(s => s.trim()).filter(Boolean);
  try {
    const res = await apiFetch("/api/reputation/ip", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ips }),
    });
    const data = await res.json();
    const el = document.getElementById("ipRepResults");
    let html = '<div class="detonation-summary">';
    (data.ip_reputation ? Object.entries(data.ip_reputation) : []).forEach(([domain, info]) => {
      const cls = info.malicious ? "malicious" : "safe";
      html += `<div class="detonation-url ${cls}">${domain}: ${info.aggregate_score}/100 (${info.malicious ? 'MALICIOUS' : 'Clean'})</div>`;
    });
    html += '</div>';
    el.innerHTML = html;
  } catch(e) {}
});

document.getElementById("fileRepBtn")?.addEventListener("click", async () => {
  const hashInput = document.getElementById("fileHashInput");
  const hash = hashInput.value.trim();
  if (!hash) return;
  try {
    const res = await apiFetch("/api/reputation/file", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ hash }),
    });
    const data = await res.json();
    const el = document.getElementById("fileRepResults");
    const fr = data.file_reputation || {};
    const cls = fr.malicious ? "malicious" : "safe";
    el.innerHTML = `<div class="detonation-url ${cls}">${fr.sha256 || hash}<br>Score: ${fr.aggregate_score}/100<br>${fr.malicious ? 'MALICIOUS' : 'Clean'}</div>`;
  } catch(e) {}
});

document.getElementById("owaspScanBtn")?.addEventListener("click", async () => {
  const urlInput = document.getElementById("owaspUrlInput");
  const contentInput = document.getElementById("owaspContentInput");
  const url = urlInput.value.trim();
  const content = contentInput.value.trim();
  if (!url && !content) return;
  try {
    const res = await apiFetch("/api/owasp/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, content }),
    });
    const data = await res.json();
    const el = document.getElementById("owaspResults");
    const findings = data.owasp_findings || [];
    const bySev = data.by_severity || {};
    let html = `<div class="detonation-summary">Critical: ${bySev.critical || 0} | High: ${bySev.high || 0} | Medium: ${bySev.medium || 0} | Low: ${bySev.low || 0}</div>`;
    findings.slice(0,10).forEach(f => {
      const cls = f.severity === "critical" || f.severity === "high" ? "malicious" : "suspicious";
      html += `<div class="detonation-url ${cls}">[${f.severity.toUpperCase()}] ${f.name}<br><span style="font-size: 10px; color: var(--text-dim);">${f.description}</span></div>`;
    });
    el.innerHTML = html || '<span style="color: var(--text-dim);">No OWASP findings.</span>';
  } catch(e) {}
});

// ===================== PHISHING REPORTS TAB =====================
document.getElementById("phishReportBtn")?.addEventListener("click", async () => {
  const email = document.getElementById("phishReportEmail").value.trim();
  const reporter = document.getElementById("phishReporter").value.trim();
  const autoRemediate = document.getElementById("phishAutoRemediate").checked;
  if (!email) {
    document.getElementById("phishResults").innerHTML = '<span style="color: var(--accent-rose);">Please enter the reported email content.</span>';
    return;
  }
  const btn = document.getElementById("phishReportBtn");
  btn.disabled = true;
  btn.textContent = "Validating...";
  try {
    const res = await apiFetch("/api/report/phishing", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, reporter, auto_remediate: autoRemediate }),
    });
    const data = await res.json();
    document.getElementById("phishResults").innerHTML =
      `<div class="detonation-summary">
        <div>Scan ID: ${data.scan_id}</div>
        <div>Decision: <strong style="color: ${data.decision === 'ALLOW' ? 'var(--accent-emerald)' : 'var(--accent-rose)'}">${data.decision}</strong></div>
        <div>Risk Score: ${data.risk_score}/100</div>
        ${data.enrichment && data.enrichment.phishing_signals ? 
          '<div style="margin-top: 8px;">Phishing Signals: ' + 
          (data.enrichment.phishing_signals.brand_impersonation ? 'Brand Impersonation, ' : '') +
          (data.enrichment.phishing_signals.missing_ssl ? 'Missing SSL, ' : '') +
          (data.enrichment.phishing_signals.header_mismatch ? 'Header Mismatch' : '') +
          '</div>' : ''}
      </div>`;
    log(`Phishing report submitted: ${data.scan_id} (${data.decision})`, data.decision === "ALLOW" ? "success" : "error");
    const history = document.getElementById("phishHistory");
    const entry = document.createElement("div");
    entry.className = "alert-entry";
    entry.innerHTML = `<span class="risk-badge ${data.risk_score >= 70 ? 'high' : 'medium'}">${data.risk_score}</span>${data.decision} (${data.scan_id})`;
    history.prepend(entry);
    document.getElementById("phishReportEmail").value = "";
    document.getElementById("phishReporter").value = "";
  } catch(e) {
    document.getElementById("phishResults").innerHTML = `<span style="color: var(--accent-rose);">Error: ${e.message}</span>`;
  }
  btn.disabled = false;
  btn.textContent = "Validate & Respond";
});

window.addEventListener("load", async () => {
  const authed = await checkAuth();
  if (!authed) return;
  loadScenarios();
  setupSSE();
  drawGraph();
  loadAnalytics();
  loadIntegrations();
});

window.addEventListener("resize", () => {
  drawGraph();
});

// Tab Switching
document.querySelectorAll(".tab-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById(btn.dataset.target).classList.add("active");
  });
});

// Integrations
async function loadIntegrations() {
  try {
    const res = await apiFetch("/api/integrations");
    if (res.ok) {
      const data = await res.json();
      const c = data.config || {};
      document.getElementById("splunkToken").value = c.splunk_token || "";
      document.getElementById("splunkUrl").value = c.splunk_url || "";
      document.getElementById("sentinelWorkspace").value = c.sentinel_workspace || "";
      document.getElementById("secopsKey").value = c.secops_key || "";
      document.getElementById("vtApiKey").value = c.vt_api_key || "";
      document.getElementById("abuseipdbKey").value = c.abuseipdb_api_key || "";
      document.getElementById("otxApiKey").value = c.otx_api_key || "";
      document.getElementById("defenderTenantId").value = c.defender_tenant_id || "";
      document.getElementById("defenderClientId").value = c.defender_client_id || "";
      document.getElementById("defenderClientSecret").value = c.defender_client_secret || "";
      document.getElementById("ciscoEsaHost").value = c.cisco_esa_host || "";
      document.getElementById("ciscoEsaKey").value = c.cisco_esa_key || "";
      document.getElementById("adminEmail").value = c.admin_email || "";
      document.getElementById("slackWebhook").value = c.slack_webhook || "";
      document.getElementById("actionWebhook").value = c.action_webhook || "";
    }
  } catch(e) {}
}

document.getElementById("saveIntegrationsBtn")?.addEventListener("click", async () => {
  const config = {
    splunk_token: document.getElementById("splunkToken").value,
    splunk_url: document.getElementById("splunkUrl").value,
    sentinel_workspace: document.getElementById("sentinelWorkspace").value,
    secops_key: document.getElementById("secopsKey").value,
    vt_api_key: document.getElementById("vtApiKey").value,
    abuseipdb_api_key: document.getElementById("abuseipdbKey").value,
    otx_api_key: document.getElementById("otxApiKey").value,
    defender_tenant_id: document.getElementById("defenderTenantId").value,
    defender_client_id: document.getElementById("defenderClientId").value,
    defender_client_secret: document.getElementById("defenderClientSecret").value,
    cisco_esa_host: document.getElementById("ciscoEsaHost").value,
    cisco_esa_key: document.getElementById("ciscoEsaKey").value,
    admin_email: document.getElementById("adminEmail").value,
    slack_webhook: document.getElementById("slackWebhook").value,
    action_webhook: document.getElementById("actionWebhook").value,
  };
  try {
    const res = await apiFetch("/api/integrations", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ config })
    });
    if (res.ok) {
      const toast = document.getElementById("toast");
      toast.classList.add("show");
      setTimeout(() => toast.classList.remove("show"), 3000);
    } else if (res.status === 403) {
      alert("Unauthorized: Admin role required to save integrations.");
    }
  } catch(e) {}
});

document.getElementById("fpBtn")?.addEventListener("click", async () => {
  if (!state.scanId) return;
  await apiFetch("/api/analytics/quality", { method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({scan_id: state.scanId}) });
  document.getElementById("fpBtn").textContent = "Reported";
  document.getElementById("fpBtn").disabled = true;
});