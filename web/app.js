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
  { id: "aggregate_risk", plane: "decision", label: "Risk Score", deps: ["extract_urls", "scan_qr_codes", "extract_archive_password", "whois_lookup", "enrich_dns", "detect_typo_squatting", "detonate_urls"] },
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
const actionsEl = document.getElementById("actions");
const logEntries = document.getElementById("logEntries");
const detonationArea = document.getElementById("detonationArea");
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
    // If it's not valid JSON, treat the raw text as the email content automatically
    body = { email: text };
  }

  if (!body.email && !body.sms && !body.voice) {
    log("Custom scan payload must contain 'email', 'sms', or 'voice' field", "error");
    return;
  }
  // Check for PII
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
    // PII check unavailable; proceed anyway
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

// URL / Domain Detonation
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

// File Upload Scan
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
      html += r.detonation_links.map(l => `<a class="detonation-link" href="${l}" target="_blank">&#128279; View on CyberWatch</a>`).join("");
    }
    html += '</div>';
  });

  detonationArea.innerHTML = html;
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
  confidenceEl.textContent = "-";
  actionsEl.textContent = "-";
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
      confidenceEl.textContent = data.confidence + "%";
      mlConfidenceEl.textContent = data.ml_confidence !== null ? data.ml_confidence + "%" : "-";
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
    if (data.dominance) {
      if (data.dominance.honey_credentials.length) log("Honey creds deployed", "action");
      if (Object.keys(data.dominance.rewritten_urls).length) log("Links rewritten to proxy", "action");
      if (data.dominance.blocked_ips.length) log("IPs blocked: " + data.dominance.blocked_ips.join(", "), "action");
      if (data.dominance.quarantined) log("Email quarantined", "action");
      if (data.dominance.mfa_reset) log("MFA reset triggered", "action");
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
    // analytics unavailable
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
