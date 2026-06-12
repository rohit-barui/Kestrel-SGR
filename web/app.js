const GRAPH_NODES = [
  { id: "ingest", plane: "perception", label: "Ingest", deps: [] },
  { id: "extract_urls", plane: "perception", label: "Extract URLs", deps: ["ingest"] },
  { id: "scan_qr_codes", plane: "perception", label: "Scan QR", deps: ["ingest"] },
  { id: "extract_archive_password", plane: "perception", label: "Extract Pwd", deps: ["ingest"] },
  { id: "whois_lookup", plane: "perception", label: "WHOIS", deps: ["extract_urls"] },
  { id: "enrich_dns", plane: "perception", label: "DNS Enrich", deps: ["extract_urls"] },
  { id: "detect_typo_squatting", plane: "perception", label: "Typo Detect", deps: ["extract_urls"] },
  { id: "aggregate_risk", plane: "decision", label: "Risk Score", deps: ["extract_urls", "scan_qr_codes", "extract_archive_password", "whois_lookup", "enrich_dns", "detect_typo_squatting"] },
  { id: "apply_veto", plane: "decision", label: "Veto", deps: ["aggregate_risk"] },
  { id: "recommend_actions", plane: "decision", label: "Actions", deps: ["apply_veto"] },
  { id: "deploy_honey_credentials", plane: "dominance", label: "Honey Creds", deps: ["recommend_actions", "apply_veto"] },
  { id: "rewrite_links", plane: "dominance", label: "Rewrite Links", deps: ["recommend_actions", "extract_urls"] },
  { id: "containment_actions", plane: "dominance", label: "Containment", deps: ["recommend_actions", "apply_veto"] },
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
const confidenceEl = document.getElementById("confidence");
const actionsEl = document.getElementById("actions");
const logEntries = document.getElementById("logEntries");

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
    const res = await fetch("/api/scenarios");
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

async function runScan() {
  if (!state.selectedScenario) return;
  runBtn.disabled = true;
  statusBadge.textContent = "Running";
  statusBadge.style.background = "var(--accent-cyan)";
  resetGraph();
  log("Scan started...", "info");
  try {
    const res = await fetch("/api/scan", {
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
  const rect = document.querySelector(`.node-rect[data-id="${id}"]`);
  if (!rect) return;
  const node = GRAPH_NODES.find((n) => n.id === id);
  if (!node) return;
  const colors = PLANE_COLORS[node.plane];
  if (error) {
    rect.setAttribute("fill", "#7F1D1D");
    rect.setAttribute("stroke", "#F43F5E");
  } else if (done) {
    rect.setAttribute("fill", colors.done);
    rect.setAttribute("stroke", colors.done);
  } else {
    rect.setAttribute("fill", colors.fill);
    rect.setAttribute("stroke", colors.stroke);
  }
}

function updateAllNodeColors() {
  GRAPH_NODES.forEach((n) => {
    const status = state.nodeStatus[n.id];
    updateNodeColor(n.id, status === "done", status === "error");
  });
}

function setupSSE() {
  const evtSource = new EventSource("/events");
  evtSource.addEventListener("skill_done", (e) => {
    const data = JSON.parse(e.data);
    state.nodeStatus[data.node] = "done";
    updateNodeColor(data.node, true);
    activateEdgesForNode(data.node);
    log(`${data.node} done (confidence: ${data.confidence})`, "success");
  });
  evtSource.addEventListener("run_complete", (e) => {
    const data = JSON.parse(e.data);
    riskScoreEl.textContent = data.risk_score;
    riskScoreEl.className = "metric-value" + (data.risk_score >= 70 ? " risk-high" : data.risk_score >= 30 ? " risk-medium" : " risk-low");
    policyStatusEl.textContent = data.decision;
    policyStatusEl.style.color = data.decision === "ALLOW" ? "var(--accent-emerald)" : "var(--accent-rose)";
    confidenceEl.textContent = data.confidence + "%";
    actionsEl.textContent = data.actions.join(", ");
    if (data.dominance) {
      if (data.dominance.honey_credentials.length) log("Honey creds deployed", "action");
      if (Object.keys(data.dominance.rewritten_urls).length) log("Links rewritten to proxy", "action");
      if (data.dominance.blocked_ips.length) log("IPs blocked: " + data.dominance.blocked_ips.join(", "), "action");
      if (data.dominance.quarantined) log("Email quarantined", "action");
      if (data.dominance.mfa_reset) log("MFA reset triggered", "action");
    }
    statusBadge.textContent = data.decision;
    statusBadge.style.background = data.decision === "ALLOW" ? "var(--accent-emerald)" : "var(--accent-rose)";
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

function activateEdgesForNode(nodeId) {
  const node = GRAPH_NODES.find((n) => n.id === nodeId);
  if (!node) return;
  node.deps.forEach((dep) => {
    const edgeId = `${dep}->${nodeId}`;
    const el = document.querySelector(`.edge-line[data-id="${edgeId}"]`);
    if (el) el.classList.add("active");
  });
}

function drawGraph() {
  const svg = document.getElementById("graphSvg");
  const container = document.getElementById("graphContainer");
  const width = container.clientWidth || 600;
  const height = container.clientHeight || 400;

  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);

  const layers = [[], [], []];
  GRAPH_NODES.forEach((n) => {
    if (n.plane === "perception") layers[0].push(n);
    else if (n.plane === "decision") layers[1].push(n);
    else layers[2].push(n);
  });

  const nodePositions = {};
  const layerGap = width / 4;
  const nodeW = 120;
  const nodeH = 36;

  layers.forEach((layer, li) => {
    const cx = layerGap * (li + 1);
    const startY = (height - (layer.length * (nodeH + 20) - 20)) / 2;
    layer.forEach((node, ni) => {
      nodePositions[node.id] = { x: cx - nodeW / 2, y: startY + ni * (nodeH + 20) };
    });
  });

  GRAPH_NODES.forEach((node) => {
    node.deps.forEach((dep) => {
      const from = nodePositions[dep];
      const to = nodePositions[node.id];
      if (!from || !to) return;
      const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
      const edgeId = `${dep}->${node.id}`;
      line.setAttribute("data-id", edgeId);
      line.setAttribute("class", "edge-line");
      line.setAttribute("x1", from.x + nodeW / 2);
      line.setAttribute("y1", from.y + nodeH / 2);
      line.setAttribute("x2", to.x + nodeW / 2);
      line.setAttribute("y2", to.y + nodeH / 2);
      svg.appendChild(line);
    });
  });

  GRAPH_NODES.forEach((node) => {
    const pos = nodePositions[node.id];
    if (!pos) return;
    const colors = PLANE_COLORS[node.plane];
    const g = document.createElementNS("http://www.w3.org/2000/svg", "g");
    const rect = document.createElementNS("http://www.w3.org/2000/svg", "rect");
    rect.setAttribute("data-id", node.id);
    rect.setAttribute("class", "node-rect");
    rect.setAttribute("x", pos.x);
    rect.setAttribute("y", pos.y);
    rect.setAttribute("width", nodeW);
    rect.setAttribute("height", nodeH);
    rect.setAttribute("fill", colors.fill);
    rect.setAttribute("stroke", colors.stroke);
    g.appendChild(rect);

    const label = document.createElementNS("http://www.w3.org/2000/svg", "text");
    label.setAttribute("class", "node-label");
    label.setAttribute("x", pos.x + nodeW / 2);
    label.setAttribute("y", pos.y + nodeH / 2 + 4);
    label.setAttribute("text-anchor", "middle");
    label.setAttribute("dominant-baseline", "central");
    label.textContent = node.label;
    g.appendChild(label);

    svg.appendChild(g);
  });
}

window.addEventListener("load", () => {
  loadScenarios();
  setupSSE();
  drawGraph();
});

window.addEventListener("resize", () => {
  drawGraph();
});
