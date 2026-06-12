# Web UI Guide

The dashboard is a static single‑page application served by `server.py`.  It provides a visual console for operators to trigger threat scenarios, watch the Skill Graph execution in real time, and inspect forensic replay data.

## Directory Layout (`web/`)
- **index.html** – Entry point; loads `style.css` and `app.js`.
- **style.css** – Dark‑mode glass‑morphic design system.  Primary colors: `#0B0C10` (background), `rgba(20,24,33,0.7)` (panels), cyan/emerald accents for safe paths, amber/rose for alerts.
- **app.js** – JavaScript that:
  1. Fetches the list of scenarios (`GET /api/scenarios`).
  2. Sends a scan request (`POST /api/scan`).
  3. Subscribes to Server‑Sent Events (`/events`) emitted by `server.py` to receive node‑execution updates.
  4. Renders the DAG using the D3.js library (included via CDN).
  5. Updates metrics panels (Risk Score, Policy Status, Confidence, Active Containment Actions).

## Key UI Sections
- **Scenario Selector** – Dropdown with four preset scenarios (CEO Fraud, Credential Harvester, Malware Drop, Clean Alert).  Selecting a scenario auto‑populates the request payload.
- **Live Graph** – Nodes are colour‑coded by plane (Perception = blue, Decision = orange, Dominance = red).  Edges animate when data flows between nodes.
- **Metrics Panel** – Shows the aggregated risk score, policy decision (`ALLOW`/`DENY`), and confidence percentage.
- **Forensics / Replay** – After a run completes, a timeline view lets the operator step through each skill’s input/output JSON.
- **Action Log** – Real‑time log of side‑effects (IP blocks, honey‑cred deployments, quarantines).

## Interaction Flow
1. Operator selects a scenario and clicks **Run**.
2. `app.js` sends the payload to `/api/scan`.
3. `server.py` creates a new saga, registers side‑effects with `gateway`, and starts `engine.run()`.
4. As each skill finishes, the engine emits an SSE event (`skill_done`) containing:
   ```json
   {"node": "extract_urls", "output": {...}, "confidence": 85}
   ```
5. The UI updates the graph node colour (green for success, red for failure) and appends the output to the metrics panel.
6. Once the saga finishes, the server sends a final `run_complete` event with the overall decision and a link to the replay JSON stored by `replay.py`.

## Extending the UI
- **Add a new scenario** – Append a JSON definition to `static/scenarios.json` and update `app.js` to render the new entry.
- **Custom styling** – Modify `style.css`; the UI uses CSS variables (`--bg`, `--panel`, `--accent-success`, `--accent-failure`).
- **Backend API changes** – Ensure the new endpoint follows the same SSE contract; otherwise update the event handling code in `app.js`.

---

The UI intentionally avoids heavy client‑side logic; all heavy lifting remains in the Python backend, keeping the dashboard responsive even on modest machines.
