# Usage Walk‑through

This guide walks you through a complete end‑to‑end run of APCS, from starting the server to observing the dashboard and replaying a forensic trace.

## 1. Install the environment
```powershell
cd "C:/Users/user/Documents/projects/Kestrel-SGR"
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```
*(If `requirements.txt` does not exist yet, create an empty one – the code only needs `jsonschema` for now.)*

## 2. Start the server
```powershell
python server.py
```
You should see something like:
```
Serving HTTP on localhost port 8080 …
```
The server will:
- expose REST endpoints under `/api/*`
- serve static files (`index.html`, `style.css`, `app.js`) from the `web/` folder
- push execution events over Server‑Sent Events (`/events`).

## 3. Open the dashboard
Open a browser and navigate to `http://localhost:8080`.  You will see the APCS cockpit with:
- **Scenario selector** (top‑left)
- **Live graph** area (center)
- **Metrics & log** panel (right)

## 4. Run a preset scenario
1. Choose **Credential Harvester** from the dropdown.
2. Click **Run**.
3. The UI will display a loading spinner while the backend processes the DAG.
4. As each skill completes, the corresponding node in the graph turns green (success) or red (failure) and the log updates.
5. When the saga finishes, the final decision (`ALLOW`/`DENY`) and risk score appear at the top of the metrics panel.

## 5. Inspect forensic replay
After the run completes, a **Replay** button becomes active.
- Click it to load the JSON trace stored by `core/replay.py`.
- Step through each node using the **Next** / **Prev** controls.  The UI highlights the node being inspected and shows its input and output payloads.

## 6. Manual verification (optional)
You can also hit the API directly with `curl`:
```bash
curl -X POST http://localhost:8080/api/scan \
     -H "Content-Type: application/json" \
     -d @samples/credential_harvester.json
```
The response contains the final decision and a URL to the replay JSON.

You can also retrieve forensic traces and generate adversarial payloads:
```bash
# List all replay scan IDs
curl http://localhost:8080/api/replay

# Get full trace for a specific scan
curl http://localhost:8080/api/replay/<scan_id>

# Generate synthetic red-team payloads
curl http://localhost:8080/api/red-team
```

## 7. Stopping the server
Press `Ctrl+C` in the terminal running `server.py`.

---

**Next steps**
- Add unit tests under `tests/` (see `TESTING.md`).
- Extend the policy set (`policies/`).
- Deploy the dashboard behind HTTPS for production use.
