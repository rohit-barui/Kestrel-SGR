# One‑Click installer for Kestrel‑SGR
# ---------------------------------------------------
# This script performs the full local setup:
#   1. Creates a Python virtual environment in `.venv`
#   2. Installs all Python dependencies from `requirements.txt`
#   3. Starts the APCS server (`python server.py`)
#   4. Opens the dashboard in the default web browser
# ---------------------------------------------------

# Ensure script stops on any error
$ErrorActionPreference = "Stop"

# Step 1 – create virtual environment (if not present)
if (-Not (Test-Path -Path ".venv")) {
    Write‑Host "Creating virtual environment…"
    python -m venv .venv
}

# Step 2 – activate virtual environment
# NOTE: PowerShell activation uses the `Activate.ps1` script inside the venv
$env:VIRTUAL_ENV = (Resolve‑Path ".venv").Path
$activateScript = Join‑Path $env:VIRTUAL_ENV "Scripts\Activate.ps1"
if (Test‑Path $activateScript) {
    Write‑Host "Activating virtual environment…"
    & $activateScript
} else {
    throw "Activation script not found: $activateScript"
}

# Step 3 – install Python requirements
Write‑Host "Installing dependencies…"
pip install -r requirements.txt

# Step 4 – launch the server in a new background job
Write‑Host "Starting APCS server…"
Start‑Job -ScriptBlock { python server.py } | Out‑Null
Start‑Sleep -Seconds 2  # give server a moment to start

# Step 5 – open the dashboard in the default browser
$dashboardUrl = "http://localhost:8080"
Write‑Host "Opening dashboard at $dashboardUrl"
Start‑Process $dashboardUrl

Write‑Host "Setup complete. Press Ctrl+C to stop the server when you are done."
# Keep the script alive so the PowerShell session doesn’t exit immediately
while ($true) { Start‑Sleep -Seconds 60 }
