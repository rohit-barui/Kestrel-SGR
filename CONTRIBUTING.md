# Contributing to Kestrel‑SGR

All work **must** follow the exact workflow below. The repository is configured to enforce it automatically.

## 1️⃣ Start a new task

```powershell
.\tools\start-task.ps1 -Name "<short‑description>"
```

*The script creates a branch `task/<short‑description>` from the latest `main`.*

## 2️⃣ Implement the change

- Do **all** edits, tests, documentation, and CI updates **only** on this branch.
- Run the full test suite locally (`pytest --cov`) and ensure the CI checks pass on your branch.

## 3️⃣ Request review

```powershell
git add .
git commit -m "feat: <your description>"
git push -u origin task/<short‑description>
```

Open a Pull Request against `main`.  
**Do not merge** yourself; wait for my explicit approval.

## 4️⃣ Approval & merge

I will review the PR. Once I respond with **“Approved – merge”**, you (or the maintainer) may merge the PR.

Merging will:
1. Push the final updates to `main`.
2. Delete the `task/<short‑description>` branch automatically (handled by the merge UI).

## 5️⃣ No half‑finished work

A PR that does not pass **all** CI checks (lint, tests, coverage) will be blocked from merging.
