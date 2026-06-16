<#
.SYNOPSIS
    Starts a new task by creating a git branch.
.PARAMETER Name
    Short, hyphen‑separated description of the task (e.g. "add-ci-coverage").
#>
param(
    [Parameter(Mandatory=$true)][string]$Name
)

# Ensure we are on main and up‑to‑date
git checkout main
if ($LASTEXITCODE -ne 0) { throw "Failed to checkout main" }
git pull
if ($LASTEXITCODE -ne 0) { throw "Failed to pull latest main" }

# Create and switch to the new branch
$branch = "task/$Name"
git checkout -b $branch
if ($LASTEXITCODE -ne 0) { throw "Failed to create branch $branch" }

Write-Host "✅  New branch created and checked out: $branch"
