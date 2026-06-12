# API Reference

## POST /api/scan
Run the SGR graph on a payload.

## GET /api/scenarios
List preset threat scenarios.

## GET /api/policies
Retrieve current Rego policies.

## PUT /api/policies
Update Rego policies.

## GET /api/replay
List scan IDs with stored traces.

## GET /api/replay/<scan_id>
Get full forensic trace for a scan.

## GET /api/red-team
Generate synthetic adversarial payloads.

## /events
Server-Sent Events stream for live graph updates.
