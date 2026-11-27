# Changelog

## 0.1.3 — 2026-11-27

Patch: publish-metadata correction — the crates.io publish wire format
carries the README text itself in the metadata `readme` field; 0.1.2
sent the filename, so crates.io served a 17-byte readme and the MCP
Registry's mcp-name ownership validation still could not pass.
No code changes.

## 0.1.2 — 2026-11-27

Patch: declares `readme = "README.md"` in the manifest so crates.io
serves the README (0.1.1's publish metadata omitted it, so the MCP
Registry's ownership validation could not see the mcp-name marker).
No code changes.

## 0.1.1 — 2026-11-27

Patch: adds the `mcp-name: ai.qompass/bosun` ownership marker to the
README, which the MCP Registry requires to validate the crates.io
package against this server name. No code changes.

## 0.1.0 — 2026-11-27

First release. Remote device provisioning MCP: device inventory and
diagnostics for Android, Windows, and iOS, operator-gated package
install/update and reboot, and a full MDM for iOS — 12 tools in 6 groups.
Stage 1 gate: simulated-device end-to-end (enroll, push wake,
DeviceInformation, InstallApplication, adversarial refusals), 20/20
(STAGE1.md). Published to crates.io and the MCP Registry as the first
release at the tree's own 0.1.0 lineage: the build programme is staged
(Stage 1 of record), so a 1.0.0 claim would overstate maturity.
