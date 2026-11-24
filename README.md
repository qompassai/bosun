# Bosun

Qompass AI's remote device provisioning MCP server — the boatswain
for the household fleet: one surface that inventories devices,
collects their diagnostics, and (only ever through an
operator-approved gate) installs and updates packages and reboots
them, across **Android, Windows, and iOS**. iOS is served by a real
MDM — check-in endpoint, command queue, SCEP device identity, APNs
push — not a companion subset.

Bosun is an MCP-over-stdio server on rmcp, speaking the MCP modern
era only (**2026-07-28**). Sessions open with `server/discover`;
a legacy `initialize` is refused at the stdio front door with the
typed `-32022` unsupported-version error. See `STAGE0.md` for the
current stage record: what is live, what is stubbed, and the exact
next gate.

## The domain and the surface

One domain: **device provisioning**. Nine tools in five
role-shaped groups (the trigger-scoped loading groupings):

| Group | Tools | Access |
| --- | --- | --- |
| inventory | `bosun_device_list`, `bosun_device_get`, `bosun_device_register` | reads ungated; register gated |
| diagnostics | `bosun_device_diagnostics`, `bosun_package_list` | read-only, ungated |
| packages | `bosun_package_install`, `bosun_package_update` | gated mutations |
| power | `bosun_device_reboot` | gated mutation |
| gate | `bosun_gate_check` | read-only verdict |

Every tool is annotated from birth; every input schema is an
object with an explicit `properties` key. No `outputSchema` is
published at Stage 0 — backend results carry platform output whose
shape is not yet stable, and an unenforced schema is decoration.
That departure is deliberate and closes when the backend result
shapes are pinned by the Stage 1/2 live exercises.

## The gate

Every mutation passes through `gate::decide` — a pure function
(no I/O, no clock, no ambient authority) in the phlow/ache
pattern. A mutation is allowed only when:

1. the target device **declares the capability** the action needs
   (checked first — an operator cannot approve a device into a
   capability its platform does not have), and
2. the call carries an **operator approval**
   (`operator_approval.approved_by`, non-empty).

Denials are typed (`capability_not_declared`,
`operator_approval_required`, `device_not_found`, …) and return
before the store or any backend is touched. `bosun_gate_check`
exposes the same verdict without performing the action.

Stage 0's approval is a presented object; the verified approval
channel (an operator check the server does not merely trust) is a
Stage 1 hardening item — the decision structure does not change
when it lands.

## The capability model

Capabilities are computed per device from platform + enrollment
and are served inside the device record itself:

- **Android** (ADB): diagnostics, package list/install/update,
  reboot — the full set.
- **Windows** (SSH + winget): the full set.
- **iOS** (MDM): an *unenrolled* device declares nothing. An
  *enrolled, unsupervised* device declares diagnostics and the
  installed-application query. An *enrolled, supervised* device
  additionally declares package install/update (managed apps) and
  OS update scheduling. iOS does not declare the transport-style
  reboot at Stage 0; MDM's queued `RestartDevice` joins when the
  MDM backend goes live.

## Backends at Stage 0

- **Android**: real `adb` command paths (diagnostics bundle via
  `dumpsys`/`getprop`, `pm list packages`, `install -r`,
  `reboot`), every call under a 20 s timeout and a 64 KiB output
  bound. Implemented, **not yet exercised against a live device**.
- **Windows**: real `ssh` + `winget` command paths (CIM
  diagnostics, `winget list/install/upgrade`). Same exercise
  status.
- **iOS**: the MDM command model and the bounded per-device
  command queue are real; installs enqueue and report `queued`
  with their command UUID. Reads that would need a device answer
  refuse with the typed `stage1_not_live` error rather than
  fabricating a result. Delivery — the HTTPS check-in endpoint,
  SCEP, APNs push — is Stage 1.

## Configuration

- `BOSUN_HOME`: directory holding `inventory.json`
  (default `~/.local/share/bosun`). The inventory is one bounded
  JSON file (256 KiB, 256 devices), rewritten atomically.

## The path to 1.0

- **Stage 0 (this tree)**: scaffold, capability model, gate,
  inventory, backend skeletons, the APNs push-certificate route
  and the enrollment path, both written down in `STAGE0.md`.
- **Stage 1**: the MDM protocol round-trip — push certificate
  installed (Owner portal steps, `STAGE0.md`), SCEP + check-in
  endpoint live, one real iPhone enrolled via Apple Configurator
  supervision, first `DeviceInformation` answer and first
  `InstallApplication` delivered by push + check-in. Exit gate: a
  command round-trips against the real device.
- **Stage 2**: live Android and Windows exercise against the
  Owner's devices (diagnostics first, then one gated install
  each); the verified operator-approval channel; the guard's
  ordering barrier if Stage 1 evidence asks for it.
- **Stage 3**: publication — crates.io, the MCP Registry, the
  fleet client configs, and the qompass.ai listing, under the
  fleet's per-push and publish rules.

## Citizenship

`server.json` (MCP Registry manifest) and
`.well-known/agent-card.json` (A2A capability manifest, fleet
profile D-1607) are a provisioning pair; `tests/manifest_agreement.rs`
holds their join invariant by test. Provider of record is the
studio, Qompass AI — never a personal name (D-489).
