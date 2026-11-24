# Bosun — Stage 0 record (2026-11-24)

Stage 0 scope: the APNs push-certificate spike, the enrollment
path write-up, and the gated scaffold. **Nothing in this stage
enrolled a device, mutated a device, pushed to GitHub, or handled
a credential.** The server was renamed during this stage from the
working name *quartermaster* to **bosun** on the Owner's ruling
(repo `qompassai/bosun`, crate `bosun`); the rename is recorded
here so the working name in early notes is not a mystery later.

## 1. The APNs MDM push certificate — the critical path

**Bottom line:** there is no route to this certificate from Apple
alone with a plain CSR. The file uploaded to Apple's portal must
first be **signed by an MDM vendor's "MDM Vendor CSR signing"
certificate**. A self-hoster has three live routes (A–C below),
one dead route (D), and one eligibility caveat that gates all of
them.

### 1.1 What the portal actually does

- Issuing site: the **Apple Push Certificates Portal**,
  `https://identity.apple.com/pushcert/`. Sign in, **Create a
  Certificate**, accept the terms, upload the *vendor-signed
  request bundle* (in MicroMDM tooling,
  `PushCertificateRequest.plist` — a base64 plist holding the push
  CSR, the vendor certificate chain, and an RSA signature over the
  CSR made with the vendor certificate's private key), then
  **Download** the `.pem`.
- The download is named for the *signing vendor* (e.g.
  `MDM_ <Vendor>_Certificate.pem`). The matching private key is
  the one generated locally with the push CSR; it never leaves
  the Owner's infrastructure — Apple and the vendor only ever see
  the CSR. Lose the key and the `.pem` is useless.
- The certificate's Subject UID is the push **topic**,
  `com.apple.mgmt.External.<UUID>`. It must match the `Topic` in
  the MDM enrollment profile exactly. MDM push is **production
  APNs only**; there is no sandbox MDM.
- Lifetime **365 days**. Renewal rules, all three load-bearing:
  (1) sign in with the **same Apple ID** that created the
  certificate; (2) click **Renew**, never Create; (3) upload a
  fresh vendor-signed request (a new key is fine). Renewal
  preserves the topic. A topic change — creating instead of
  renewing, or renewing under a different Apple ID — breaks push
  to **every** enrolled device and forces re-enrollment of all of
  them. Use the portal's Notes field to name the server each
  certificate belongs to.

### 1.2 Eligibility caveat (read before choosing a route)

Apple's developer agreements exclude individual/personal use of
MDM push certificates; the routes below are for **legally
recognized businesses, institutions, and organizations**. Bosun's
operator is Qompass AI (Amor Fati Labs LLC), so the routes are
available — but the certificate must be taken out under the
organization, with an organization-controlled Apple ID, not a
personal one.

### 1.3 The routes

- **Route A — own vendor certificate (the production route).**
  Enroll in the Apple Developer Program (standard program,
  **US$99/yr**, now suffices — the older claim that the
  US$299/yr Enterprise Program is required is outdated). The
  **Account Holder** contacts Apple to request the **MDM Vendor
  CSR signing certificate** ("available by request"). With it,
  vendor-signing is done in-house forever:
  `mdmctl mdmcert vendor` (vendor CSR → portal → `mdm.cer`),
  `mdmctl mdmcert push` (push CSR), `mdmctl mdmcert vendor -sign`
  (produce the portal upload). Not beholden to any third party at
  renewal. **This is the recommended route for bosun.**
- **Route B — mdmcert.download (free community signing).**
  A community service (operating since 2016) that vendor-signs
  push CSRs for open-source MDM — it names NanoMDM and MicroMDM
  explicitly. Free. Its own terms: organizations only, intended
  for development/testing/getting started, and Apple could revoke
  the signing certificate (and with it, downstream push certs) at
  any time. Suitable to stand Stage 1 up quickly; not the
  production answer.
- **Route C — commercial vendor signing.** Commercial MDMs
  vendor-sign for their own customers, which produces a cert for
  *that* deployment — not a general route. The one documented
  standalone example, Twocanoes MDS support, is **closed to new
  buyers**. Treat Route C as unavailable.
- **Route D — DEAD.** Extracting a push cert from macOS Server /
  Profile Manager: Apple discontinued macOS Server in 2022;
  Profile Manager could not create/renew push certs after
  2024-10-29 and could not send pushes after 2025-04-14. Do not
  plan around it.

### 1.4 Who does what (the Owner-action list)

Owner-only (cannot be delegated, by Apple's design):

1. Choose and control the durable organization Apple ID that will
   own the certificate — sign-in and two-factor are the Owner's,
   and the same account is required at **every annual renewal**.
2. Route A: Developer Program enrollment, payment, and identity
   verification; and, **as Account Holder**, contacting Apple to
   request the MDM Vendor CSR signing certificate.
   Route B (if used to start): mdmcert.download registration and
   the organization attestation.
3. In the Push Certificates Portal: accept the terms, click
   Create (later: Renew), upload the signed request, download the
   `.pem`.

Assistant-preparable in advance (no Apple account needed):

1. Stand up the MDM server, SCEP, and public HTTPS (Stage 1).
2. Generate the push private key + CSR; guard the key.
3. Perform the vendor-signing step once the Owner's vendor cert
   exists (Route A) — producing `PushCertificateRequest.plist`
   for the Owner's portal upload.
4. After the Owner downloads the `.pem`: verify topic + expiry
   (`openssl x509`), install cert+key into the server, build the
   enrollment profile with that exact topic.
5. Record Apple ID used, topic, expiry, signing route; set the
   renewal reminder ≥ 30 days before expiry.

**Blocker statement:** the certificate cannot exist until the
Owner performs the Route A (or B) steps above. Everything else in
Stage 1 is buildable before that; the MDM round-trip is not.

## 2. Enrollment path for the Owner's existing iPhone(s)

Researched against Apple's deployment documentation (sources in
the Stage 0 report). Four facts govern everything:

1. **Supervision on a phone already in hand is never an in-place
   upgrade.** Every supervised route erases the device and goes
   back through Setup Assistant. There is no exception.
2. **A Mac is not required.** Apple Configurator for Mac does
   require a Mac (current release: macOS 15.7+), but **Apple
   Configurator for iPhone** — running on a *second* iPhone or
   iPad (iOS 16+) — can add a target iPhone to Apple Business
   Manager, after which it enrolls via ADE, supervised. That is
   the no-Mac supervised route. The target must be erased and
   sitting at the "Choose a Wi-Fi Network" Setup Assistant pane
   (iOS 16+); pairing is by proximity (scan the pairing image or
   a six-digit code).
3. **The 30-day provisional window is real and one-sided.** Any
   iPhone added to ABM by Configurator (either app) is
   provisional for 30 days **from assignment + enrollment** (not
   from pairing). During the window the device shows a banner,
   and its holder can tap **Leave Remote Management**
   (Settings > General > VPN & Device Management) — one action
   that removes ABM registration, supervision, and the MDM
   together. The admin cannot disable this during the window;
   all management otherwise works normally, it is simply
   revocable. After day 30 the control disappears, and the ADE
   profile's `is_mdm_removable = false` (settable only on
   supervised devices) locks the enrollment. Re-adding a released
   device restarts the clock.
4. **"Zero-touch" starts after the conversion, not at it.** For
   an already-owned phone, zero-touch can only mean: erase once,
   add via Configurator, assign — and *every subsequent* setup
   (including after any future wipe) is hands-off ADE. True
   never-touched zero-touch exists only for devices purchased
   through Apple / an authorized reseller into the ABM account.
   Nothing about the current setup, accounts, or data is
   preserved by the enrollment mechanism itself.

### The recommended path for the Owner's iPhone

1. Back up anything that must survive; sign out of iCloud and
   turn off Find My; erase the phone.
2. From a second iPhone with Apple Configurator (signed in with
   a Managed Apple Account holding a device-management role),
   add the erased phone to ABM at its Wi-Fi pane.
3. In ABM, assign the device to bosun's MDM service (bosun must
   be linked as a device management service, with the §1 push
   certificate installed). Do not walk the phone through Setup
   Assistant before assigning it.
4. Boot the phone: it fetches its ADE assignment, shows the
   Remote Management pane, and enrolls supervised into bosun.
5. Treat the enrollment as provisional until day 30 lapses;
   the ADE profile sets `is_mdm_removable = false`.

If a Mac is available, Configurator for Mac does the same job
over USB and additionally offers manual supervision *without*
ABM (no ADE, no 30-day window — but also no ADE re-enrollment
after a future erase; the ABM route is strictly better for a
device that stays in the fleet).

### The no-erase interim (weaker, and honestly labelled)

If the phone must be managed before an erase is acceptable:
**account-driven Device Enrollment** (iOS 17+) — no erase, no
Mac, no ABM — gives an *unsupervised* enrollment: serial and app
inventory, managed-app installs (prompted, via the user's Apple
Account — never silent), remote erase/lock, declarative OS
update enforcement. The user can remove it at any time, and no
supervised restriction applies. Account-driven **User
Enrollment** (iOS 15+) is weaker still and is the only route
Apple designed for a genuinely personal BYOD phone: no serial /
UDID visibility, no wipe, managed-data-only removal. Bosun's
capability model already prices this in — an unsupervised iOS
device declares diagnostics + package list only — with one
recorded refinement for Stage 1: unsupervised *device*
enrollment's prompted (non-silent) installs can be declared as
a distinct capability when the MDM backend goes live; Stage 0
keeps the conservative floor.

## 3. Scaffold state

Tree: Rust workspace (single crate `bosun` 0.1.0, edition 2024,
rmcp =3.8.0 fleet pin, modern era only), in the primo staging
tree `~/bosun-stage0/` with a mirror copy on hatch at
`~/workspace/bosun-stage0-20261124/tree/`. **Placement note:**
the GitHub repo exists (`qompassai/bosun`, renamed via the API
from the initially created `qompassai/quartermaster`), but the
scaffold is **not yet in the primo local mirror**
`~/.GH/Qompass/bosun` and **not committed or pushed** — see the
Stage 0 report for why (an execution-risk flag on the first
clone) and what clears it.

What is real:

- **Server**: rmcp stdio server behind an era guard —
  `server/discover` answers (era 2026-07-28, bosun 0.1.0),
  legacy `initialize` refused with typed `-32022`, clean exit on
  stdin EOF (the guard shuts the duplex write side down at EOF;
  a bare drop deadlocks against the pump's read half — found by
  the live probe, fixed, re-probed).
- **Catalog**: 9 tools in 5 groups (inventory, diagnostics,
  packages, power, gate), every input schema an object with
  explicit `properties`, every tool annotated from birth,
  declared access matching kind in both directions (tested).
  Served `tools/list` payload ≈ 1,436 tokens (budget 2,500).
  No `outputSchema` yet — backend shapes are not stable enough
  to enforce; the departure and reason are in the README.
- **Capability model** (`src/capability.rs`): per-device
  capabilities computed from platform + iOS enrollment state,
  served inside the device record and enforced by dispatch.
  iOS: unenrolled → none; enrolled-unsupervised → diagnostics +
  package list; enrolled-supervised → + install/update + OS
  update scheduling. iOS does not declare the transport reboot
  at Stage 0.
- **Gate** (`src/gate.rs`): pure `decide()`; capability checked
  before approval; typed denial codes; an allow names its
  approver in the verdict JSON. `bosun_gate_check` exposes the
  verdict without acting.
- **Store** (`src/store.rs`): bounded JSON inventory
  (256 KiB / 256 devices), atomic write-then-rename, corruption
  is an error, never a silent reset.
- **Android backend**: real `adb` command paths (diagnostics
  bundle, `pm list`, `install -r`, `reboot`), 20 s timeout and
  64 KiB output bounds, argv-only (never a shell). **Implemented,
  not yet exercised against a live device** — Stage 0 made no
  device contact.
- **Windows backend**: real `ssh` + `winget` command paths
  (CIM diagnostics, list/install/upgrade/upgrade --all, reboot).
  Same exercise status.
- **iOS backend**: the MDM command vocabulary, supervision
  requirements in code, and the bounded FIFO command queue are
  real; installs enqueue and report `queued` + command UUID.
  Reads refuse with typed `stage1_not_live` — nothing fabricates
  a device answer before the check-in endpoint exists.
- **Citizenship**: `server.json` (`ai.qompass/bosun`, title
  Bosun, 0.1.0) and `.well-known/agent-card.json` (fleet profile:
  one MCP-binding interface, registryName join, no
  `stateTransitionHistory`), held together by
  `tests/manifest_agreement.rs`.

Gates, all run on primo against this tree (2026-11-24):

- `cargo build` — clean. `cargo clippy --all-targets` — **0
  warnings**. `cargo fmt --check` — clean.
- `cargo test` — **35 passed, 0 failed** (34 unit + 1 manifest
  agreement; validation and adversarial cases both: approval
  cannot create a capability, capability precedes approval,
  corrupt inventory errors, duplicate ids refuse, queue bound
  holds, catalog invariants hold).
- Live probe of the built binary (`probe.py`) — **14/14**:
  discover shape and era, 9 annotated tools, `-32022` refusal,
  empty-inventory list, gate denial without device, gated
  register with approval, gate denial of an unapproved install,
  list-after-register, clean EOF exit.
- Agent card: validates against the official A2A JSON Schema
  (0 errors); the deliberately broken positive control (empty
  `supportedInterfaces` + `stateTransitionHistory`) is rejected,
  so the validation is not vacuous; structural checks pass.
- Theodolite (bridge, bacon-ls route, producer-first per the
  Rust-route cure): **0 diagnostics on all 10 source files**,
  with the positive control live — a seeded E0308 appended to
  `src/mdm.rs` produced 2 error diagnostics through the bridge,
  and the file was restored byte-identical (sha256 verified).

## 4. The Stage 1 gate

Stage 1 is the **MDM protocol round-trip against a real
enrolled iPhone**:

1. Owner completes the §1.4 certificate steps (Route A
   recommended; Route B acceptable to start). Assistant installs
   cert+key and verifies the topic.
2. Assistant builds: SCEP enrollment of device identity certs,
   the HTTPS check-in endpoint (Authenticate / TokenUpdate /
   Checkout), the server endpoint that serves the next queued
   command on a push wake-up, and APNs push over HTTP/2.
3. Owner enrolls one iPhone via the §2 path (Configurator
   supervision; the 30-day window and its terms understood
   before anyone taps anything).
4. **Exit gate, exactly**: bosun queues `DeviceInformation`; a
   push wakes the device; the device checks in; the command
   delivers; the device's response lands in bosun and is shown
   against the queue record. Then one `InstallApplication` of a
   managed app by the same path. Both round-trips, on the real
   device, or Stage 1 is not done.

Also carried into Stage 1: the verified operator-approval
channel (replacing Stage 0's presented approval object), the
guard ordering barrier if client evidence asks for it, and
Stage 2's live Android/Windows exercise (diagnostics first,
then one gated install each) against the Owner's Z Flip 7
(ADB over the tailnet) and a Windows host.
