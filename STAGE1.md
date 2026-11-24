# Bosun — Stage 1 record

Stage 1's server-side build is landed. Everything the MDM
round-trip needs that does not depend on the push certificate
existing yet is built, gated, and proven against a simulated
device. **The Stage 1 completion gate stays OPEN**: the two
round-trips on a real iPhone (`DeviceInformation`, then
`InstallApplication`, both by push + check-in) remain, behind
the Owner's certificate steps listed at the end.

Built under the Owner's clearance of 2026-11-24 11:42 PT for
work in the primo mirror `~/.GH/Qompass/bosun`. Local commits
only; nothing pushed (per-push confirmation is the Owner's).

## What was built

1. **MDM check-in server** (`src/mdmhttp.rs`, run as
   `bosun mdm-serve`, a separate process from the MCP server;
   the two coordinate through the home directory's files, each
   loading fresh per operation). HTTPS endpoints:
   `PUT /mdm/checkin` (`Authenticate` / `TokenUpdate` /
   `CheckOut`), `PUT /mdm/server` (command channel),
   `GET /enroll` (profile download), `GET|POST /scep`,
   `GET /health`. Std-thread socket server (32-connection cap,
   15 s socket timeouts, 16 KiB header / 1 MiB body bounds) with
   rustls TLS. TLS posture: configured cert/key; else, on a
   loopback bind, a self-signed development certificate
   generated under the home (key 0600); plaintext only when
   `BOSUN_MDM_ALLOW_PLAIN_LOOPBACK=1` **and** the bind is
   loopback. A non-loopback bind without TLS refuses to start.
   Check-in semantics: the first `Authenticate` must carry the
   one-shot enrollment session token (spent on use); it binds
   the UDID to the inventory record the session names (UDID
   must match the record's transport) at the session's declared
   enrollment. `TokenUpdate` stores the push token (hex),
   push magic, and topic. `CheckOut` drops the push
   credentials. The MCP side overlays the MDM state's
   enrollment onto inventory records, so an enrolling device
   transitions unenrolled → unsupervised/supervised in every
   gate decision from its first check-in.
2. **Command channel**: the persisted command records
   (`src/mdmstate.rs`, `$BOSUN_HOME/mdm_state.json`, bounded:
   512 KiB file, 256 devices, 512 pending commands, 1,024
   records, 32 KiB per recorded response) carry commands
   `Queued → Delivered → Acknowledged|Error`. An Idle poll
   delivers the oldest queued command; a response in the same
   poll records against its record and chains the next command.
   Responses are refused — record untouched — when the UUID is
   unknown (`command_not_found`), belongs to another device
   (`command_device_mismatch`), names a not-yet-delivered
   command (`command_not_delivered`), or answers a completed
   one (`command_already_completed`). `NotNow` records nothing;
   the command stays outstanding. `DeviceInformation` is the
   first command (iOS diagnostics queues it), `InstallApplication`
   the second (supervised installs; a numeric identifier renders
   as `iTunesStoreID`, an https URL as `ManifestURL`, anything
   else refuses at enqueue).
3. **APNs push client** (`src/apns.rs`): a bounded
   `curl --http2` invocation with the push certificate + key
   (the estate's argv-only subprocess pattern; the fleet curl
   is nghttp2-built), `apns-push-type: mdm`, payload
   `{"aps": {}, "mdm": "<push magic>"}`. The topic is read from
   the certificate's subject UID via openssl unless
   `BOSUN_MDM_TOPIC` pins it. Behind a transport trait: the
   production transport is curl; a file-logging mock is
   selected by `BOSUN_MDM_PUSH_TRANSPORT=mock` for tests and
   the simulated gate. No real APNs call is possible in this
   stage: without push cert/key configured, the tool refuses
   with `push_not_configured` before any transport runs.
4. **SCEP — the choice, and why**: a **clearly-fenced local CA
   step** (`src/scep.rs`), not a full SCEP implementation.
   `bosun ca-init` creates a real local CA under
   `$BOSUN_HOME/ca/` (key 0600). `GetCACert`/`GetCACaps` are
   served for real. `PKIOperation` accepts a bare PKCS#10 CSR
   (DER or PEM), verifies its proof-of-possession signature,
   signs it with the CA, and answers with a certs-only PKCS#7 —
   the CertRep payload shape. What is fenced off is the CMS
   envelope (`pkiMessage` wrapping): no maintained CMS crate
   exists in the estate's offline registry cache, and
   hand-rolling ASN.1 CMS was judged out of bounds for this
   stage. **Consequence, stated plainly: a stock iPhone speaks
   enveloped SCEP and will not complete enrollment against
   this simplified operation.** Closing the gap means adding a
   CMS envelope in front of this CA (a bounded ASN.1 job); the
   signing core does not change. This is a named real-device
   gate item below, not a hidden one.
5. **Enrollment profile** (`src/profile.rs`,
   `bosun_mdm_enrollment_profile` tool): generates the
   `.mobileconfig` from config — server URL, check-in URL
   carrying the one-shot session token, the topic (placeholder
   `com.apple.mgmt.External.00000000-…` until the real
   certificate lands; regenerate profiles then), the SCEP
   payload (endpoint, RSA 2048 identity, the local CA's SHA-1
   fingerprint when the CA exists). The artifact is written to
   `$BOSUN_HOME/profiles/<token>.mobileconfig`, returned inline,
   and served by `GET /enroll?session=<token>` (the download
   does not spend the session; `Authenticate` does).
6. **Verified operator-approval channel** (`src/approval.rs`):
   replaces Stage 0's presented approval object wherever a key
   exists. `bosun approve --action A --by NAME [--device ID]
   [--ttl S]` mints `v1.<expires>.<base64url(mac)>` — HMAC-SHA256
   (hand-rolled, pinned by the RFC 4231 vectors) over a
   canonical string binding action, device, approver, and
   expiry (≤ 3600 s). The server verifies the token from
   `operator_approval.token` and only then marks the approval;
   `gate::decide_with_policy` with `RequireVerified` denies an
   unverified approval with `approval_not_verified`, after the
   capability check as before — an allow still names its
   approver, and a verified approval still cannot create a
   capability. The key file must be 0600 and ≥ 16 bytes; a
   present-but-unusable key file fails closed. Known scope,
   recorded: the token binds action + device + approver +
   expiry, not the call's remaining arguments (e.g. which
   package); within its TTL it authorizes its action on its
   device. Keyless deployments keep Stage 0 presented
   semantics, so existing callers are unaffected.
7. **Cert-prep script** (`scripts/mdmcert_prep.py`): see
   usage below. Dry-run-proven with a throwaway self-signed
   vendor stand-in.
8. **Simulated-device gate** (`tests/mdm_simulated_device.rs`):
   the stage's exit evidence. It plays the iPhone side
   end-to-end against both real processes over one shared
   home: register → enrollment profile → `Authenticate` /
   `TokenUpdate` → diagnostics queues `DeviceInformation` →
   mock-APNs wake (the mock log carries the device's token hex
   and push magic) → Idle poll delivers the command with the
   same UUID → `Acknowledged` with `QueryResponses` lands
   against the record → approved install queues
   `InstallApplication` → delivered with the right
   `iTunesStoreID` → acknowledged. Adversarial, in the same
   run: a wrong-UUID response gets HTTP 400 and the record
   stays `delivered`; a second device enrolled unsupervised
   meets `capability_not_declared` on an approved install and
   queues nothing.

Supporting pieces: a bounded hand-rolled plist codec
(`src/plist.rs` — MDM's wire format; refuses DTDs/entities,
duplicate keys, oversize/deep documents), the MDM environment
contract (`src/config.rs`, `BOSUN_MDM_*`), and the lib/bin
split so the integration test links the real protocol modules.
The MCP surface is now **12 tools in 6 groups** (new `mdm`
group: `bosun_mdm_enrollment_profile`, `bosun_mdm_queue`,
`bosun_mdm_send_push`); tools/list ≈ 2,232 tokens against the
2,500 budget.

## Gates (run artifacts: primo, 2026-11-24)

- `cargo build --offline`: clean. `cargo clippy --all-targets`:
  **0 warnings**. `cargo fmt --check`: clean.
- `cargo test`: **75 passed / 0 failed** — 73 unit (plist,
  approval crypto vectors, gate policy, MDM state adversarial
  set, check-in/command flow over `handle()`, SCEP CA
  round-trip + tamper refusals, APNs argv/response shapes,
  server wiring incl. the verified channel) + the manifest
  agreement test + the simulated-device end-to-end.
- Live MCP probe (`scripts/probe.py`, fleet shape):
  **20/20** — discover era, 12 tools within budget, legacy
  `initialize` refused `-32022`, gate behaviour, the mdm tools.
  (The probe now awaits dependent calls one at a time: the
  server executes calls concurrently, and the Stage 0 probe's
  pipelining of dependent calls was a latent race — two
  transient failures during this stage were the probe's, not
  the server's, and are fixed in the probe.)
- Theodolite (`scripts/theo_probe.py`): **17 files, 0 errors,
  0 warnings**, positive control live (seeded E0308 in
  `src/mdm.rs` produced 2 severity-1 diagnostics through the
  bridge; control file restored byte-identical).
- Cert-prep dry run: **PASS** (stand-in vendor → keygen →
  sign → signature verifies; push key mode verified 0600).

## Cert-prep script — exact usage

All subcommands refuse to write key material inside the repo
tree; private keys are created 0600 and never overwritten.

```sh
# Once the vendor signing certificate arrives (Route A):
python3 scripts/mdmcert_prep.py keygen --out-dir ~/bosun-push
#   -> ~/bosun-push/push.key (0600), ~/bosun-push/push.csr

python3 scripts/mdmcert_prep.py sign \
  --csr ~/bosun-push/push.csr \
  --vendor-cert <vendor.pem> --vendor-key <vendor.key> \
  --out ~/bosun-push/PushCertificateRequest.plist
#   -> upload the .plist at https://identity.apple.com/pushcert
#      (Create Certificate); download the issued .pem.

python3 scripts/mdmcert_prep.py verify-bundle \
  --bundle ~/bosun-push/PushCertificateRequest.plist \
  --vendor-cert <vendor.pem>

# Mechanics proof with a throwaway self-signed vendor:
python3 scripts/mdmcert_prep.py dry-run --work-dir /tmp/bosun-cert-dryrun
```

The bundle follows mdmctl's documented construction (plist:
CSR DER as data, vendor cert PEM as string, RSA SHA-256
signature over the CSR DER as data). `mdmctl` is not installed
on the fleet machine; when the real vendor certificate
arrives, cross-check the bundle against `mdmctl mdmcert`
before the portal upload — a malformed bundle fails safe at
the portal (rejected upload, nothing enrolled), but the check
costs minutes. The default CSR subject is
`/CN=MDM Push/O=Amor Fati Labs LLC` (`--subject` overrides).

## Remaining real-device gate, in order

1. **Owner** completes Route A (STAGE0.md §1): Apple Developer
   Program enrollment for Amor Fati Labs LLC ($99/yr, org
   Apple ID kept for renewals), Account Holder request for
   the MDM Vendor CSR signing certificate, Apple Business
   Manager enrollment.
2. Owner hands over the vendor certificate + key; Pax runs
   the cert-prep `keygen` + `sign` (cross-checked against
   mdmctl), Owner does the one portal upload at
   identity.apple.com/pushcert and downloads the `.pem`.
3. Pax installs cert + key on the server
   (`BOSUN_MDM_PUSH_CERT`/`BOSUN_MDM_PUSH_KEY`), verifies the
   topic reads from the certificate, points
   `BOSUN_MDM_SERVER_URL` at the reachable HTTPS address with
   a real TLS certificate, and regenerates the enrollment
   profile (real topic replaces the placeholder).
4. **SCEP decision point**: the fenced PKIOperation will not
   satisfy a stock iPhone's enveloped SCEP. Before the device
   enrollment below, either (a) build the CMS envelope in
   front of the local CA, or (b) deliver the device identity
   certificate by another profile payload and drop the SCEP
   payload from the enrollment profile. This is the one
   build item the simulation could not retire.
5. **Owner** enrolls one iPhone via the Configurator path
   (STAGE0.md §2): backup → erase → Apple Configurator for
   iPhone adds it to ABM → assign to bosun → Setup Assistant →
   supervised ADE enrollment (provisional for 30 days).
6. **Exit gate (Stage 1 completes here, and only here)**:
   bosun queues `DeviceInformation`; a push wakes the device;
   it checks in; the command delivers; its response lands
   against the queue record — then one `InstallApplication`
   by the same path. Both round-trips on the real device.
7. Carried to Stage 2 as before: live Android/Windows
   exercise; renewal tracking for the push certificate (same
   Apple ID, Renew never Create — a topic change forces
   fleet-wide re-enrollment).

## Commits (local only, no push)

- `f393600` Stage 0 scaffold (reconstructed tree state;
  re-verified 35 tests before committing).
- `5dc7eac` Stage 1 core: check-in/command server, APNs,
  SCEP step, profiles, approval channel.
- `7378709` Stage 1 scripts: cert-prep + probe.
- `195741d` Stage 1 gate: simulated-device end-to-end.
- This record + README refresh.
