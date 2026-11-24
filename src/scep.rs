//! SCEP, as a clearly-fenced local CA step.
//!
//! The choice, and why (the full record is STAGE1.md): bosun
//! does not implement the SCEP wire protocol's CMS envelope.
//! What lands here is the part the check-in server actually
//! depends on — a local certificate authority that verifies and
//! signs CSRs — behind the SCEP operation names:
//!
//! - `GetCACert` / `GetCACaps` are served for real.
//! - `PKIOperation` accepts a bare PKCS#10 CSR (DER or PEM)
//!   instead of a CMS-enveloped `pkiMessage`. The CA verifies
//!   the CSR's proof-of-possession signature, signs it, and
//!   answers with a certs-only PKCS#7 — the same payload shape a
//!   SCEP CertRep carries.
//!
//! The fence is the point: a stock iPhone speaks enveloped SCEP
//! and will not complete enrollment against this simplified
//! operation. That gap is a named real-device gate item, not a
//! hidden one; closing it means adding a CMS envelope (a bounded
//! ASN.1 job) in front of this CA, whose signing core does not
//! change. The CA itself is real and is what the enrollment
//! profile's SCEP payload points at.
//!
//! Everything runs through bounded openssl subprocesses (the
//! estate pattern), the CA key is 0600 under `$BOSUN_HOME/ca/`,
//! and no key material ever enters the repo tree.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

/// Bound on a CSR presented to PKIOperation.
pub const MAX_CSR_BYTES: usize = 64 * 1024;
/// Bound on any openssl output we accept back.
const MAX_OPENSSL_OUTPUT: usize = 1024 * 1024;
const OPENSSL_TIMEOUT: Duration = Duration::from_secs(20);
const CA_DAYS: u32 = 3650;
const LEAF_DAYS: u32 = 825;

#[derive(Debug)]
pub struct ScepError {
    pub code: &'static str,
    pub message: String,
}

impl ScepError {
    fn new(code: &'static str, message: impl Into<String>) -> ScepError {
        ScepError {
            code,
            message: message.into(),
        }
    }
}

/// Run openssl with a wall-clock bound and an output bound.
/// Local, fixed-purpose invocations only — the arguments are
/// built by this module, never from wire input.
fn run_openssl(args: &[String], stdin: Option<&[u8]>) -> Result<Vec<u8>, ScepError> {
    let mut cmd = Command::new("openssl");
    cmd.args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd
        .spawn()
        .map_err(|e| ScepError::new("openssl_unavailable", format!("cannot run openssl: {e}")))?;
    if let Some(input) = stdin {
        let mut pipe = child.stdin.take().expect("stdin piped");
        // The input is bounded at 64 KiB and openssl drains it;
        // a failed write surfaces as a signing error below.
        let _ = pipe.write_all(input);
        drop(pipe);
    }
    // Drain both pipes on threads so a chatty openssl can never
    // deadlock against a full pipe buffer while we poll.
    use std::io::Read;
    let mut out_pipe = child.stdout.take().expect("stdout piped");
    let out_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = out_pipe.read_to_end(&mut buf);
        buf
    });
    let mut err_pipe = child.stderr.take().expect("stderr piped");
    let err_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = err_pipe.read_to_end(&mut buf);
        buf
    });
    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if start.elapsed() > OPENSSL_TIMEOUT {
                    let _ = child.kill();
                    return Err(ScepError::new(
                        "openssl_timeout",
                        format!("openssl exceeded the {}s bound", OPENSSL_TIMEOUT.as_secs()),
                    ));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => {
                return Err(ScepError::new(
                    "openssl_failed",
                    format!("waiting on openssl: {e}"),
                ));
            }
        }
    };
    let stdout = out_thread.join().unwrap_or_default();
    let stderr = err_thread.join().unwrap_or_default();
    if stdout.len() > MAX_OPENSSL_OUTPUT || stderr.len() > MAX_OPENSSL_OUTPUT {
        return Err(ScepError::new(
            "openssl_output_too_large",
            "openssl output exceeded the bound",
        ));
    }
    if !status.success() {
        return Err(ScepError::new(
            "openssl_failed",
            format!(
                "openssl {} failed: {}",
                args.first().map(String::as_str).unwrap_or(""),
                String::from_utf8_lossy(&stderr).trim()
            ),
        ));
    }
    Ok(stdout)
}

/// SHA-1 (FIPS 180-4), needed for exactly one thing: the SCEP
/// `CAFingerprint` in the enrollment profile is a SHA-1 hash of
/// the CA certificate. Pinned by the standard vectors in tests,
/// like the SHA-256 in `approval`.
fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut block = data.to_vec();
    block.push(0x80);
    while block.len() % 64 != 56 {
        block.push(0);
    }
    block.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in block.as_chunks::<64>().0 {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[4 * i],
                chunk[4 * i + 1],
                chunk[4 * i + 2],
                chunk[4 * i + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, &word) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let tmp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = tmp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    let mut out = [0u8; 20];
    for (i, word) in h.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

fn set_key_permissions(path: &Path) -> Result<(), ScepError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|e| {
            ScepError::new(
                "ca_key_permissions_failed",
                format!("cannot chmod {}: {e}", path.display()),
            )
        })?;
    }
    Ok(())
}

/// The local CA, rooted at `$BOSUN_HOME/ca/`.
pub struct LocalCa {
    dir: PathBuf,
}

impl LocalCa {
    pub fn new(home: &Path) -> LocalCa {
        LocalCa {
            dir: home.join("ca"),
        }
    }

    pub fn cert_path(&self) -> PathBuf {
        self.dir.join("ca.pem")
    }

    pub fn key_path(&self) -> PathBuf {
        self.dir.join("ca.key")
    }

    pub fn is_initialized(&self) -> bool {
        self.cert_path().exists() && self.key_path().exists()
    }

    /// Create the CA. Refuses to overwrite an existing one —
    /// replacing a CA silently invalidates every identity it
    /// issued.
    pub fn init(&self) -> Result<Value, ScepError> {
        if self.is_initialized() {
            return Err(ScepError::new(
                "ca_already_initialized",
                format!(
                    "a CA already exists at {}; refusing to replace it",
                    self.cert_path().display()
                ),
            ));
        }
        std::fs::create_dir_all(&self.dir).map_err(|e| {
            ScepError::new(
                "ca_unwritable",
                format!("cannot create {}: {e}", self.dir.display()),
            )
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&self.dir, std::fs::Permissions::from_mode(0o700));
        }
        run_openssl(
            &[
                "req".to_string(),
                "-x509".to_string(),
                "-newkey".to_string(),
                "rsa:2048".to_string(),
                "-keyout".to_string(),
                self.key_path().display().to_string(),
                "-out".to_string(),
                self.cert_path().display().to_string(),
                "-days".to_string(),
                CA_DAYS.to_string(),
                "-nodes".to_string(),
                "-subj".to_string(),
                "/CN=Bosun Local CA/O=Bosun".to_string(),
            ],
            None,
        )?;
        set_key_permissions(&self.key_path())?;
        Ok(json!({
            "ca_cert": self.cert_path().display().to_string(),
            "ca_key": self.key_path().display().to_string(),
            "note": "local CA for the fenced SCEP step; the key is 0600 and never leaves this home",
        }))
    }

    /// The CA certificate in DER — the `GetCACert` body.
    pub fn ca_cert_der(&self) -> Result<Vec<u8>, ScepError> {
        if !self.is_initialized() {
            return Err(ScepError::new(
                "ca_not_initialized",
                "no local CA yet; run `bosun ca-init` first",
            ));
        }
        run_openssl(
            &[
                "x509".to_string(),
                "-in".to_string(),
                self.cert_path().display().to_string(),
                "-outform".to_string(),
                "DER".to_string(),
            ],
            None,
        )
    }

    /// The SHA-1 fingerprint of the CA certificate, for the
    /// enrollment profile's SCEP `CAFingerprint`.
    pub fn ca_fingerprint_sha1(&self) -> Result<Vec<u8>, ScepError> {
        let der = self.ca_cert_der()?;
        Ok(sha1(&der).to_vec())
    }

    /// The `GetCACaps` body: only what this fence actually does.
    pub fn caps() -> &'static str {
        "POSTPKIOperation\nSHA-256\nAES\n"
    }

    /// PKIOperation, fenced form: verify a bare CSR's
    /// proof-of-possession, sign it, and answer with a
    /// certs-only PKCS#7 (DER).
    pub fn issue(&self, csr: &[u8]) -> Result<Vec<u8>, ScepError> {
        if !self.is_initialized() {
            return Err(ScepError::new(
                "ca_not_initialized",
                "no local CA yet; run `bosun ca-init` first",
            ));
        }
        if csr.is_empty() || csr.len() > MAX_CSR_BYTES {
            return Err(ScepError::new(
                "csr_invalid",
                format!("CSR must be 1..={MAX_CSR_BYTES} bytes"),
            ));
        }
        let stamp = format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        let csr_path = self.dir.join(format!("req-{stamp}.csr"));
        let cert_path = self.dir.join(format!("cert-{stamp}.pem"));
        let result = self.issue_inner(csr, &csr_path, &cert_path);
        let _ = std::fs::remove_file(&csr_path);
        let _ = std::fs::remove_file(&cert_path);
        result
    }

    fn issue_inner(
        &self,
        csr: &[u8],
        csr_path: &Path,
        cert_path: &Path,
    ) -> Result<Vec<u8>, ScepError> {
        std::fs::write(csr_path, csr)
            .map_err(|e| ScepError::new("ca_unwritable", format!("cannot stage CSR: {e}")))?;
        // DER CSRs start with a SEQUENCE tag; anything else is
        // treated as PEM. openssl makes the final call either way.
        let inform = if csr.first() == Some(&0x30) {
            "DER"
        } else {
            "PEM"
        };
        // Proof of possession: the CSR's self-signature must
        // verify before the CA spends a signature on it.
        run_openssl(
            &[
                "req".to_string(),
                "-in".to_string(),
                csr_path.display().to_string(),
                "-inform".to_string(),
                inform.to_string(),
                "-noout".to_string(),
                "-verify".to_string(),
            ],
            None,
        )
        .map_err(|e| {
            ScepError::new(
                "csr_signature_invalid",
                format!("CSR proof-of-possession does not verify: {}", e.message),
            )
        })?;
        run_openssl(
            &[
                "x509".to_string(),
                "-req".to_string(),
                "-in".to_string(),
                csr_path.display().to_string(),
                "-inform".to_string(),
                inform.to_string(),
                "-CA".to_string(),
                self.cert_path().display().to_string(),
                "-CAkey".to_string(),
                self.key_path().display().to_string(),
                "-CAcreateserial".to_string(),
                "-days".to_string(),
                LEAF_DAYS.to_string(),
                "-sha256".to_string(),
                "-out".to_string(),
                cert_path.display().to_string(),
            ],
            None,
        )?;
        // Certs-only PKCS#7: the SCEP CertRep payload shape.
        run_openssl(
            &[
                "crl2pkcs7".to_string(),
                "-nocrl".to_string(),
                "-certfile".to_string(),
                cert_path.display().to_string(),
                "-outform".to_string(),
                "DER".to_string(),
            ],
            None,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_ca(tag: &str) -> (PathBuf, LocalCa) {
        let dir =
            std::env::temp_dir().join(format!("bosun-scep-test-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        (dir.clone(), LocalCa::new(&dir))
    }

    fn make_csr(dir: &Path) -> Vec<u8> {
        let key = dir.join("device.key");
        let csr = dir.join("device.csr");
        run_openssl(
            &[
                "req".to_string(),
                "-newkey".to_string(),
                "rsa:2048".to_string(),
                "-keyout".to_string(),
                key.display().to_string(),
                "-out".to_string(),
                csr.display().to_string(),
                "-nodes".to_string(),
                "-subj".to_string(),
                "/CN=Bosun Device".to_string(),
            ],
            None,
        )
        .expect("csr generation works");
        std::fs::read(&csr).expect("csr readable")
    }

    #[test]
    fn sha1_standard_vectors() {
        assert_eq!(
            crate::plist::hex_encode(&sha1(b"")),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
        assert_eq!(
            crate::plist::hex_encode(&sha1(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
    }

    #[test]
    fn ca_init_issue_and_getcacert_round_trip() {
        let (dir, ca) = temp_ca("roundtrip");
        assert!(!ca.is_initialized());
        assert!(ca.ca_cert_der().is_err());
        ca.init().expect("ca init");
        assert!(ca.is_initialized());
        // Re-init refuses: a CA is never silently replaced.
        assert_eq!(
            ca.init().expect_err("re-init must refuse").code,
            "ca_already_initialized"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(ca.key_path())
                .expect("key exists")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "CA key must be 0600");
        }
        let der = ca.ca_cert_der().expect("ca cert der");
        assert_eq!(der.first(), Some(&0x30), "DER starts with a SEQUENCE");
        let csr = make_csr(&dir);
        let p7 = ca.issue(&csr).expect("issue works");
        assert_eq!(p7.first(), Some(&0x30), "PKCS#7 is DER");
        assert!(p7.len() > 200, "PKCS#7 carries a certificate");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn issue_refuses_garbage_and_tampered_csrs() {
        // Adversarial: junk bytes and a CSR whose signature no
        // longer verifies must both refuse, with no cert issued.
        let (dir, ca) = temp_ca("adversarial");
        ca.init().expect("ca init");
        assert_eq!(
            ca.issue(b"not a csr").expect_err("junk refuses").code,
            "csr_signature_invalid"
        );
        let mut csr = make_csr(&dir);
        // Flip a byte in the signature region (the tail of the
        // PEM's base64): decode, tamper, re-encode is overkill —
        // corrupting the PEM body directly breaks the signature
        // or the parse, and either way openssl refuses.
        let mid = csr.len() / 2;
        csr[mid] = if csr[mid] == b'A' { b'B' } else { b'A' };
        assert!(ca.issue(&csr).is_err(), "tampered CSR must refuse");
        assert_eq!(
            ca.issue(&vec![0u8; MAX_CSR_BYTES + 1])
                .expect_err("oversize refuses")
                .code,
            "csr_invalid"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
