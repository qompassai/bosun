//! The verified operator-approval channel (Stage 1 hardening of
//! the Stage 0 gate).
//!
//! Stage 0's approval was a *presented* object: any caller could
//! type `approved_by: "operator"` and the gate trusted the
//! string. This module is the channel the gate record asked for —
//! an approval the server *verifies* rather than trusts:
//!
//! - The operator holds a shared key in a 0600 file outside the
//!   repo (`$BOSUN_HOME/approval.key`, or `BOSUN_APPROVAL_KEY_FILE`).
//! - `bosun approve --action … --device … --by …` mints a
//!   short-lived token: `v1.<expires_unix>.<base64url(mac)>`,
//!   where the MAC is HMAC-SHA256 over a canonical string binding
//!   the action, the target device, the approver's name, and the
//!   expiry. A token minted for one action, device, or approver
//!   verifies for no other.
//! - A tool call carries the token as
//!   `operator_approval.token`; the server verifies it against
//!   its key and only then marks the approval verified. The pure
//!   gate (`gate::decide_with_policy`) requires that mark
//!   whenever a key is configured.
//!
//! Known scope, recorded rather than hidden: the token binds
//! action + device + approver + expiry, not the call's remaining
//! arguments (e.g. which package). Within its TTL (≤ 1 hour) a
//! token authorizes its action on its device. That is the
//! household threat model; argument binding is a later refinement
//! if the fleet ever needs it.
//!
//! SHA-256 and HMAC are implemented here, pinned by the standard
//! test vectors, rather than adding a crypto dependency for two
//! small primitives. The MAC comparison is constant-time.

use std::path::Path;

/// Hard bound on a token's lifetime, seconds.
pub const MAX_TTL_SECONDS: u64 = 3600;

/// Default token lifetime minted by the CLI, seconds.
pub const DEFAULT_TTL_SECONDS: u64 = 300;

/// Minimum approval-key length, bytes.
pub const MIN_KEY_BYTES: usize = 16;

#[derive(Debug)]
pub struct ApprovalError {
    pub code: &'static str,
    pub message: String,
}

impl ApprovalError {
    fn new(code: &'static str, message: impl Into<String>) -> ApprovalError {
        ApprovalError {
            code,
            message: message.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// SHA-256 (FIPS 180-4), pinned by the standard vectors in tests.
// ---------------------------------------------------------------------------

const K256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut block = data.to_vec();
    block.push(0x80);
    while block.len() % 64 != 56 {
        block.push(0);
    }
    block.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in block.as_chunks::<64>().0 {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[4 * i],
                chunk[4 * i + 1],
                chunk[4 * i + 2],
                chunk[4 * i + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K256[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut key_block = [0u8; 64];
    if key.len() > 64 {
        let hashed = sha256(key);
        key_block[..32].copy_from_slice(&hashed);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Vec::with_capacity(64 + message.len());
    inner.extend(key_block.iter().map(|b| b ^ 0x36));
    inner.extend_from_slice(message);
    let inner_hash = sha256(&inner);
    let mut outer = Vec::with_capacity(64 + 32);
    outer.extend(key_block.iter().map(|b| b ^ 0x5c));
    outer.extend_from_slice(&inner_hash);
    sha256(&outer)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// Base64url (no padding), the token's MAC encoding.
// ---------------------------------------------------------------------------

const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn b64url_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(*chunk.get(1).unwrap_or(&0));
        let b2 = u32::from(*chunk.get(2).unwrap_or(&0));
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64URL[(n >> 18) as usize & 63] as char);
        out.push(B64URL[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(B64URL[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(B64URL[n as usize & 63] as char);
        }
    }
    out
}

fn b64url_decode(text: &str) -> Option<Vec<u8>> {
    fn value_of(byte: u8) -> Option<u32> {
        match byte {
            b'A'..=b'Z' => Some(u32::from(byte - b'A')),
            b'a'..=b'z' => Some(u32::from(byte - b'a') + 26),
            b'0'..=b'9' => Some(u32::from(byte - b'0') + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }
    let bytes = text.as_bytes();
    if bytes.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3 + 3);
    for chunk in bytes.chunks(4) {
        let mut n: u32 = 0;
        for (i, &b) in chunk.iter().enumerate() {
            n |= value_of(b)? << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(n as u8);
        }
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// The key file and the token.
// ---------------------------------------------------------------------------

/// The operator's approval key: raw bytes from the key file.
#[derive(Clone)]
pub struct ApprovalKey {
    bytes: Vec<u8>,
}

impl ApprovalKey {
    /// Load the key if the file exists. A present-but-unusable
    /// file (too short, or readable by group/other) is an error,
    /// never a silent fall back to presented approvals — the
    /// whole point of the file existing is that verification is
    /// in force.
    pub fn load(path: &Path) -> Result<Option<ApprovalKey>, ApprovalError> {
        let metadata = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(ApprovalError::new(
                    "approval_key_unreadable",
                    format!("cannot stat {}: {e}", path.display()),
                ));
            }
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(ApprovalError::new(
                    "approval_key_permissions",
                    format!(
                        "{} is group/other-accessible; the approval key must be 0600",
                        path.display()
                    ),
                ));
            }
        }
        let bytes = std::fs::read(path).map_err(|e| {
            ApprovalError::new(
                "approval_key_unreadable",
                format!("cannot read {}: {e}", path.display()),
            )
        })?;
        if bytes.len() < MIN_KEY_BYTES {
            return Err(ApprovalError::new(
                "approval_key_too_short",
                format!(
                    "approval key is {} bytes; minimum is {MIN_KEY_BYTES}",
                    bytes.len()
                ),
            ));
        }
        Ok(Some(ApprovalKey { bytes }))
    }

    /// Create a fresh key file (32 random bytes, mode 0600).
    /// Refuses to overwrite an existing file.
    pub fn create(path: &Path) -> Result<ApprovalKey, ApprovalError> {
        use std::io::Write;
        if path.exists() {
            return Err(ApprovalError::new(
                "approval_key_exists",
                format!("{} already exists; refusing to overwrite", path.display()),
            ));
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                ApprovalError::new(
                    "approval_key_unwritable",
                    format!("cannot create {}: {e}", parent.display()),
                )
            })?;
        }
        let mut bytes = [0u8; 32];
        {
            use std::io::Read;
            std::fs::File::open("/dev/urandom")
                .and_then(|mut f| f.read_exact(&mut bytes))
                .map_err(|e| {
                    ApprovalError::new(
                        "approval_key_unwritable",
                        format!("cannot read randomness: {e}"),
                    )
                })?;
        }
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path).map_err(|e| {
            ApprovalError::new(
                "approval_key_unwritable",
                format!("cannot create {}: {e}", path.display()),
            )
        })?;
        file.write_all(&bytes).map_err(|e| {
            ApprovalError::new(
                "approval_key_unwritable",
                format!("cannot write {}: {e}", path.display()),
            )
        })?;
        Ok(ApprovalKey {
            bytes: bytes.to_vec(),
        })
    }
}

fn canonical(action: &str, device_id: Option<&str>, approved_by: &str, expires: u64) -> String {
    format!(
        "bosun-approval-v1\n{action}\n{}\n{approved_by}\n{expires}",
        device_id.unwrap_or("-")
    )
}

/// Mint a token. The CLI is the only minter; the server never
/// mints, it only verifies.
pub fn mint(
    key: &ApprovalKey,
    action: &str,
    device_id: Option<&str>,
    approved_by: &str,
    expires_unix: u64,
) -> String {
    let mac = hmac_sha256(
        &key.bytes,
        canonical(action, device_id, approved_by, expires_unix).as_bytes(),
    );
    format!("v1.{expires_unix}.{}", b64url_encode(&mac))
}

/// Verify a presented token for exactly this action, device, and
/// approver at this moment. Every mismatch — version, shape,
/// expiry, over-long TTL, wrong binding, wrong MAC — is the same
/// `false`; the caller learns nothing about which check failed.
pub fn verify(
    key: &ApprovalKey,
    token: &str,
    action: &str,
    device_id: Option<&str>,
    approved_by: &str,
    now_unix: u64,
) -> bool {
    if approved_by.trim().is_empty() {
        return false;
    }
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 || parts[0] != "v1" {
        return false;
    }
    let Ok(expires) = parts[1].parse::<u64>() else {
        return false;
    };
    if now_unix > expires || expires.saturating_sub(now_unix) > MAX_TTL_SECONDS {
        return false;
    }
    let Some(presented) = b64url_decode(parts[2]) else {
        return false;
    };
    let expected = hmac_sha256(
        &key.bytes,
        canonical(action, device_id, approved_by, expires).as_bytes(),
    );
    constant_time_eq(&presented, &expected)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        crate::plist::hex_encode(bytes)
    }

    #[test]
    fn sha256_standard_vectors() {
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(&sha256(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn hmac_rfc4231_vectors() {
        // Test case 1: key 0x0b x20, data "Hi There".
        assert_eq!(
            hex(&hmac_sha256(&[0x0b; 20], b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        // Test case 2: key "Jefe", data "what do ya want for nothing?".
        assert_eq!(
            hex(&hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        // Test case 6: key longer than the block size (0xaa x131).
        assert_eq!(
            hex(&hmac_sha256(
                &[0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    fn test_key() -> ApprovalKey {
        ApprovalKey {
            bytes: b"stage1-test-approval-key-0123456".to_vec(),
        }
    }

    #[test]
    fn mint_verify_round_trip() {
        let key = test_key();
        let token = mint(&key, "package_install", Some("iphone-1"), "matt", 2000);
        assert!(verify(
            &key,
            &token,
            "package_install",
            Some("iphone-1"),
            "matt",
            1900
        ));
        assert!(verify(
            &key,
            &token,
            "package_install",
            Some("iphone-1"),
            "matt",
            2000
        ));
    }

    #[test]
    fn tokens_bind_action_device_approver_and_time() {
        // Adversarial: a genuine token replayed outside its
        // binding must fail on every axis.
        let key = test_key();
        let token = mint(&key, "package_install", Some("iphone-1"), "matt", 2000);
        assert!(!verify(
            &key,
            &token,
            "reboot",
            Some("iphone-1"),
            "matt",
            1900
        ));
        assert!(!verify(
            &key,
            &token,
            "package_install",
            Some("iphone-2"),
            "matt",
            1900
        ));
        assert!(!verify(&key, &token, "package_install", None, "matt", 1900));
        assert!(!verify(
            &key,
            &token,
            "package_install",
            Some("iphone-1"),
            "eve",
            1900
        ));
        assert!(!verify(
            &key,
            &token,
            "package_install",
            Some("iphone-1"),
            "",
            1900
        ));
        assert!(!verify(
            &key,
            &token,
            "package_install",
            Some("iphone-1"),
            "matt",
            2001
        ));
        // Over-long TTL: minted "for" a far-future expiry is not
        // acceptable even while unexpired.
        let long = mint(
            &key,
            "package_install",
            Some("iphone-1"),
            "matt",
            1900 + MAX_TTL_SECONDS + 1,
        );
        assert!(!verify(
            &key,
            &long,
            "package_install",
            Some("iphone-1"),
            "matt",
            1900
        ));
    }

    #[test]
    fn forged_and_malformed_tokens_fail() {
        // Adversarial: tampered MAC, tampered expiry, wrong key,
        // and shapeless input all fail closed.
        let key = test_key();
        let token = mint(&key, "package_install", Some("iphone-1"), "matt", 2000);
        let mut tampered = token.clone();
        tampered.push('A');
        assert!(!verify(
            &key,
            &tampered,
            "package_install",
            Some("iphone-1"),
            "matt",
            1900
        ));
        let parts: Vec<&str> = token.split('.').collect();
        let later = format!("v1.2500.{}", parts[2]);
        assert!(!verify(
            &key,
            &later,
            "package_install",
            Some("iphone-1"),
            "matt",
            1900
        ));
        let other = ApprovalKey {
            bytes: b"a-different-key-entirely-000000".to_vec(),
        };
        assert!(!verify(
            &other,
            &token,
            "package_install",
            Some("iphone-1"),
            "matt",
            1900
        ));
        for junk in ["", "v1", "v2.2000.abc", "v1.notanumber.abc", "v1.2000.!!!"] {
            assert!(
                !verify(
                    &key,
                    junk,
                    "package_install",
                    Some("iphone-1"),
                    "matt",
                    1900
                ),
                "junk token {junk:?} must fail"
            );
        }
    }
}
