#!/usr/bin/env python3
"""Prepare the APNs MDM push certificate request (Stage 1, item 7).

Apple's push-certificate portal (identity.apple.com/pushcert)
does not accept a bare CSR: the upload must be a vendor-signed
request bundle — a plist carrying the push CSR, the MDM vendor
certificate, and an RSA signature over the CSR made with the
vendor key. This is the `mdmctl mdmcert` construction; this
script performs the same steps with openssl so the mechanics
are proven before the real vendor certificate exists (see
`dry-run`, which stands in a throwaway self-signed vendor).

Subcommands:
  keygen       --out-dir DIR [--subject DN]
               Create the push private key (0600) + CSR in DIR.
  sign         --csr CSR --vendor-cert PEM --vendor-key KEY
               --out BUNDLE.plist
               Build the vendor-signed portal-upload bundle.
  verify-bundle --bundle BUNDLE.plist --vendor-cert PEM
               Check a bundle's signature against the vendor cert.
  dry-run      --work-dir DIR
               keygen + sign + verify with a throwaway vendor.

Hard rules, enforced here rather than by convention: private
keys are written 0600, an existing key is never overwritten,
and no key material is written inside the repository tree —
--out-dir / --work-dir must live outside it.
"""
import argparse
import os
import plistlib
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SUBJECT = "/CN=MDM Push/O=Amor Fati Labs LLC"


def fail(msg):
    print(f"mdmcert_prep: error: {msg}", file=sys.stderr)
    sys.exit(1)


def openssl(args, **kw):
    proc = subprocess.run(
        ["openssl", *args], capture_output=True, text=False, **kw
    )
    if proc.returncode != 0:
        fail(
            f"openssl {' '.join(args[:2])} failed: "
            f"{proc.stderr.decode(errors='replace').strip()}"
        )
    return proc.stdout


def outside_repo(path: Path, what: str) -> Path:
    resolved = path.resolve()
    if resolved == REPO_ROOT or REPO_ROOT in resolved.parents:
        fail(f"{what} must live outside the repository tree ({REPO_ROOT}); got {resolved}")
    return resolved


def write_key(path: Path, data: bytes):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.chmod(path, 0o600)


def cmd_keygen(args):
    out_dir = outside_repo(Path(args.out_dir), "--out-dir")
    out_dir.mkdir(parents=True, exist_ok=True)
    key_path = out_dir / "push.key"
    csr_path = out_dir / "push.csr"
    if key_path.exists() or csr_path.exists():
        fail(f"{key_path} or {csr_path} already exists; refusing to overwrite key material")
    key = openssl(["genrsa", "2048"])
    write_key(key_path, key)
    csr = openssl(
        ["req", "-new", "-key", str(key_path), "-subj", args.subject]
    )
    csr_path.write_bytes(csr)
    os.chmod(csr_path, 0o644)
    print(f"push key (0600): {key_path}")
    print(f"push CSR:        {csr_path}")
    print("next: when the vendor signing certificate arrives, run `sign`.")


def csr_der(csr_path: Path) -> bytes:
    raw = csr_path.read_bytes()
    if raw[:1] == b"\x30":
        return raw
    with tempfile.NamedTemporaryFile(suffix=".der", delete=False) as tmp:
        tmp_path = tmp.name
    try:
        openssl(
            ["req", "-in", str(csr_path), "-outform", "DER", "-out", tmp_path]
        )
        return Path(tmp_path).read_bytes()
    finally:
        os.unlink(tmp_path)


def cmd_sign(args):
    csr_path = Path(args.csr)
    vendor_cert = Path(args.vendor_cert)
    vendor_key = Path(args.vendor_key)
    out_path = Path(args.out)
    for p in (csr_path, vendor_cert, vendor_key):
        if not p.exists():
            fail(f"missing input: {p}")
    der = csr_der(csr_path)
    with tempfile.NamedTemporaryFile(suffix=".sig", delete=False) as tmp:
        sig_path = tmp.name
    try:
        openssl(
            ["dgst", "-sha256", "-sign", str(vendor_key), "-out", sig_path,
             "-"],
            input=der,
        )
        signature = Path(sig_path).read_bytes()
    finally:
        os.unlink(sig_path)
    bundle = {
        "PushCertificateRequest": der,
        "VendorCertificate": vendor_cert.read_text(),
        "Signature": signature,
    }
    out_path.write_bytes(plistlib.dumps(bundle, fmt=plistlib.FMT_XML))
    print(f"portal bundle: {out_path}")
    print("upload at https://identity.apple.com/pushcert (Create Certificate),")
    print("then hand the downloaded .pem to the server install step.")


def cmd_verify_bundle(args):
    bundle = plistlib.loads(Path(args.bundle).read_bytes())
    for key in ("PushCertificateRequest", "VendorCertificate", "Signature"):
        if key not in bundle:
            fail(f"bundle lacks {key}")
    der = bundle["PushCertificateRequest"]
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        pub = td / "vendor.pub"
        pub.write_bytes(
            openssl(
                ["x509", "-in", str(args.vendor_cert), "-pubkey", "-noout"]
            )
        )
        sig = td / "sig.bin"
        sig.write_bytes(bundle["Signature"])
        proc = subprocess.run(
            ["openssl", "dgst", "-sha256", "-verify", str(pub),
             "-signature", str(sig), "-"],
            input=der,
            capture_output=True,
        )
        if proc.returncode != 0:
            fail(f"bundle signature does not verify: {proc.stderr.decode(errors='replace').strip()}")
    print("bundle signature verifies against the vendor certificate")
    print(f"CSR bytes: {len(der)}; signature bytes: {len(bundle['Signature'])}")


def cmd_dry_run(args):
    work = outside_repo(Path(args.work_dir), "--work-dir")
    work.mkdir(parents=True, exist_ok=True)
    vendor_key = work / "vendor.key"
    vendor_cert = work / "vendor.pem"
    if vendor_key.exists() or vendor_cert.exists():
        fail("dry-run work dir already holds a vendor stand-in; use a fresh dir")
    # Throwaway self-signed vendor stand-in. It proves the
    # mechanics only; Apple would not accept its signature.
    key = openssl(["genrsa", "2048"])
    write_key(vendor_key, key)
    cert = openssl(
        ["req", "-x509", "-new", "-key", str(vendor_key), "-days", "30",
         "-subj", "/CN=Throwaway MDM Vendor (dry run)/O=Bosun Dry Run"]
    )
    vendor_cert.write_bytes(cert)
    print(f"vendor stand-in: {vendor_cert} (self-signed, mechanics only)")

    class A:
        pass

    kg = A()
    kg.out_dir = str(work / "push")
    kg.subject = DEFAULT_SUBJECT
    cmd_keygen(kg)

    sg = A()
    sg.csr = str(work / "push" / "push.csr")
    sg.vendor_cert = str(vendor_cert)
    sg.vendor_key = str(vendor_key)
    sg.out = str(work / "PushCertificateRequest.plist")
    cmd_sign(sg)

    vf = A()
    vf.bundle = sg.out
    vf.vendor_cert = str(vendor_cert)
    cmd_verify_bundle(vf)

    mode = stat.S_IMODE(os.stat(work / "push" / "push.key").st_mode)
    if mode != 0o600:
        fail(f"push key mode is {oct(mode)}, expected 0o600")
    print("push key mode verified 0600")
    print("DRY RUN PASS: keygen -> sign -> verify, end to end")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("keygen")
    p.add_argument("--out-dir", required=True)
    p.add_argument("--subject", default=DEFAULT_SUBJECT)
    p.set_defaults(fn=cmd_keygen)

    p = sub.add_parser("sign")
    p.add_argument("--csr", required=True)
    p.add_argument("--vendor-cert", required=True)
    p.add_argument("--vendor-key", required=True)
    p.add_argument("--out", required=True)
    p.set_defaults(fn=cmd_sign)

    p = sub.add_parser("verify-bundle")
    p.add_argument("--bundle", required=True)
    p.add_argument("--vendor-cert", required=True)
    p.set_defaults(fn=cmd_verify_bundle)

    p = sub.add_parser("dry-run")
    p.add_argument("--work-dir", required=True)
    p.set_defaults(fn=cmd_dry_run)

    args = parser.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
