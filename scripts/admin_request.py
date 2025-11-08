#!/usr/bin/env python3
import argparse
import base64
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from getpass import getpass
from textwrap import dedent

import requests
from cryptography.hazmat.primitives.serialization import load_ssh_private_key


def canonical_json(raw: str) -> str:
    parsed = json.loads(raw)
    return json.dumps(parsed, separators=(",", ":"), sort_keys=True)

def build_signing_string(canon_payload: str, method: str, path: str, nonce: str) -> bytes:
    return "\n".join([canon_payload, method.upper(), path, nonce]).encode()


def load_ed25519_key(path: Path, passphrase: str | None):
    data = path.read_bytes()
    password_bytes = passphrase.encode() if passphrase else None
    try:
        return load_ssh_private_key(data, password=password_bytes)
    except ValueError as exc:
        if passphrase is None:
            raise ValueError("Key is password-protected; rerun with --prompt-passphrase") from exc
        raise


def sign_payload(priv_key, message: bytes) -> str:
    sig = priv_key.sign(message)
    return base64.b64encode(sig).decode()


def generate_csr(args) -> None:
    cert_path = Path(args.output_cert)
    key_path = Path(args.output_key)
    csr_path = Path(args.output_csr)

    for path, desc in [(cert_path, "client certificate"), (key_path, "private key"), (csr_path, "CSR")]:
        if path.exists():
            print(f"[!] Refusing to overwrite existing {desc} at {path}")
            sys.exit(1)

    cmd = [
        "openssl",
        "req",
        "-new",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        str(key_path),
        "-out",
        str(csr_path),
        "-subj",
        args.subject,
    ]
    cfg_path = None
    if args.san:
        config = dedent(
            f"""
            [req]
            distinguished_name = dn
            req_extensions = req_ext
            [dn]
            [req_ext]
            subjectAltName = {args.san}
            """
        ).strip()
        tmp = tempfile.NamedTemporaryFile("w", delete=False)
        try:
            tmp.write(config)
            tmp.flush()
        finally:
            tmp.close()
        cfg_path = Path(tmp.name)
        cmd.extend(["-config", str(cfg_path), "-extensions", "req_ext"])

    try:
        subprocess.run(cmd, check=True)
    except FileNotFoundError:
        print("[!] openssl is required to generate the CSR but was not found on PATH")
        if cfg_path:
            cfg_path.unlink(missing_ok=True)
        sys.exit(1)
    except subprocess.CalledProcessError as exc:
        print(f"[!] openssl exited with error code {exc.returncode}")
        if cfg_path:
            cfg_path.unlink(missing_ok=True)
        sys.exit(exc.returncode)
    else:
        print(f"[+] Generated TLS private key: {key_path}")
        print(f"[+] Generated CSR: {csr_path}")
        print("    Submit the CSR to your Admin X.509 CA to obtain the client certificate,")
        print(f"    then place the signed certificate at {cert_path}.")
    finally:
        if cfg_path:
            cfg_path.unlink(missing_ok=True)


def ensure_file(path: Path, description: str, remedy: str) -> None:
    if path.exists():
        return
    print(f"[!] {description} not found at {path}")
    if remedy:
        print(remedy)
    sys.exit(1)


def run_request(args) -> None:
    if not args.path.startswith("/"):
        args.path = "/" + args.path

    cert_path = Path(args.mtls_cert)
    key_path = Path(args.mtls_key)
    ensure_file(
        cert_path,
        "TLS client certificate",
        "Use 'admin_request.py generate-csr' to create a CSR, then have it signed by the Admin X.509 CA.",
    )
    ensure_file(
        key_path,
        "TLS client private key",
        "Use 'admin_request.py generate-csr' (or openssl) to create a new private key if needed.",
    )
    admin_key_path = Path(args.admin_key)
    admin_cert_path = Path(args.admin_cert)
    ensure_file(
        admin_key_path,
        "Admin Ed25519 private key",
        "Generate with: ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -C 'admin'",
    )
    ensure_file(
        admin_cert_path,
        "Admin OpenSSH certificate",
        "Request a signed certificate from the Admin SSH CA (ssh-keygen -s <ca> ...)",
    )

    if args.payload.startswith("@"):  # Load payload
        payload = Path(args.payload[1:]).read_text()
    else:
        payload = args.payload

    canon_payload = canonical_json(payload)
    nonce = args.nonce if args.nonce else os.urandom(16).hex()
    signing_string = build_signing_string(canon_payload, args.method, args.path, nonce)

    passphrase = None
    if args.prompt_passphrase:
        passphrase = getpass("Admin Ed25519 key passphrase: ") or None
    priv_key = load_ed25519_key(admin_key_path, passphrase)

    signature = sign_payload(priv_key, signing_string)
    admin_cert = admin_cert_path.read_text().replace("\n", "")

    headers = {
        "Content-Type": "application/json",
        "X-Admin-Cert": admin_cert,
        "X-Admin-Nonce": nonce,
        "X-Admin-Signature": signature,
    }

    url = "https://" + args.host.rstrip("/") + ":" + str(args.port) + args.path
    cert_tuple = (args.mtls_cert, args.mtls_key)
    verify = args.verify_ca if isinstance(args.verify_ca, bool) else args.verify_ca

    response = requests.request(
        args.method.upper(),
        url,
        headers=headers,
        data=payload.encode(),
        cert=cert_tuple,
        verify=verify,
    )

    print(f"{response.status_code} {response.reason}")
    if response.content:
        try:
            print(json.dumps(response.json(), indent=2))
        except ValueError:
            print(response.text)


def main():
    parser = argparse.ArgumentParser(description="Admin helper for kernel mTLS + detached signature requests")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # request subcommand
    request_parser = subparsers.add_parser("request", help="Send an authenticated admin request")
    request_parser.add_argument("--host", required=True, help="Kernel base host (hostname or IP)")
    request_parser.add_argument("--path", default="/auth/review", help="Request path (default: /auth/review)")
    request_parser.add_argument("--port", type=int, default=443, help="Port to use for the request (default: 443)")
    request_parser.add_argument("--method", default="POST", help="HTTP method (default: POST)")
    request_parser.add_argument("--payload", required=True, help="JSON payload string or @file.json")
    request_parser.add_argument("--nonce", help="Optional pre-generated nonce (hex)")
    request_parser.add_argument("--mtls-cert", default=str(Path.home() / ".ssh" / "admin-mtls.pem"), help="Client TLS certificate (PEM)")
    request_parser.add_argument("--mtls-key", default=str(Path.home() / ".ssh" / "admin-mtls-key.pem"), help="Client TLS private key (PEM)")
    request_parser.add_argument("--admin-cert", default=str(Path.home() / ".ssh" / "id_ed25519-cert.pub"), help="OpenSSH admin certificate (public)")
    request_parser.add_argument("--admin-key", default=str(Path.home() / ".ssh" / "id_ed25519"), help="OpenSSH admin private key (Ed25519)")
    request_parser.add_argument("--prompt-passphrase", action="store_true", help="Prompt for Ed25519 key passphrase if encrypted")
    request_parser.add_argument("--verify-ca", default=True, help="CA bundle for HTTPS verification (default: True -> system CA)")
    request_parser.set_defaults(func=run_request)

    # generate-csr subcommand
    csr_parser = subparsers.add_parser("generate-csr", help="Generate TLS private key + CSR for admin mTLS")
    csr_parser.add_argument("--output-cert", default=str(Path.home() / ".ssh" / "admin-mtls.pem"), help="Where the signed certificate should live (default: ~/.ssh/admin-mtls.pem)")
    csr_parser.add_argument("--output-key", default=str(Path.home() / ".ssh" / "admin-mtls-key.pem"), help="Output path for generated private key (default: ~/.ssh/admin-mtls-key.pem)")
    csr_parser.add_argument("--output-csr", default=str(Path.home() / ".ssh" / "admin-mtls.csr"), help="Output path for CSR (default: ~/.ssh/admin-mtls.csr)")
    csr_parser.add_argument("--subject", default="/CN=kernel-admin", help="Subject for the CSR (default: /CN=kernel-admin)")
    csr_parser.add_argument("--san", help="subjectAltName string, e.g. DNS:admin-ops or DNS:admin-ops,DNS:admin.example.com")
    csr_parser.set_defaults(func=generate_csr)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()