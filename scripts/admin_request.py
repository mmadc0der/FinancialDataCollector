#!/usr/bin/env python3
import argparse
import base64
import json
import sys
from pathlib import Path
from getpass import getpass

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
    except ValueError as exc:  # password required but missing
        if passphrase is None:
            raise ValueError("Key is password-protected; rerun with --prompt-passphrase") from exc
        raise

def sign_payload(priv_key, message: bytes) -> str:
    sig = priv_key.sign(message)
    return base64.b64encode(sig).decode()

def main():
    parser = argparse.ArgumentParser(description="Send admin requests to the kernel with detached Ed25519 signature.")
    parser.add_argument("--host", required=True, help="Kernel base URL (e.g. https://kernel.example.com:7600)")
    parser.add_argument("--path", default="/auth/review", help="Request path (default: /auth/review)")
    parser.add_argument("--method", default="POST", help="HTTP method (default: POST)")
    parser.add_argument("--payload", required=True, help="JSON payload string or @file.json")
    parser.add_argument("--nonce", required=False, help="Optional pre-generated nonce (hex).")
    parser.add_argument("--mtls-cert", default=str(Path.home() / ".ssh" / "admin-mtls.pem"), help="Client TLS certificate (PEM)")
    parser.add_argument("--mtls-key", default=str(Path.home() / ".ssh" / "admin-mtls-key.pem"), help="Client TLS private key (PEM)")
    parser.add_argument("--admin-cert", default=str(Path.home() / ".ssh" / "id_ed25519-cert.pub"), help="OpenSSH admin certificate (public)")
    parser.add_argument("--admin-key", default=str(Path.home() / ".ssh" / "id_ed25519"), help="OpenSSH admin private key (Ed25519)")
    parser.add_argument("--prompt-passphrase", action="store_true", help="Prompt for Ed25519 key passphrase if encrypted")
    parser.add_argument("--verify-ca", default=True, help="CA bundle for HTTPS verification (default: True -> system CA).")
    args = parser.parse_args()

    # Load payload
    if args.payload.startswith("@"):
        payload = Path(args.payload[1:]).read_text()
    else:
        payload = args.payload

    canon_payload = canonical_json(payload)

    # Nonce
    if args.nonce:
        nonce = args.nonce
    else:
        nonce = Path("/dev/urandom").read_bytes(16).hex()

    signing_string = build_signing_string(canon_payload, args.method, args.path, nonce)

    # Load private key
    passphrase = None
    if args.prompt_passphrase:
        passphrase = getpass("Admin Ed25519 key passphrase: ")
        if passphrase == "":
            passphrase = None
    priv_key = load_ed25519_key(Path(args.admin_key), passphrase)

    signature = sign_payload(priv_key, signing_string)
    admin_cert = Path(args.admin_cert).read_text().replace("\n", "")

    headers = {
        "Content-Type": "application/json",
        "X-Admin-Cert": admin_cert,
        "X-Admin-Nonce": nonce,
        "X-Admin-Signature": signature,
    }

    # POST request
    url = args.host.rstrip("/") + args.path
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

if __name__ == "__main__":
    main()