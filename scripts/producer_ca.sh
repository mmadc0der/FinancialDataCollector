#!/usr/bin/env bash
set -euo pipefail

# Producer CA utility
# Default CA location: modules.d/ssh/producer_ca (private) and producer_ca.pub (public)

ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
CA_DIR="$ROOT_DIR/modules.d/ssh"
CA_KEY="$CA_DIR/producer_ca"
CA_PUB="$CA_DIR/producer_ca.pub"

usage() {
  cat <<USAGE
Usage:
  $0 init-ca                      # generate producer CA ed25519 keypair under modules.d/ssh/
  $0 sign -k <producer_pub> \
        -I <key_id> -n <principal> [-V <validity>]   # sign a producer public key with CA

Examples:
  $0 init-ca
  $0 sign -k modules.d/producer-example/ssh/id_ed25519.pub -I producer-01 -n producer -V +52w

Notes:
  - After init-ca, copy the contents of $CA_PUB into kernel config: auth.producer_ssh_ca
  - The 'principal' (-n) is the name the producer cert asserts, typically 'producer'.
USAGE
}

cmd=${1:-}
case "$cmd" in
  init-ca)
    mkdir -p "$CA_DIR"
    if [[ -f "$CA_KEY" ]]; then
      echo "CA already exists at $CA_KEY" >&2
      exit 0
    fi
    ssh-keygen -t ed25519 -C "producer-ca" -f "$CA_KEY" -N ""
    echo "CA generated: $CA_KEY (private), $CA_PUB (public)"
    ;;
  sign)
    shift || true
    KEY=""; KEY_ID=""; PRINC=""; VALID="+52w"
    while [[ $# -gt 0 ]]; do
      case "$1" in
        -k) KEY="$2"; shift 2;;
        -I) KEY_ID="$2"; shift 2;;
        -n) PRINC="$2"; shift 2;;
        -V) VALID="$2"; shift 2;;
        *) echo "Unknown arg: $1"; usage; exit 1;;
      esac
    done
    if [[ -z "$KEY" || -z "$KEY_ID" || -z "$PRINC" ]]; then
      echo "Missing required args" >&2; usage; exit 1
    fi
    if [[ ! -f "$CA_KEY" ]]; then
      echo "CA private key not found at $CA_KEY. Run '$0 init-ca' first." >&2
      exit 1
    fi
    ssh-keygen -s "$CA_KEY" -I "$KEY_ID" -n "$PRINC" -V "$VALID" "$KEY"
    echo "Signed certificate: ${KEY%-pub}-cert.pub"
    ;;
  *)
    usage; exit 1;
    ;;
esac


