#!/usr/bin/env python3
"""nym maestro PKI — local CA and node enrollment (runs on your Mac).

    python pki.py init                 create CA + orchestrator client cert
    python pki.py enroll CH01          issue a server cert + build a deploy bundle
    python pki.py enroll CH01 --ip 1.2.3.4 --port 8443
    python pki.py list                 show issued bundles

The CA private key never leaves this machine. Each node only receives its own
server cert/key plus the CA's public cert (to verify the orchestrator).
"""
import argparse
import datetime
import ipaddress
import os
import shutil
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT = Path(__file__).resolve().parent
AGENT_DIR = ROOT / "agent"
DIST_ROOT = ROOT / "dist"


def home_base() -> Path:
    return Path.home() / ".nym-maestro"


def pki_dir() -> Path:
    return Path(os.environ.get("MAESTRO_PKI") or (home_base() / "pki"))


def default_db() -> str:
    return os.environ.get("MAESTRO_DB") or str(home_base() / "maestro.db")


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def _gen_key():
    return ec.generate_private_key(ec.SECP256R1())


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _write_key(p: Path, key):
    p.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    os.chmod(p, 0o600)


def _write_cert(p: Path, cert):
    p.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def _make_leaf(ca_key, ca_cert, cn, server, ip=None):
    key = _gen_key()
    eku = ExtendedKeyUsageOID.SERVER_AUTH if server else ExtendedKeyUsageOID.CLIENT_AUTH
    b = (x509.CertificateBuilder()
         .subject_name(_name(cn))
         .issuer_name(ca_cert.subject)
         .public_key(key.public_key())
         .serial_number(x509.random_serial_number())
         .not_valid_before(_now() - datetime.timedelta(minutes=5))
         .not_valid_after(_now() + datetime.timedelta(days=825))
         .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
         .add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
         .add_extension(
             x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
             critical=False)
         .add_extension(
             x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                 ca_cert.extensions.get_extension_for_class(
                     x509.SubjectKeyIdentifier).value),
             critical=False))
    if server and ip:
        b = b.add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(ip))]),
            critical=False)
    return b.sign(ca_key, hashes.SHA256()), key


def _load_ca(d: Path):
    ca_key = load_pem_private_key((d / "ca.key").read_bytes(), None)
    ca_cert = x509.load_pem_x509_certificate((d / "ca.crt").read_bytes())
    return ca_key, ca_cert


def init_ca(d: Path, force=False):
    d.mkdir(parents=True, exist_ok=True)
    if (d / "ca.crt").exists() and not force:
        raise SystemExit(f"CA already exists at {d} (use --force to overwrite)")
    ca_key = _gen_key()
    ca_cert = (x509.CertificateBuilder()
               .subject_name(_name("nym maestro CA"))
               .issuer_name(_name("nym maestro CA"))
               .public_key(ca_key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(_now() - datetime.timedelta(minutes=5))
               .not_valid_after(_now() + datetime.timedelta(days=3650))
               .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
               .add_extension(x509.KeyUsage(
                   digital_signature=False, content_commitment=False,
                   key_encipherment=False, data_encipherment=False,
                   key_agreement=False, key_cert_sign=True, crl_sign=True,
                   encipher_only=False, decipher_only=False), critical=True)
               .add_extension(
                   x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
                   critical=False)
               .sign(ca_key, hashes.SHA256()))
    _write_key(d / "ca.key", ca_key)
    _write_cert(d / "ca.crt", ca_cert)
    client_cert, client_key = _make_leaf(ca_key, ca_cert, "nym-maestro-orchestrator", server=False)
    _write_cert(d / "orchestrator.crt", client_cert)
    _write_key(d / "orchestrator.key", client_key)
    return ca_cert


def enroll(d: Path, name, ip, port, dist_root=DIST_ROOT, agent_dir=AGENT_DIR):
    ca_key, ca_cert = _load_ca(d)
    cert, key = _make_leaf(ca_key, ca_cert, name, server=True, ip=ip)
    out = dist_root / name
    out.mkdir(parents=True, exist_ok=True)
    _write_cert(out / "server.crt", cert)
    _write_key(out / "server.key", key)
    shutil.copy(d / "ca.crt", out / "ca.crt")
    shutil.copy(agent_dir / "agent.py", out / "agent.py")
    shutil.copy(agent_dir / "install.sh", out / "install.sh")
    shutil.copy(agent_dir / "nym-maestro-agent.service", out / "nym-maestro-agent.service")
    (out / "agent.env").write_text(
        f"MAESTRO_AGENT_PORT={port}\n"
        "MAESTRO_AGENT_CERTDIR=/etc/nym-maestro-agent\n"
        "MAESTRO_NYM_PORT=8080\n"
        "MAESTRO_NYM_SERVICE=nym-node.service\n")
    fp = cert.fingerprint(hashes.SHA256()).hex()
    return out, fp


# --- DB helpers (resolve node by name, pin fingerprint) --------------------

def _open_store():
    sys.path.insert(0, str(ROOT))
    from store import Store
    return Store(default_db(), (ROOT / "schema.sql").read_text())


def _resolve_node(name):
    store = _open_store()
    try:
        for n in store.list_nodes():
            if n["name"].lower() == name.lower():
                return store, n
    finally:
        pass
    store.close()
    return None, None


# --- CLI -------------------------------------------------------------------

def cmd_init(args):
    d = pki_dir()
    init_ca(d, force=args.force)
    print(f"CA + orchestrator client cert written to {d}")
    print("  ca.crt / ca.key            (keep ca.key private — never copy to a node)")
    print("  orchestrator.crt / .key    (used by the orchestrator to authenticate)")


def cmd_enroll(args):
    d = pki_dir()
    if not (d / "ca.crt").exists():
        raise SystemExit("no CA yet — run: python pki.py init")

    ip, port = args.ip, args.port
    store = None
    if not ip:
        store, node = _resolve_node(args.name)
        if not node:
            raise SystemExit(
                f"node '{args.name}' not found in the registry — add it in the UI "
                f"first, or pass --ip")
        ip = node["ip"]
        port = port or node["agent_port"]
    port = port or 8443

    out, fp = enroll(d, args.name, ip, port)

    # Pin the agent's cert fingerprint in the registry if the node exists.
    if store is None:
        store, node = _resolve_node(args.name)
    if store and node:
        store.update_node(node["uid"], {"agent_fp": fp})
        store.close()

    print(f"enrolled {args.name}  ({ip}:{port})")
    print(f"  bundle:      {out}")
    print(f"  cert sha256: {fp}")
    print()
    print("deploy:")
    print(f"  scp -r {out} root@{ip}:/tmp/nym-maestro-agent")
    print(f"  ssh root@{ip} 'cd /tmp/nym-maestro-agent && bash install.sh'")


def cmd_list(args):
    if not DIST_ROOT.exists():
        print("no bundles yet")
        return
    for p in sorted(DIST_ROOT.iterdir()):
        if p.is_dir():
            print(p.name)


def main():
    ap = argparse.ArgumentParser(prog="pki")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("init", help="create the CA + orchestrator client cert")
    p.add_argument("--force", action="store_true", help="overwrite an existing CA")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("enroll", help="issue a server cert and build a deploy bundle")
    p.add_argument("name")
    p.add_argument("--ip", help="node IP (default: looked up from the registry)")
    p.add_argument("--port", type=int, help="agent port (default: from registry or 8443)")
    p.set_defaults(func=cmd_enroll)

    p = sub.add_parser("list", help="list issued bundles")
    p.set_defaults(func=cmd_list)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
