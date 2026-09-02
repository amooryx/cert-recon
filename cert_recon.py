#!/usr/bin/env python3
"""
Cert Recon — SSL/TLS Certificate Intelligence Gatherer
Extracts SAN, org, issuer, and expiry from certificates for recon.
Author: Omar Khalid (amooryx) | github.com/amooryx/cert-recon
AUTHORIZED USE ONLY.
"""

import argparse
import csv
import json
import socket
import ssl
import sys
import urllib.request
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

# ─── Certificate fetcher ──────────────────────────────────────────────────────
def get_cert_info(host: str, port: int = 443, timeout: float = 8.0) -> dict | None:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                der  = ssock.getpeercert(binary_form=True)
                return parse_cert(host, port, cert, ssock.cipher())
    except Exception as e:
        return {"host": host, "port": port, "error": str(e)}

def parse_cert(host: str, port: int, cert: dict, cipher: tuple) -> dict:
    subject    = dict(x[0] for x in cert.get("subject", []))
    issuer     = dict(x[0] for x in cert.get("issuer", []))
    san        = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
    not_before = cert.get("notBefore", "")
    not_after  = cert.get("notAfter", "")

    try:
        expiry    = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        days_left = (expiry - datetime.utcnow()).days
    except Exception:
        expiry    = None
        days_left = None

    return {
        "host":         host,
        "port":         port,
        "cn":           subject.get("commonName"),
        "org":          subject.get("organizationName"),
        "country":      subject.get("countryName"),
        "issuer_cn":    issuer.get("commonName"),
        "issuer_org":   issuer.get("organizationName"),
        "san":          san,
        "not_before":   not_before,
        "not_after":    not_after,
        "days_left":    days_left,
        "cipher":       f"{cipher[0]} {cipher[1]}bit" if cipher else None,
        "expired":      days_left is not None and days_left < 0,
        "expiring_soon": days_left is not None and 0 <= days_left <= 30,
    }

# ─── crt.sh passive discovery ─────────────────────────────────────────────────
def crtsh_lookup(domain: str) -> list[dict]:
    url = f"https://crt.sh/?q=%.{urllib.parse.quote(domain)}&output=json"
    try:
        with urllib.request.urlopen(url, timeout=15) as resp:
            entries = json.loads(resp.read())
            results = []
            seen    = set()
            for e in entries:
                cert_id = e.get("id")
                if cert_id in seen:
                    continue
                seen.add(cert_id)
                results.append({
                    "id":            cert_id,
                    "logged_at":     e.get("entry_timestamp"),
                    "not_before":    e.get("not_before"),
                    "not_after":     e.get("not_after"),
                    "common_name":   e.get("common_name"),
                    "name_value":    e.get("name_value"),
                    "issuer_name":   e.get("issuer_name"),
                })
            return results
    except Exception as e:
        print(f"[!] crt.sh error: {e}")
        return []

# ─── Reporting ────────────────────────────────────────────────────────────────
def print_cert(info: dict):
    if "error" in info:
        print(f"  [-] {info['host']}:{info['port']} — ERROR: {info['error']}")
        return
    days = info.get("days_left")
    flag = " [EXPIRED]" if info.get("expired") else (" [EXPIRING SOON]" if info.get("expiring_soon") else "")
    print(f"\n  [+] {info['host']}:{info['port']}{flag}")
    print(f"      CN       : {info.get('cn')}")
    print(f"      Org      : {info.get('org')}")
    print(f"      Issuer   : {info.get('issuer_cn')} ({info.get('issuer_org')})")
    print(f"      Valid    : {info.get('not_before')} → {info.get('not_after')} ({days} days left)")
    print(f"      Cipher   : {info.get('cipher')}")
    san = info.get("san", [])
    if san:
        print(f"      SAN ({len(san)}): {', '.join(san[:5])}" + (" ..." if len(san) > 5 else ""))

# ─── Entry ────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Cert Recon — TLS Certificate Intelligence (Authorized use only)",
    )
    subparsers = parser.add_subparsers(dest="cmd")

    scan_p = subparsers.add_parser("scan", help="Scan hosts for TLS certificate info")
    scan_p.add_argument("hosts", nargs="+", help="Hosts to scan (host or host:port)")
    scan_p.add_argument("--threads", type=int, default=20)
    scan_p.add_argument("--out", help="Output JSON file")

    passive_p = subparsers.add_parser("passive", help="Passive cert discovery via crt.sh")
    passive_p.add_argument("domain", help="Domain to search in crt.sh")
    passive_p.add_argument("--out",  help="Output JSON file")

    args = parser.parse_args()
    if not args.cmd:
        parser.print_help()
        sys.exit(1)

    if args.cmd == "scan":
        targets = []
        for h in args.hosts:
            if ":" in h:
                host, port = h.rsplit(":", 1)
                targets.append((host, int(port)))
            else:
                targets.append((h, 443))
        print(f"[*] Scanning {len(targets)} targets...")
        with ThreadPoolExecutor(max_workers=args.threads) as exe:
            results = list(exe.map(lambda t: get_cert_info(*t), targets))
        for r in results:
            print_cert(r)
        if args.out:
            with open(args.out, "w") as f:
                json.dump(results, f, indent=2)
            print(f"\n[*] Results → {args.out}")

    elif args.cmd == "passive":
        print(f"[*] Querying crt.sh for *.{args.domain} ...")
        entries = crtsh_lookup(args.domain)
        print(f"[+] {len(entries)} certificate entries found")
        names = set()
        for e in entries:
            for n in e.get("name_value", "").split("\n"):
                names.add(n.strip().lstrip("*."))
        print(f"[+] Unique names: {len(names)}")
        for n in sorted(names):
            print(f"    {n}")
        if args.out:
            with open(args.out, "w") as f:
                json.dump({"entries": entries, "names": sorted(names)}, f, indent=2)
            print(f"[*] Results → {args.out}")

if __name__ == "__main__":
    main()
