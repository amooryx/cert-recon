import json, urllib.request, urllib.error, rclib

def run(ctx):
    apex = ctx.target.lstrip("*.").lower()
    url = f"https://crt.sh/?q=%25.{apex}&output=json"
    ctx.info("querying Certificate Transparency (crt.sh)")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "redcell/cert-recon"})
        raw = urllib.request.urlopen(req, timeout=40).read()
        entries = json.loads(raw)
    except (urllib.error.URLError, json.JSONDecodeError, TimeoutError) as e:
        ctx.err(f"crt.sh query failed: {e}"); return 1
    names = set()
    for e in entries:
        for n in str(e.get("name_value", "")).splitlines():
            n = n.strip().lstrip("*.").lower()
            if n.endswith(apex):
                names.add(n)
    for n in sorted(names):
        ctx.good(n)
    ctx.data["subdomains"] = sorted(names)
    ctx.info(f"{len(names)} unique names from {len(entries)} certificates")
    if names:
        ctx.finding(f"{len(names)} subdomains discovered via CT logs", "info",
                    detail=apex, count=len(names))
    return 0

rclib.main("cert-recon", "Certificate Transparency subdomain mining", run)
