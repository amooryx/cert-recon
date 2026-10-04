"""Read-only subdomain discovery from Certificate Transparency logs."""
import http.client
import ipaddress
import json
import urllib.error
import urllib.parse
import urllib.request

import rclib

SOURCE = "crt.sh Certificate Transparency"
REQUEST_TIMEOUT_SECONDS = 20
MAX_RESPONSE_BYTES = 5 * 1024 * 1024
MAX_CERTIFICATES = 25_000
MAX_NAMES = 10_000
MAX_NAME_CANDIDATES = 100_000
USER_AGENT = "cert-recon/1.0 (passive CT lookup)"


def normalize_domain(value):
    """Return a normalized ASCII DNS domain or raise ValueError."""
    value = value.strip()
    if value.endswith("."):
        value = value[:-1]
    if not value or value.startswith("*.") or any(c in value for c in "/:@?#\\"):
        raise ValueError("target must be a DNS domain, not a URL, wildcard, or host:port")

    try:
        domain = value.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("target is not a valid DNS domain") from exc

    if len(domain) > 253:
        raise ValueError("target exceeds the DNS domain length limit")
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        pass
    else:
        raise ValueError("target must be a DNS domain, not an IP address")
    labels = domain.split(".")
    if len(labels) < 2 or any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        or not all(ch.isalnum() or ch == "-" for ch in label)
        for label in labels
    ):
        raise ValueError("target must be a valid multi-label DNS domain")
    return domain


def fetch_certificates(domain):
    query = urllib.parse.urlencode({"q": f"%.{domain}", "output": "json"})
    request = urllib.request.Request(
        f"https://crt.sh/?{query}", headers={"User-Agent": USER_AGENT}
    )
    with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
        raw = response.read(MAX_RESPONSE_BYTES + 1)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ValueError("crt.sh response exceeded the 5 MiB limit")

    entries = json.loads(raw)
    if not isinstance(entries, list):
        raise ValueError("crt.sh returned an unexpected JSON shape")
    if len(entries) > MAX_CERTIFICATES:
        raise ValueError("crt.sh response exceeded the certificate limit")
    return entries


def run(ctx):
    try:
        apex = normalize_domain(ctx.target)
    except ValueError as exc:
        ctx.err(f"invalid target: {exc}")
        return 2

    ctx.info(f"querying {SOURCE} (read-only)")
    try:
        entries = fetch_certificates(apex)
    except urllib.error.HTTPError as exc:
        ctx.err(f"{SOURCE} request failed with HTTP status {exc.code}")
        return 1
    except (urllib.error.URLError, TimeoutError, OSError, http.client.HTTPException):
        ctx.err(f"{SOURCE} request failed (network error or timeout)")
        return 1
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        ctx.err(f"{SOURCE} response failed validation: {exc}")
        return 1

    names = set()
    results_truncated = False
    candidate_limit_reached = False
    candidates_examined = 0
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        for candidate in str(entry.get("name_value", "")).splitlines():
            if candidates_examined >= MAX_NAME_CANDIDATES:
                candidate_limit_reached = True
                break
            candidates_examined += 1
            name = candidate.strip().lower()
            if name.startswith("*."):
                name = name[2:]
            try:
                name = normalize_domain(name)
            except ValueError:
                continue
            if not name or not (name == apex or name.endswith("." + apex)):
                continue
            names.add(name)
            if len(names) > MAX_NAMES:
                names.remove(max(names))
                results_truncated = True
        if candidate_limit_reached:
            break

    results = sorted(names)
    results_truncated = results_truncated or candidate_limit_reached
    for name in results:
        ctx.good(name)
    ctx.data.update(
        {
            "source": SOURCE,
            "evidence": "Certificate Transparency certificate names; not DNS-verified",
            "certificates_examined": len(entries),
            "name_candidates_examined": candidates_examined,
            "subdomains": results,
            "results_truncated": results_truncated,
            "candidate_limit_reached": candidate_limit_reached,
        }
    )
    ctx.info(
        f"{len(results)} unique names from {len(entries)} CT certificates"
        + (" (processing limit reached; results may be incomplete)" if results_truncated else "")
    )
    if results:
        ctx.finding(
            f"{len(results)} names found in Certificate Transparency logs",
            "info",
            detail="CT evidence only; DNS resolution was not performed",
            source=SOURCE,
            count=len(results),
            results_truncated=results_truncated,
            candidate_limit_reached=candidate_limit_reached,
        )
    return 0


if __name__ == "__main__":
    rclib.main("cert-recon", "Certificate Transparency subdomain mining", run)
