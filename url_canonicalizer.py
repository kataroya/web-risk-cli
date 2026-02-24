"""URL canonicalization and SHA-256 hashing module.

Canonicalizes URLs according to the Google Web Risk Update API specification,
then generates SHA-256 hashes for the URL and its suffix/prefix combinations.

Reference: https://cloud.google.com/web-risk/docs/urls-hashing
"""

import hashlib
import re
from urllib.parse import unquote, urlparse


def _unescape_until_stable(url: str) -> str:
    """Repeatedly percent-decode until the URL no longer changes."""
    prev = None
    while prev != url:
        prev = url
        url = unquote(url)
    return url


def _remove_tab_cr_lf(url: str) -> str:
    """Remove tab(\\t), CR(\\r), and LF(\\n) characters."""
    return url.replace("\t", "").replace("\r", "").replace("\n", "")


def _normalize_host(host: str) -> str:
    """Convert host to lowercase and strip leading/trailing dots."""
    host = host.strip(".")
    host = host.lower()
    # Collapse consecutive dots into one
    host = re.sub(r"\.{2,}", ".", host)

    # Normalize IP addresses to decimal form
    try:
        import ipaddress
        ip = ipaddress.ip_address(host)
        host = str(ip)
    except ValueError:
        pass

    return host


def _normalize_path(path: str) -> str:
    """Resolve /../ and /./ segments, and collapse // into /."""
    if not path:
        path = "/"

    # Resolve /./ and /../ segments
    parts = path.split("/")
    resolved: list[str] = []
    for part in parts:
        if part == ".":
            continue
        elif part == "..":
            if resolved:
                resolved.pop()
        else:
            resolved.append(part)

    normalized = "/".join(resolved)
    if not normalized.startswith("/"):
        normalized = "/" + normalized

    # Collapse consecutive slashes
    normalized = re.sub(r"/{2,}", "/", normalized)
    return normalized


def canonicalize(url: str) -> str:
    """Canonicalize a URL according to the Google Web Risk specification."""
    url = url.strip()
    url = _remove_tab_cr_lf(url)
    url = _unescape_until_stable(url)

    # Remove fragment (#...)
    url = url.split("#")[0]

    # Add scheme if missing
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    host = _normalize_host(parsed.hostname or "")
    path = _normalize_path(parsed.path)

    # Preserve query string as-is
    canonical = f"{parsed.scheme}://{host}{path}"
    if parsed.query:
        canonical += f"?{parsed.query}"

    return canonical


def _generate_host_suffixes(host: str) -> list[str]:
    """Generate host suffix list.

    Example: a.b.c.d.e.f.g -> [a.b.c.d.e.f.g, b.c.d.e.f.g, c.d.e.f.g, d.e.f.g, e.f.g]
    Up to 5 entries (full host + last 4 subdomain combinations).
    """
    parts = host.split(".")
    suffixes = [host]
    # Reduce down to at least 2 parts (e.g. example.com)
    for i in range(1, len(parts) - 1):
        suffix = ".".join(parts[i:])
        suffixes.append(suffix)
        if len(suffixes) >= 5:
            break
    return suffixes


def _generate_path_prefixes(path: str, query: str = "") -> list[str]:
    """Generate path prefix list.

    Includes full path + query, full path only, and /-delimited prefixes.
    Up to 6 entries.
    """
    prefixes = []
    if query:
        prefixes.append(f"{path}?{query}")
    prefixes.append(path)

    # Split path by / and generate prefixes
    parts = path.split("/")
    for i in range(1, len(parts)):
        prefix = "/".join(parts[:i]) + "/"
        if prefix != path and prefix not in prefixes:
            prefixes.append(prefix)
            if len(prefixes) >= 6:
                break

    return prefixes


def generate_url_expressions(url: str) -> list[str]:
    """Generate host/path expression combinations for lookup from a canonicalized URL.

    Returns up to 30 combinations per Google specification.
    """
    canonical = canonicalize(url)
    parsed = urlparse(canonical)
    host = parsed.hostname or ""
    path = parsed.path or "/"
    query = parsed.query or ""

    host_suffixes = _generate_host_suffixes(host)
    path_prefixes = _generate_path_prefixes(path, query)

    expressions = []
    for h in host_suffixes:
        for p in path_prefixes:
            expr = f"{h}{p}"
            if expr not in expressions:
                expressions.append(expr)
    return expressions


def compute_url_hashes(url: str) -> list[bytes]:
    """URL에서 생성되는 모든 expression의 SHA-256 full hash(32바이트) 목록을 반환한다."""
    expressions = generate_url_expressions(url)
    return [hashlib.sha256(expr.encode("utf-8")).digest() for expr in expressions]
