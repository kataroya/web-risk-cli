"""URL canonicalization and SHA-256 hashing module.

Canonicalizes URLs according to the Google Web Risk Update API specification,
then generates SHA-256 hashes for the URL and its suffix/prefix combinations.

Reference: https://cloud.google.com/web-risk/docs/urls-hashing
"""

import hashlib
import ipaddress
import re
import struct
from urllib.parse import unquote, urlparse


def _unescape_until_stable(url: str) -> str:
    """Repeatedly percent-decode until the URL no longer changes."""
    prev = None
    while prev != url:
        prev = url
        url = unquote(url)
    return url


def _remove_tab_cr_lf(url: str) -> str:
    """Remove raw tab (0x09), CR (0x0d), and LF (0x0a) characters.

    Does NOT remove percent-encoded versions like %0a.
    """
    return url.replace("\t", "").replace("\r", "").replace("\n", "")


def _percent_escape(url: str) -> str:
    """Percent-escape characters <= ASCII 32, >= 127, '#', and '%'.

    Escapes use uppercase hex characters (%XX).
    """
    result = []
    for char in url:
        code = ord(char)
        if code <= 32 or code >= 127 or char in ("#", "%"):
            result.append(f"%{code:02X}")
        else:
            result.append(char)
    return "".join(result)


def _parse_ip_octal_hex(host: str) -> str | None:
    """Parse IP addresses with octal, hex, or fewer than 4 components.

    Handles formats like:
      0x7f.0x0.0x0.0x1  -> 127.0.0.1
      0177.0.0.01        -> 127.0.0.1
      2130706433          -> 127.0.0.1 (single 32-bit int)
      0x7f000001          -> 127.0.0.1
      127.0.1             -> 127.0.0.1 (3 components)

    Returns normalized dotted-decimal string or None if not a valid IP.
    """
    parts = host.split(".")
    if not parts or len(parts) > 4:
        return None

    # All parts must be numeric (decimal, octal, or hex)
    values = []
    for part in parts:
        part = part.strip()
        if not part:
            return None
        try:
            if part.startswith(("0x", "0X")):
                values.append(int(part, 16))
            elif part.startswith("0") and len(part) > 1 and part.isdigit():
                values.append(int(part, 8))
            else:
                values.append(int(part, 10))
        except ValueError:
            return None

    # Expand to 4 octets based on number of components
    if len(values) == 1:
        # Single 32-bit value
        ip_int = values[0]
    elif len(values) == 2:
        # a.b -> a.0.0.b (first is top octet, last is remaining 24 bits)
        ip_int = (values[0] << 24) | (values[1] & 0xFFFFFF)
    elif len(values) == 3:
        # a.b.c -> a.b.0.c (last is remaining 16 bits)
        ip_int = (values[0] << 24) | (values[1] << 16) | (values[2] & 0xFFFF)
    elif len(values) == 4:
        ip_int = (values[0] << 24) | (values[1] << 16) | (values[2] << 8) | values[3]
    else:
        return None

    if ip_int < 0 or ip_int > 0xFFFFFFFF:
        return None

    octets = struct.pack("!I", ip_int)
    return f"{octets[0]}.{octets[1]}.{octets[2]}.{octets[3]}"


def _normalize_host(host: str) -> str:
    """Canonicalize hostname: strip dots, collapse, normalize IP, lowercase, IDN->Punycode."""
    host = host.strip(".")
    # Collapse consecutive dots into one
    host = re.sub(r"\.{2,}", ".", host)

    # IDN (Internationalized Domain Name) -> ASCII Punycode
    try:
        host = host.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        pass

    host = host.lower()

    # Normalize IP addresses: try octal/hex/short form first, then standard
    parsed_ip = _parse_ip_octal_hex(host)
    if parsed_ip is not None:
        return parsed_ip

    try:
        import ipaddress
        ip = ipaddress.ip_address(host)
        return str(ip)
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
    """Canonicalize a URL according to the Google Web Risk specification.

    Order of operations (per spec):
      1. Remove tab, CR, LF (raw chars only, not %0a etc.)
      2. Remove fragment (#...)
      3. Repeatedly percent-unescape until stable
      4. Add scheme if missing, ensure path has leading /
      5. Canonicalize host (strip dots, IDN->punycode, IP normalization, lowercase)
      6. Canonicalize path (resolve /../, /./, collapse //)
      7. Percent-escape chars <= 32, >= 127, '#', '%' with uppercase hex
    """
    url = url.strip()

    # Step 1: Remove raw tab, CR, LF
    url = _remove_tab_cr_lf(url)

    # Step 2: Remove fragment
    url = url.split("#")[0]

    # Step 3: Repeatedly unescape
    url = _unescape_until_stable(url)

    # Step 4: Add scheme if missing
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    host = _normalize_host(parsed.hostname or "")
    path = _normalize_path(parsed.path)

    # Reconstruct (preserve query string as-is, no path canonicalization on query)
    canonical = f"{parsed.scheme}://{host}{path}"
    if parsed.query:
        canonical += f"?{parsed.query}"

    # Step 7: Percent-escape special characters
    canonical = _percent_escape(canonical)

    return canonical


def _generate_host_suffixes(host: str) -> list[str]:
    """Generate host suffix list per Google spec.

    1. The exact hostname.
    2. Up to 4 hostnames formed by starting with the last 5 components
       and successively removing the leading component.
       Skip if host is an IP address.

    Example: a.b.c.d.e.f.g -> [a.b.c.d.e.f.g, c.d.e.f.g, d.e.f.g, e.f.g, f.g]
    """
    suffixes = [host]

    # If the host is an IP address, don't generate additional suffixes
    try:
        ipaddress.ip_address(host)
        return suffixes
    except ValueError:
        pass

    parts = host.split(".")
    # Start from the last 5 components (skip intermediate ones for long hosts)
    start = max(1, len(parts) - 5)
    for i in range(start, len(parts) - 1):
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
    """Return a list of SHA-256 full hashes (32 bytes each) for all expressions generated from the URL."""
    expressions = generate_url_expressions(url)
    return [hashlib.sha256(expr.encode("utf-8")).digest() for expr in expressions]
