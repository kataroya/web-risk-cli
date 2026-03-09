"""URL threat checking module.

Local prefix matching -> SearchHashes API for full hash verification.
Results are cached until expire_time to avoid redundant API calls.
"""

import hashlib
from datetime import datetime, timedelta, timezone

from google.cloud import webrisk_v1

import threat_hash_store
import url_canonicalizer
from threat_list_syncer import ALL_THREAT_TYPES

# Default cache TTL for safe URLs (no expire_time from API)
SAFE_URL_CACHE_TTL = timedelta(minutes=30)

_THREAT_TYPE_NAMES = {1: "MALWARE", 2: "SOCIAL_ENGINEERING", 3: "UNWANTED_SOFTWARE"}


def check_url(
    url: str,
    client: webrisk_v1.WebRiskServiceClient | None = None,
    use_cache: bool = True,
    verbose: bool = False,
) -> dict:
    """Check whether a URL is listed in any threat list.

    Step 0: Check cache for a previous result
    Step 1: URL -> SHA-256 hashes -> local DB prefix matching
    Step 2: If matched, verify with SearchHashes API using full hash
    Step 3: Cache the result

    Returns:
        {
            "url": str,
            "safe": bool,
            "threats": [{"threat_type": str, "expire_time": str}, ...],
            "cached": bool  # True if result came from cache
        }
    """
    def log(msg: str) -> None:
        if verbose:
            print(f"  [{_step}] {msg}")

    _step = "Step 0"
    log("Checking cache...")
    # Step 0: Check cache
    if use_cache:
        cached = threat_hash_store.get_cached_result(url)
        if cached is not None:
            log(f"Cache HIT (expires: {cached.get('expire_time', 'N/A')})")
            return cached
        log("Cache MISS")
    else:
        log("Cache disabled, skipping")

    if client is None:
        client = webrisk_v1.WebRiskServiceClient()

    _step = "Step 1"
    canonical = url_canonicalizer.canonicalize(url)
    log(f"Canonicalized URL: {canonical}")

    # Generate expressions and show them in verbose mode
    expressions = url_canonicalizer.generate_url_expressions(url)
    url_hashes = [hashlib.sha256(expr.encode("utf-8")).digest() for expr in expressions]
    log(f"Generated {len(url_hashes)} hash expressions")

    if verbose:
        print()
        print("  ┌─ Suffix/Prefix Expressions & SHA-256 Hashes ────────────────────")
        for i, (expr, full_hash) in enumerate(zip(expressions, url_hashes)):
            prefix_4b = full_hash[:4].hex()
            print(f"  │ [{i}] {expr}")
            print(f"  │     full hash : {full_hash.hex()}")
            print(f"  │     4B prefix : {prefix_4b}")
        print("  └─────────────────────────────────────────────────────────────────")
        print()

    result = {
        "url": url,
        "safe": True,
        "threats": [],
        "cached": False,
    }

    # Step 1: Local prefix matching
    matched_hashes: list[bytes] = []
    matched_expressions: list[str] = []
    for expr, full_hash in zip(expressions, url_hashes):
        matched_types = threat_hash_store.lookup_prefix(full_hash)
        if matched_types:
            matched_hashes.append(full_hash)
            matched_expressions.append(expr)
            if verbose:
                type_names = [_THREAT_TYPE_NAMES.get(t, str(t)) for t in matched_types]
                print(f"  │ ✅ MATCH prefix={full_hash[:4].hex()} -> {', '.join(type_names)}")
                print(f"  │    expression: {expr}")
        elif verbose:
            print(f"  │ ❌ No match  prefix={full_hash[:4].hex()} <- {expr}")

    if verbose:
        print()

    log(f"Local prefix matches: {len(matched_hashes)}/{len(url_hashes)}")

    if not matched_hashes:
        log("No local match -> SAFE")
        # No local match -> safe, cache it
        _step = "Step 3"
        expire = datetime.now(timezone.utc) + SAFE_URL_CACHE_TTL
        threat_hash_store.save_cached_result(url, True, [], expire)
        log(f"Result cached (TTL: {SAFE_URL_CACHE_TTL})")
        return result

    # Step 2: Verify with SearchHashes API
    _step = "Step 2"
    # Call API with the first 4 bytes of each matched hash as prefix
    seen_prefixes = set()
    for idx, full_hash in enumerate(matched_hashes):
        prefix = full_hash[:4]
        if prefix in seen_prefixes:
            continue
        seen_prefixes.add(prefix)

        log(f"Sending hash prefix {prefix.hex()} to Google SearchHashes API...")
        if verbose:
            expr_name = matched_expressions[idx] if idx < len(matched_expressions) else "?"
            print(f"  │ request  : prefix={prefix.hex()} (from: {expr_name})")
            print(f"  │ full hash: {full_hash.hex()}")

        try:
            response = client.search_hashes(
                hash_prefix=prefix,
                threat_types=[
                    webrisk_v1.ThreatType.MALWARE,
                    webrisk_v1.ThreatType.SOCIAL_ENGINEERING,
                    webrisk_v1.ThreatType.UNWANTED_SOFTWARE,
                ],
            )
        except Exception as e:
            log(f"SearchHashes call FAILED: {e}")
            continue

        log(f"Received {len(response.threats)} threat entries from Google")

        if verbose:
            print(f"  │ API returned {len(response.threats)} threat entries:")
            for ti, threat in enumerate(response.threats):
                api_hash_hex = threat.hash.hex() if threat.hash else "(none)"
                tt_name = (
                    webrisk_v1.ThreatType(threat.threat_types[0]).name
                    if threat.threat_types
                    else "UNKNOWN"
                )
                is_our_hash = threat.hash in url_hashes
                marker = " ← MATCH (our URL!)" if is_our_hash else ""
                print(f"  │   [{ti}] {tt_name}: {api_hash_hex}{marker}")
            print()

        # Compare full hashes from API response against local URL hashes
        for threat in response.threats:
            # threat.hash is a single bytes value (not a list)
            if threat.hash in url_hashes:
                expire_str = ""
                if threat.expire_time:
                    et = threat.expire_time
                    expire_str = datetime.fromtimestamp(
                        et.timestamp(), tz=timezone.utc
                    ).isoformat()
                result["threats"].append(
                    {
                        "threat_type": webrisk_v1.ThreatType(
                            threat.threat_types[0]
                        ).name
                        if threat.threat_types
                        else "UNKNOWN",
                        "expire_time": expire_str,
                    }
                )

    if result["threats"]:
        result["safe"] = False
        log(f"THREAT DETECTED: {len(result['threats'])} match(es)")
    else:
        log("Full hash comparison: no match -> SAFE")

    # Step 3: Cache the result
    _step = "Step 3"
    if result["threats"]:
        # Use the earliest expire_time from threats
        expire_times = [
            datetime.fromisoformat(t["expire_time"])
            for t in result["threats"]
            if t.get("expire_time")
        ]
        expire = min(expire_times) if expire_times else datetime.now(timezone.utc) + SAFE_URL_CACHE_TTL
    else:
        expire = datetime.now(timezone.utc) + SAFE_URL_CACHE_TTL
    threat_hash_store.save_cached_result(url, result["safe"], result["threats"], expire)
    log(f"Result cached until {expire.isoformat()}")

    return result
