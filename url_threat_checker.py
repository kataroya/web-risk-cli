"""URL threat checking module.

Local prefix matching -> SearchHashes API for full hash verification.
Results are cached until expire_time to avoid redundant API calls.
"""

from datetime import datetime, timedelta, timezone

from google.cloud import webrisk_v1

import threat_hash_store
import url_canonicalizer
from threat_list_syncer import ALL_THREAT_TYPES

# Default cache TTL for safe URLs (no expire_time from API)
SAFE_URL_CACHE_TTL = timedelta(minutes=30)


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
    url_hashes = url_canonicalizer.compute_url_hashes(url)
    log(f"Generated {len(url_hashes)} hash expressions")

    result = {
        "url": url,
        "safe": True,
        "threats": [],
        "cached": False,
    }

    # Step 1: Local prefix matching
    matched_hashes: list[bytes] = []
    for full_hash in url_hashes:
        matched_types = threat_hash_store.lookup_prefix(full_hash)
        if matched_types:
            matched_hashes.append(full_hash)

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
    for full_hash in matched_hashes:
        prefix = full_hash[:4]
        if prefix in seen_prefixes:
            continue
        seen_prefixes.add(prefix)

        log(f"Sending hash prefix {prefix.hex()} to Google SearchHashes API...")
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
