"""URL threat checking module.

Local prefix matching -> SearchHashes API for full hash verification.
"""

from google.cloud import webrisk_v1

import threat_hash_store
import url_canonicalizer
from threat_list_syncer import ALL_THREAT_TYPES


def check_url(
    url: str,
    client: webrisk_v1.WebRiskServiceClient | None = None,
) -> dict:
    """Check whether a URL is listed in any threat list.

    Step 1: URL -> SHA-256 hashes -> local DB prefix matching
    Step 2: If matched, verify with SearchHashes API using full hash

    Returns:
        {
            "url": str,
            "safe": bool,
            "threats": [{"threat_type": str, "expire_time": str}, ...]
        }
    """
    if client is None:
        client = webrisk_v1.WebRiskServiceClient()

    url_hashes = url_canonicalizer.compute_url_hashes(url)

    result = {
        "url": url,
        "safe": True,
        "threats": [],
    }

    # Step 1: Local prefix matching
    matched_hashes: list[bytes] = []
    for full_hash in url_hashes:
        matched_types = threat_hash_store.lookup_prefix(full_hash)
        if matched_types:
            matched_hashes.append(full_hash)

    if not matched_hashes:
        # No local match -> safe
        return result

    # Step 2: Verify with SearchHashes API
    # Call API with the first 4 bytes of each matched hash as prefix
    seen_prefixes = set()
    for full_hash in matched_hashes:
        prefix = full_hash[:4]
        if prefix in seen_prefixes:
            continue
        seen_prefixes.add(prefix)

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
            print(f"  [WARN] SearchHashes call failed: {e}")
            continue

        # Compare full hashes from API response against local URL hashes
        for threat in response.threats:
            # threat.hash is a single bytes value (not a list)
            if threat.hash in url_hashes:
                expire_str = ""
                if threat.expire_time:
                    expire_str = threat.expire_time.isoformat()
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

    return result
