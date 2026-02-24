"""Threat list synchronization module.

Keeps the local DB up-to-date by calling the ComputeThreatListDiff API.
"""

from datetime import datetime, timezone

from google.cloud import webrisk_v1

import threat_hash_store


# Threat types to synchronize
ALL_THREAT_TYPES = [
    webrisk_v1.ThreatType.MALWARE,
    webrisk_v1.ThreatType.SOCIAL_ENGINEERING,
    webrisk_v1.ThreatType.UNWANTED_SOFTWARE,
]

# Default constraints
DEFAULT_MAX_DIFF_ENTRIES = 2**16       # 65536
DEFAULT_MAX_DATABASE_ENTRIES = 2**18   # 262144
DEFAULT_COMPRESSION = webrisk_v1.CompressionType.RAW


def _parse_raw_hashes(additions) -> list[bytes]:
    """Extract individual hash prefixes from a ThreatEntryAdditions object.

    additions: single ThreatEntryAdditions object
    additions.raw_hashes: repeated RawHashes (each with prefix_size + raw_hashes bytes)
    """
    prefixes: list[bytes] = []
    if not additions or not additions.raw_hashes:
        return prefixes
    for rh in additions.raw_hashes:
        if rh.prefix_size == 0 or not rh.raw_hashes:
            continue
        size = rh.prefix_size
        data = rh.raw_hashes
        prefixes.extend(data[i : i + size] for i in range(0, len(data), size))
    return prefixes


def _parse_removal_indices(removals) -> list[int]:
    """Extract removal indices from a ThreatEntryRemovals object.

    removals: single ThreatEntryRemovals object
    removals.raw_indices.indices: list of indices to remove
    """
    if not removals or not removals.raw_indices or not removals.raw_indices.indices:
        return []
    return list(removals.raw_indices.indices)


def sync_threat_list(
    threat_type: webrisk_v1.ThreatType,
    client: webrisk_v1.WebRiskServiceClient | None = None,
) -> dict:
    """Fetch the diff for a single threat_type and apply it to the local DB.

    Returns:
        A summary dict of the sync result.
    """
    if client is None:
        client = webrisk_v1.WebRiskServiceClient()

    threat_type_value = int(threat_type)
    version_token = threat_hash_store.get_version_token(threat_type_value)

    # Build request
    constraints = webrisk_v1.ComputeThreatListDiffRequest.Constraints(
        max_diff_entries=DEFAULT_MAX_DIFF_ENTRIES,
        max_database_entries=DEFAULT_MAX_DATABASE_ENTRIES,
        supported_compressions=[DEFAULT_COMPRESSION],
    )
    request = webrisk_v1.ComputeThreatListDiffRequest(
        threat_type=threat_type,
        version_token=version_token,
        constraints=constraints,
    )

    response = client.compute_threat_list_diff(request)
    response_type = response.response_type

    result = {
        "threat_type": threat_type.name,
        "response_type": response_type.name,
        "additions": 0,
        "removals": 0,
    }

    if response_type == webrisk_v1.ComputeThreatListDiffResponse.ResponseType.RESET:
        # Full snapshot: delete all existing data and insert everything
        prefixes = _parse_raw_hashes(response.additions)
        threat_hash_store.reset_prefixes(threat_type_value, prefixes)
        result["additions"] = len(prefixes)

    elif response_type == webrisk_v1.ComputeThreatListDiffResponse.ResponseType.DIFF:
        # Incremental diff update
        additions = _parse_raw_hashes(response.additions)
        removals = _parse_removal_indices(response.removals)
        threat_hash_store.apply_diff(threat_type_value, additions, removals)
        result["additions"] = len(additions)
        result["removals"] = len(removals)

    else:
        result["note"] = "RESPONSE_TYPE_UNSPECIFIED - no changes"

    # Save metadata
    next_diff = None
    if response.recommended_next_diff:
        next_diff = response.recommended_next_diff.replace(tzinfo=timezone.utc)

    threat_hash_store.save_metadata(
        threat_type_value,
        response.new_version_token,
        next_diff,
    )

    result["prefix_count"] = threat_hash_store.get_prefix_count(threat_type_value)
    return result


def sync_all(client: webrisk_v1.WebRiskServiceClient | None = None) -> list[dict]:
    """Synchronize all threat types."""
    if client is None:
        client = webrisk_v1.WebRiskServiceClient()

    results = []
    for tt in ALL_THREAT_TYPES:
        print(f"[SYNC] Syncing {tt.name}...")
        r = sync_threat_list(tt, client)
        print(f"  -> {r['response_type']} | +{r['additions']} -{r['removals']} | total {r['prefix_count']}")
        results.append(r)
    return results


def should_sync(threat_type: webrisk_v1.ThreatType) -> bool:
    """Return True if recommended_next_diff has passed or no metadata exists."""
    next_diff = threat_hash_store.get_next_diff_time(int(threat_type))
    if next_diff is None:
        return True
    now = datetime.now(timezone.utc)
    # next_diff에 tzinfo가 없으면 UTC로 간주
    if next_diff.tzinfo is None:
        next_diff = next_diff.replace(tzinfo=timezone.utc)
    return now >= next_diff
