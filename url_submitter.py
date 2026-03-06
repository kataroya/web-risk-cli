"""Submit URI module for Google Web Risk API.

Submits suspicious URLs to Google's Safe Browsing blocklist for review.
This is a separate workflow from the Update API (ComputeThreatListDiff / SearchHashes).
The Update API *consumes* threat data; SubmitUri *contributes* threat data to Google.

The SubmitUri call returns a Long Running Operation (LRO). The operation completes
when Google finishes reviewing the submission (this can take minutes to hours).

Requirements:
  - The calling GCP project must be allowlisted for SubmitUri.
    (Contact your Google Cloud sales representative or Customer Engineer.)
  - Web Risk API must be enabled on the project.
"""

from __future__ import annotations

import time
from typing import Any

from google.cloud import webrisk_v1


# ---------------------------------------------------------------------------
# Enum helpers — provide human-friendly names ↔ API enum values
# ---------------------------------------------------------------------------

# AbuseType enum used in ThreatInfo (subset of ThreatType)
ABUSE_TYPES = {
    "MALWARE": webrisk_v1.ThreatInfo.AbuseType.MALWARE,
    "SOCIAL_ENGINEERING": webrisk_v1.ThreatInfo.AbuseType.SOCIAL_ENGINEERING,
    "UNWANTED_SOFTWARE": webrisk_v1.ThreatInfo.AbuseType.UNWANTED_SOFTWARE,
}

CONFIDENCE_LEVELS = {
    "LOW": webrisk_v1.ThreatInfo.Confidence.ConfidenceLevel.LOW,
    "MEDIUM": webrisk_v1.ThreatInfo.Confidence.ConfidenceLevel.MEDIUM,
    "HIGH": webrisk_v1.ThreatInfo.Confidence.ConfidenceLevel.HIGH,
}

JUSTIFICATION_LABELS = {
    "MANUAL_VERIFICATION": webrisk_v1.ThreatInfo.ThreatJustification.JustificationLabel.MANUAL_VERIFICATION,
    "USER_REPORT": webrisk_v1.ThreatInfo.ThreatJustification.JustificationLabel.USER_REPORT,
    "AUTOMATED_REPORT": webrisk_v1.ThreatInfo.ThreatJustification.JustificationLabel.AUTOMATED_REPORT,
}

_PLATFORM_ENUM = webrisk_v1.ThreatDiscovery.Platform
PLATFORMS = {
    "ANDROID": _PLATFORM_ENUM.ANDROID,
    "IOS": _PLATFORM_ENUM.IOS,
    "MACOS": _PLATFORM_ENUM.MACOS,
    "WINDOWS": _PLATFORM_ENUM.WINDOWS,
}

# Long Running Operation states
_OP_STATE = webrisk_v1.SubmitUriMetadata.State
OPERATION_STATES = {
    _OP_STATE.STATE_UNSPECIFIED: "STATE_UNSPECIFIED",
    _OP_STATE.RUNNING: "RUNNING",
    _OP_STATE.SUCCEEDED: "SUCCEEDED",
    _OP_STATE.CANCELLED: "CANCELLED",
    _OP_STATE.FAILED: "FAILED",
    _OP_STATE.CLOSED: "CLOSED",
}


# ---------------------------------------------------------------------------
# Core functions
# ---------------------------------------------------------------------------

def submit_uri(
    project_id: str,
    uri: str,
    *,
    threat_type: str = "SOCIAL_ENGINEERING",
    confidence: str = "MEDIUM",
    justification_labels: list[str] | None = None,
    justification_comments: list[str] | None = None,
    platform: str | None = None,
    region_codes: list[str] | None = None,
    verbose: bool = False,
) -> dict[str, Any]:
    """Submit a URI to Google Web Risk for review.

    Args:
        project_id: GCP project ID (e.g. "my-project-123").
        uri: The suspicious URL to submit.
        threat_type: One of MALWARE, SOCIAL_ENGINEERING, UNWANTED_SOFTWARE.
        confidence: Confidence level — LOW, MEDIUM, or HIGH.
        justification_labels: Optional list of labels explaining why this URI
                              is considered a threat. Values: MANUAL_VERIFICATION,
                              USER_REPORT, AUTOMATED_REPORT.
        justification_comments: Free-form text describing why this URI is
                                considered a threat (list of strings).
        platform: Platform where the threat was discovered.
                  Values: ANDROID, IOS, MACOS, WINDOWS.
        region_codes: ISO 3166-1 alpha-2 region codes (e.g. ["US", "KR"]).
        verbose: If True, print step-by-step progress.

    Returns:
        dict with keys: operation_name, state, uri, threat_type
    """
    def log(msg: str) -> None:
        if verbose:
            print(f"  [Submit] {msg}")

    # --- Validate & resolve enum values ---
    if threat_type not in ABUSE_TYPES:
        raise ValueError(
            f"Invalid threat_type '{threat_type}'. "
            f"Choose from: {', '.join(ABUSE_TYPES)}"
        )
    if confidence not in CONFIDENCE_LEVELS:
        raise ValueError(
            f"Invalid confidence '{confidence}'. "
            f"Choose from: {', '.join(CONFIDENCE_LEVELS)}"
        )

    abuse_type_enum = ABUSE_TYPES[threat_type]
    confidence_enum = CONFIDENCE_LEVELS[confidence]

    log(f"URI: {uri}")
    log(f"Threat type: {threat_type}")
    log(f"Confidence: {confidence}")

    # --- Build Submission ---
    submission = webrisk_v1.Submission(uri=uri)
    log("Built Submission object")

    # --- Build ThreatInfo ---
    threat_confidence = webrisk_v1.ThreatInfo.Confidence(
        level=confidence_enum,
    )

    threat_justification = None
    if justification_labels or justification_comments:
        resolved_labels = []
        for label_name in (justification_labels or []):
            label_name_upper = label_name.upper()
            if label_name_upper not in JUSTIFICATION_LABELS:
                raise ValueError(
                    f"Invalid justification_label '{label_name}'. "
                    f"Choose from: {', '.join(JUSTIFICATION_LABELS)}"
                )
            resolved_labels.append(JUSTIFICATION_LABELS[label_name_upper])

        threat_justification = webrisk_v1.ThreatInfo.ThreatJustification(
            labels=resolved_labels,
            comments=justification_comments or [],
        )
        log(f"Justification labels: {justification_labels or []}")
        log(f"Justification comments: {justification_comments or []}")

    threat_info = webrisk_v1.ThreatInfo(
        abuse_type=abuse_type_enum,
        threat_confidence=threat_confidence,
        threat_justification=threat_justification,
    )
    log("Built ThreatInfo object")

    # --- Build ThreatDiscovery ---
    threat_discovery = None
    if platform or region_codes:
        td_kwargs: dict[str, Any] = {}

        if platform:
            platform_upper = platform.upper()
            if platform_upper not in PLATFORMS:
                raise ValueError(
                    f"Invalid platform '{platform}'. "
                    f"Choose from: {', '.join(PLATFORMS)}"
                )
            td_kwargs["platform"] = PLATFORMS[platform_upper]
            log(f"Platform: {platform_upper}")

        if region_codes:
            td_kwargs["region_codes"] = region_codes
            log(f"Region codes: {region_codes}")

        threat_discovery = webrisk_v1.ThreatDiscovery(**td_kwargs)
        log("Built ThreatDiscovery object")

    # --- Build SubmitUriRequest ---
    parent = f"projects/{project_id}"
    request = webrisk_v1.SubmitUriRequest(
        parent=parent,
        submission=submission,
        threat_info=threat_info,
        threat_discovery=threat_discovery,
    )
    log(f"Built SubmitUriRequest (parent={parent})")

    # --- Call API ---
    client = webrisk_v1.WebRiskServiceClient()
    log("Calling SubmitUri API...")
    operation = client.submit_uri(request=request)
    log(f"Operation started: {operation.operation.name}")

    return {
        "operation_name": operation.operation.name,
        "uri": uri,
        "threat_type": threat_type,
    }


def poll_operation(
    operation_name: str,
    *,
    timeout: int = 600,
    poll_interval: int = 10,
    verbose: bool = False,
) -> dict[str, Any]:
    """Poll a SubmitUri Long Running Operation until it reaches a terminal state.

    Args:
        operation_name: The operation resource name returned by submit_uri().
        timeout: Maximum seconds to wait (default 600 = 10 minutes).
        poll_interval: Seconds between each poll (default 10).
        verbose: If True, print progress.

    Returns:
        dict with keys: operation_name, state, done
    """
    from google.api_core import operations_v1
    from google.cloud.webrisk_v1.services.web_risk_service.transports.grpc import (
        WebRiskServiceGrpcTransport,
    )

    def log(msg: str) -> None:
        if verbose:
            print(f"  [Poll] {msg}")

    # Get a transport-level operations client
    transport = WebRiskServiceGrpcTransport()
    ops_client = operations_v1.OperationsClient(transport.grpc_channel)

    elapsed = 0
    log(f"Polling operation: {operation_name}")
    log(f"Timeout: {timeout}s, interval: {poll_interval}s")

    while elapsed < timeout:
        op = ops_client.get_operation(operation_name)

        if op.done:
            # Decode metadata to get the final state
            state_name = _get_state_from_metadata(op.metadata)
            log(f"Operation completed. State: {state_name}")
            return {
                "operation_name": operation_name,
                "state": state_name,
                "done": True,
            }

        state_name = _get_state_from_metadata(op.metadata)
        log(f"State: {state_name} ... (elapsed {elapsed}s)")
        time.sleep(poll_interval)
        elapsed += poll_interval

    log(f"Timeout after {timeout}s. Operation may still be running.")
    return {
        "operation_name": operation_name,
        "state": "TIMEOUT",
        "done": False,
    }


def _get_state_from_metadata(metadata_any) -> str:
    """Extract the state string from an Operation's metadata (Any protobuf)."""
    if metadata_any is None:
        return "UNKNOWN"
    try:
        submit_metadata = webrisk_v1.SubmitUriMetadata()
        if hasattr(metadata_any, "Unpack"):
            metadata_any.Unpack(submit_metadata._pb)
        elif hasattr(metadata_any, "unpack"):
            metadata_any.unpack(submit_metadata._pb)
        else:
            # Try direct type_url parsing
            submit_metadata = webrisk_v1.SubmitUriMetadata.deserialize(
                metadata_any.value
            )
        return OPERATION_STATES.get(submit_metadata.state, str(submit_metadata.state))
    except Exception:
        return "UNKNOWN"
