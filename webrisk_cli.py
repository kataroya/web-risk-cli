#!/usr/bin/env python3
"""Web Risk Update API Client - CLI entry point.

Usage:
  # 1. Sync threat lists (required on first run)
  python webrisk_cli.py sync

  # 2. Check a URL for threats
  python webrisk_cli.py check "http://example.com"

  # 3. View local DB status
  python webrisk_cli.py status

Prerequisites:
  - Enable the Web Risk API in your GCP project
  - Set up authentication:
      export GOOGLE_APPLICATION_CREDENTIALS="/path/to/service-account.json"
    or
      gcloud auth application-default login
"""

import argparse
import sys

from google.cloud import webrisk_v1

import threat_hash_store
from url_threat_checker import check_url
from threat_list_syncer import ALL_THREAT_TYPES, should_sync, sync_all, sync_threat_list
from url_submitter import (
    ABUSE_TYPES,
    CONFIDENCE_LEVELS,
    JUSTIFICATION_LABELS,
    PLATFORMS,
    poll_operation,
    submit_uri,
)


def cmd_sync(args: argparse.Namespace) -> None:
    """Synchronize threat lists."""
    threat_hash_store.init_db()
    client = webrisk_v1.WebRiskServiceClient()

    if args.force:
        print("Starting full forced sync...\n")
        sync_all(client)
    else:
        print("Syncing only lists that need updating...\n")
        synced = False
        for tt in ALL_THREAT_TYPES:
            if should_sync(tt):
                r = sync_threat_list(tt, client)
                print(f"  {r['threat_type']}: {r['response_type']} | +{r['additions']} -{r['removals']} | total {r['prefix_count']}")
                synced = True
            else:
                print(f"  {tt.name}: Not yet due for update - skipped")
        if not synced:
            print("\nAll lists are already up to date.")

    print("\nSync complete.")


def cmd_check(args: argparse.Namespace) -> None:
    """Check a URL for threats."""
    threat_hash_store.init_db()
    client = webrisk_v1.WebRiskServiceClient()

    # Auto-sync if local DB is empty
    for tt in ALL_THREAT_TYPES:
        if threat_hash_store.get_prefix_count(int(tt)) == 0:
            print("Local DB is empty. Running initial sync...\n")
            sync_all(client)
            print()
            break

    url = args.url
    verbose = args.verbose
    print(f"Checking: {url}\n")
    result = check_url(url, client, verbose=verbose)

    if result.get("cached"):
        print("  (result from cache)")

    if result["safe"]:
        print("  Safe - no threats detected.")
    else:
        print("  Threat detected!")
        for t in result["threats"]:
            print(f"    - {t['threat_type']} (expires: {t['expire_time'] or 'N/A'})")


def cmd_status(args: argparse.Namespace) -> None:
    """Display local DB status."""
    threat_hash_store.init_db()


def cmd_cache_clear(args: argparse.Namespace) -> None:
    """Clear the URL check cache."""
    threat_hash_store.init_db()
    deleted = threat_hash_store.clear_cache()
    print(f"Cache cleared. {deleted} entries removed.")


def cmd_submit(args: argparse.Namespace) -> None:
    """Submit a suspicious URI to Google Web Risk for review."""
    verbose = args.verbose
    project_id = args.project

    # Parse optional justification labels (comma-separated)
    justification_labels = None
    if args.justification:
        justification_labels = [l.strip() for l in args.justification.split(",")]

    # Parse optional justification comments
    justification_comments = None
    if args.comment:
        justification_comments = [args.comment]

    # Parse optional region codes (comma-separated)
    region_codes = None
    if args.region:
        region_codes = [r.strip().upper() for r in args.region.split(",")]

    print(f"Submitting: {args.url}")
    print(f"  Threat type : {args.type}")
    print(f"  Confidence  : {args.confidence}")
    if justification_labels:
        print(f"  Justification: {', '.join(justification_labels)}")
    if justification_comments:
        print(f"  Comment     : {justification_comments[0]}")
    if args.platform:
        print(f"  Platform    : {args.platform}")
    if region_codes:
        print(f"  Regions     : {', '.join(region_codes)}")
    print()

    try:
        result = submit_uri(
            project_id=project_id,
            uri=args.url,
            threat_type=args.type,
            confidence=args.confidence,
            justification_labels=justification_labels,
            justification_comments=justification_comments,
            platform=args.platform,
            region_codes=region_codes,
            verbose=verbose,
        )
    except Exception as e:
        print(f"  Submit FAILED: {e}")
        sys.exit(1)

    print(f"  Submission accepted!")
    print(f"  Operation: {result['operation_name']}")

    # If --wait is specified, poll until the operation completes
    if args.wait:
        print(f"\n  Waiting for Google to process (timeout: {args.timeout}s)...")
        poll_result = poll_operation(
            result["operation_name"],
            timeout=args.timeout,
            poll_interval=args.interval,
            verbose=verbose,
        )
        print(f"\n  Final state: {poll_result['state']}")
        if not poll_result["done"]:
            print("  (Operation did not complete within timeout)")

    print("=== Local DB Status ===\n")
    for tt in ALL_THREAT_TYPES:
        tt_val = int(tt)
        count = threat_hash_store.get_prefix_count(tt_val)
        token = threat_hash_store.get_version_token(tt_val)
        next_diff = threat_hash_store.get_next_diff_time(tt_val)

        print(f"  {tt.name}:")
        print(f"    hash prefixes  : {count:,}")
        print(f"    version_token  : {token[:16].hex() + '...' if token else '(none)'}")
        print(f"    next diff time : {next_diff or '(not set)'}")
        print()

    cache_count = threat_hash_store.get_cache_count()
    print(f"  URL check cache  : {cache_count:,} entries")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Google Web Risk Update API Client",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # sync
    p_sync = sub.add_parser("sync", help="Sync threat lists")
    p_sync.add_argument(
        "-f", "--force", action="store_true", help="Force sync regardless of next diff time"
    )

    # check
    p_check = sub.add_parser("check", help="Check URL for threats")
    p_check.add_argument("url", help="URL to check")
    p_check.add_argument(
        "-v", "--verbose", action="store_true", help="Show step-by-step progress"
    )

    # status
    sub.add_parser("status", help="Show local DB status")

    # cache-clear
    sub.add_parser("cache-clear", help="Clear URL check cache")

    # submit
    p_submit = sub.add_parser("submit", help="Submit a suspicious URI to Google for review")
    p_submit.add_argument("url", help="Suspicious URL to submit")
    p_submit.add_argument(
        "--project", required=True,
        help="GCP project ID (e.g. my-project-123)",
    )
    p_submit.add_argument(
        "--type", default="SOCIAL_ENGINEERING",
        choices=list(ABUSE_TYPES.keys()),
        help="Threat type (default: SOCIAL_ENGINEERING)",
    )
    p_submit.add_argument(
        "--confidence", default="MEDIUM",
        choices=list(CONFIDENCE_LEVELS.keys()),
        help="Confidence level (default: MEDIUM)",
    )
    p_submit.add_argument(
        "--justification",
        help="Comma-separated justification labels: MANUAL_VERIFICATION,USER_REPORT,AUTOMATED_REPORT",
    )
    p_submit.add_argument(
        "--comment", help="Free-form comment explaining why the URI is a threat",
    )
    p_submit.add_argument(
        "--platform",
        choices=list(PLATFORMS.keys()),
        help="Platform where the threat was discovered",
    )
    p_submit.add_argument(
        "--region",
        help="Comma-separated ISO 3166-1 alpha-2 region codes (e.g. US,KR)",
    )
    p_submit.add_argument(
        "-v", "--verbose", action="store_true", help="Show step-by-step progress",
    )
    p_submit.add_argument(
        "--wait", action="store_true",
        help="Wait for Google to finish processing the submission",
    )
    p_submit.add_argument(
        "--timeout", type=int, default=600,
        help="Max seconds to wait when --wait is set (default: 600)",
    )
    p_submit.add_argument(
        "--interval", type=int, default=10,
        help="Poll interval in seconds when --wait is set (default: 10)",
    )

    args = parser.parse_args()

    commands = {
        "sync": cmd_sync,
        "check": cmd_check,
        "status": cmd_status,
        "cache-clear": cmd_cache_clear,
        "submit": cmd_submit,
    }
    commands[args.command](args)


if __name__ == "__main__":
    main()
