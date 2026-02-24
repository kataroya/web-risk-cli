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
    print(f"Checking: {url}\n")
    result = check_url(url, client)

    if result["safe"]:
        print("  Safe - no threats detected.")
    else:
        print("  Threat detected!")
        for t in result["threats"]:
            print(f"    - {t['threat_type']} (expires: {t['expire_time'] or 'N/A'})")


def cmd_status(args: argparse.Namespace) -> None:
    """Display local DB status."""
    threat_hash_store.init_db()

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

    # status
    sub.add_parser("status", help="Show local DB status")

    args = parser.parse_args()

    commands = {
        "sync": cmd_sync,
        "check": cmd_check,
        "status": cmd_status,
    }
    commands[args.command](args)


if __name__ == "__main__":
    main()
