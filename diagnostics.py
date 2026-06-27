#!/usr/bin/env python3
"""
Direct API diagnostics to identify data corruption issues.
Queries each endpoint and shows raw counts + field structure.
"""

import json
import logging
import argparse
from data_collection.api_client import CBApiClient

logging.basicConfig(
    level=logging.INFO,
    format='%(levelname)s: %(message)s'
)
logger = logging.getLogger(__name__)


def diagnose_file_catalog(client: CBApiClient) -> None:
    """Check if unknown and approved counts are actually different."""
    logger.info("\n" + "="*60)
    logger.info("FILE CATALOG DIAGNOSTICS")
    logger.info("="*60)
    
    # Get unknown binaries count
    logger.info("\nQuerying: /fileCatalog?rows=0&filter=approvalState:NOT_APPROVED")
    unknown_resp = client.get(
        "/api/bit9platform/v1/fileCatalog",
        params={"rows": 0, "filter": "approvalState:NOT_APPROVED"}
    )
    unknown_count = unknown_resp.get('total', unknown_resp.get('count', 0)) if isinstance(unknown_resp, dict) else len(unknown_resp)
    logger.info(f"  Response type: {type(unknown_resp).__name__}")
    logger.info(f"  Response keys: {list(unknown_resp.keys()) if isinstance(unknown_resp, dict) else 'N/A (list)'}")
    logger.info(f"  Unknown count: {unknown_count}")
    
    # Get approved binaries count
    logger.info("\nQuerying: /fileCatalog?rows=0&filter=approvalState:APPROVED")
    approved_resp = client.get(
        "/api/bit9platform/v1/fileCatalog",
        params={"rows": 0, "filter": "approvalState:APPROVED"}
    )
    approved_count = approved_resp.get('total', approved_resp.get('count', 0)) if isinstance(approved_resp, dict) else len(approved_resp)
    logger.info(f"  Response type: {type(approved_resp).__name__}")
    logger.info(f"  Response keys: {list(approved_resp.keys()) if isinstance(approved_resp, dict) else 'N/A (list)'}")
    logger.info(f"  Approved count: {approved_count}")
    
    # Diagnosis
    logger.info(f"\n{'FAIL' if unknown_count == approved_count else 'PASS'}: unknown ({unknown_count}) vs approved ({approved_count})")
    if unknown_count == approved_count:
        logger.error("  ⚠️  CORRUPTED: Both queries return identical counts")
        logger.error("  → Check if filter parameter is being ignored by API")
        logger.error("  → Or if /fileCatalog is returning wrong dataset")


def diagnose_publishers(client: CBApiClient) -> None:
    """Check if trusted and blocked publisher counts are actually different."""
    logger.info("\n" + "="*60)
    logger.info("PUBLISHER REPUTATION DIAGNOSTICS")
    logger.info("="*60)
    
    # Get trusted publishers
    logger.info("\nQuerying: /companyName?rows=0&filter=reputation:TRUSTED")
    trusted_resp = client.get(
        "/api/bit9platform/v1/companyName",
        params={"rows": 0, "filter": "reputation:TRUSTED"}
    )
    trusted_count = trusted_resp.get('total', trusted_resp.get('count', 0)) if isinstance(trusted_resp, dict) else len(trusted_resp)
    logger.info(f"  Response type: {type(trusted_resp).__name__}")
    logger.info(f"  Response keys: {list(trusted_resp.keys()) if isinstance(trusted_resp, dict) else 'N/A (list)'}")
    logger.info(f"  Trusted count: {trusted_count}")
    
    # Get blocked publishers
    logger.info("\nQuerying: /companyName?rows=0&filter=reputation:BLOCKED")
    blocked_resp = client.get(
        "/api/bit9platform/v1/companyName",
        params={"rows": 0, "filter": "reputation:BLOCKED"}
    )
    blocked_count = blocked_resp.get('total', blocked_resp.get('count', 0)) if isinstance(blocked_resp, dict) else len(blocked_resp)
    logger.info(f"  Response type: {type(blocked_resp).__name__}")
    logger.info(f"  Response keys: {list(blocked_resp.keys()) if isinstance(blocked_resp, dict) else 'N/A (list)'}")
    logger.info(f"  Blocked count: {blocked_count}")
    
    # Diagnosis
    logger.info(f"\n{'FAIL' if trusted_count == blocked_count else 'PASS'}: trusted ({trusted_count}) vs blocked ({blocked_count})")
    if trusted_count == blocked_count:
        logger.error("  ⚠️  CORRUPTED: Both queries return identical counts")
        logger.error("  → Possible causes:")
        logger.error("    - reputation field uses different values (1/2/3 instead of TRUSTED/BLOCKED)")
        logger.error("    - API filter parser is case-sensitive or has syntax issue")
        logger.error("    - Both endpoints returning all publishers regardless of filter")


def diagnose_blocked_parsing(client: CBApiClient) -> None:
    """Get actual blocked data and check reputation field values."""
    logger.info("\n" + "="*60)
    logger.info("BLOCKED PUBLISHER DATA STRUCTURE")
    logger.info("="*60)
    
    logger.info("\nQuerying: /companyName?rows=10&filter=reputation:BLOCKED (first 10 records)")
    blocked_resp = client.get(
        "/api/bit9platform/v1/companyName",
        params={"rows": 10, "filter": "reputation:BLOCKED"}
    )
    
    if isinstance(blocked_resp, dict):
        records = blocked_resp.get('results', [])
    else:
        records = blocked_resp if isinstance(blocked_resp, list) else []
    
    logger.info(f"  Got {len(records)} records")
    
    if records:
        # Show first record structure
        first = records[0]
        logger.info(f"\n  First record keys: {list(first.keys())}")
        logger.info(f"  First record reputation value: {first.get('reputation', 'N/A')}")
        logger.info(f"  First record companyName: {first.get('companyName', 'N/A')}")
        
        # Check reputation field values across all results
        reputations = set()
        for r in records:
            rep = r.get('reputation', r.get('reputationId', 'UNKNOWN'))
            reputations.add(rep)
        logger.info(f"\n  Unique reputation values found: {reputations}")
    else:
        logger.error("  ⚠️  No records returned. Check if BLOCKED filter syntax is correct")


def diagnose_trusted_parsing(client: CBApiClient) -> None:
    """Get actual trusted data and check reputation field values."""
    logger.info("\n" + "="*60)
    logger.info("TRUSTED PUBLISHER DATA STRUCTURE")
    logger.info("="*60)
    
    logger.info("\nQuerying: /companyName?rows=10&filter=reputation:TRUSTED (first 10 records)")
    trusted_resp = client.get(
        "/api/bit9platform/v1/companyName",
        params={"rows": 10, "filter": "reputation:TRUSTED"}
    )
    
    if isinstance(trusted_resp, dict):
        records = trusted_resp.get('results', [])
    else:
        records = trusted_resp if isinstance(trusted_resp, list) else []
    
    logger.info(f"  Got {len(records)} records")
    
    if records:
        # Show first record structure
        first = records[0]
        logger.info(f"\n  First record keys: {list(first.keys())}")
        logger.info(f"  First record reputation value: {first.get('reputation', 'N/A')}")
        logger.info(f"  First record companyName: {first.get('companyName', 'N/A')}")
        
        # Check reputation field values across all results
        reputations = set()
        for r in records:
            rep = r.get('reputation', r.get('reputationId', 'UNKNOWN'))
            reputations.add(rep)
        logger.info(f"\n  Unique reputation values found: {reputations}")
    else:
        logger.error("  ⚠️  No records returned. Check if TRUSTED filter syntax is correct")


def main():
    parser = argparse.ArgumentParser(description="Diagnose API data corruption issues")
    parser.add_argument("--server", required=True, help="CB App Control server URL")
    parser.add_argument("--token", required=True, help="API token")
    args = parser.parse_args()
    
    logger.info(f"Connecting to {args.server}")
    client = CBApiClient(server_url=args.server, api_token=args.token, verify_ssl=False)
    
    try:
        # Test connection
        test_resp = client.get("/api/bit9platform/v1/fileCatalog", params={"rows": 1})
        logger.info("✓ Connected successfully\n")
        
        # Run diagnostics
        diagnose_file_catalog(client)
        diagnose_publishers(client)
        diagnose_blocked_parsing(client)
        diagnose_trusted_parsing(client)
        
        # Summary
        logger.info("\n" + "="*60)
        logger.info("SUMMARY")
        logger.info("="*60)
        logger.info("Check the FAIL/PASS markers above:")
        logger.info("  • If FILE_CATALOG fails: filter syntax or API endpoint issue")
        logger.info("  • If PUBLISHERS fails: reputation field values or filter syntax")
        logger.info("  • Check Data Structure sections for actual field names/values")
        
    except Exception as e:
        logger.error(f"Error: {e}")
        raise


if __name__ == "__main__":
    main()
