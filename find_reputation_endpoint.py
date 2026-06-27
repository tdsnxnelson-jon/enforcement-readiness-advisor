#!/usr/bin/env python3
"""
Search for endpoints that return publisher reputation data.
"""

import json
import logging
from data_collection.api_client import CBApiClient

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

# Common CB App Control API endpoints
ENDPOINTS_TO_TRY = [
    "/api/bit9platform/v1/publisher",
    "/api/bit9platform/v1/publishers",
    "/api/bit9platform/v1/companyName",
    "/api/bit9platform/v1/company",
    "/api/bit9platform/v1/reputationOverride",
    "/api/bit9platform/v1/reputation",
    "/api/bit9platform/v1/fileInstance",
    "/api/bit9platform/v1/fileCatalog",
]

def test_endpoint(client: CBApiClient, endpoint: str) -> None:
    """Try endpoint and show what fields come back."""
    try:
        logger.info(f"\nTesting: {endpoint}")
        resp = client.get(endpoint, params={"rows": 1})
        
        if isinstance(resp, list):
            if resp:
                fields = list(resp[0].keys())
                logger.info(f"  ✓ Got {len(resp)} items")
                logger.info(f"  Fields: {fields}")
                
                # Check for reputation-like fields
                rep_fields = [f for f in fields if 'reputation' in f.lower() or 'trust' in f.lower() or 'state' in f.lower() or 'status' in f.lower()]
                if rep_fields:
                    logger.info(f"  ⭐ RELEVANT: {rep_fields}")
                    logger.info(f"  Sample: {json.dumps(resp[0], indent=2)[:500]}")
            else:
                logger.info(f"  Empty list")
        elif isinstance(resp, dict):
            logger.info(f"  ✓ Dict response")
            logger.info(f"  Keys: {list(resp.keys())}")
            logger.info(f"  Sample: {json.dumps(resp, indent=2)[:500]}")
    except Exception as e:
        logger.info(f"  ✗ Error: {str(e)[:100]}")


def main():
    client = CBApiClient(
        server_url="https://192.168.1.201:4434/",
        api_token="9960C6B4-C174-446F-B81A-F36892BC824D",
        verify_ssl=False
    )
    
    # Test connection
    test_resp = client.get("/api/bit9platform/v1/fileCatalog", params={"rows": 1})
    logger.info("✓ Connected\n")
    
    for endpoint in ENDPOINTS_TO_TRY:
        test_endpoint(client, endpoint)


if __name__ == "__main__":
    main()
