#!/usr/bin/env python3
"""
Deep API inspection - dump actual response structure to find correct fields.
"""

import json
import logging
from data_collection.api_client import CBApiClient

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)


def inspect_endpoint(client: CBApiClient, endpoint: str, params: dict, label: str) -> None:
    """Fetch and dump full response structure."""
    logger.info(f"\n{'='*70}")
    logger.info(f"{label}")
    logger.info(f"{'='*70}")
    logger.info(f"Endpoint: {endpoint}")
    logger.info(f"Params: {params}\n")
    
    resp = client.get(endpoint, params=params)
    
    logger.info(f"Response type: {type(resp).__name__}")
    if isinstance(resp, dict):
        logger.info(f"Top-level keys: {list(resp.keys())}")
        logger.info(f"Full response:\n{json.dumps(resp, indent=2)}\n")
    elif isinstance(resp, list):
        logger.info(f"List with {len(resp)} items")
        if resp:
            logger.info(f"First item keys: {list(resp[0].keys())}")
            logger.info(f"First 3 items:\n{json.dumps(resp[:3], indent=2)}\n")


def main():
    client = CBApiClient(
        server_url="https://192.168.1.201:4434/",
        api_token="9960C6B4-C174-446F-B81A-F36892BC824D",
        verify_ssl=False
    )
    
    # Test connection
    test_resp = client.get("/api/bit9platform/v1/fileCatalog", params={"rows": 1})
    logger.info("✓ Connected\n")
    
    # Inspect file catalog - try different filter syntaxes
    inspect_endpoint(
        client,
        "/api/bit9platform/v1/fileCatalog",
        {"rows": 3},
        "FILE CATALOG - No Filter (all files)"
    )
    
    inspect_endpoint(
        client,
        "/api/bit9platform/v1/fileCatalog",
        {"rows": 3, "filter": "approvalState:NOT_APPROVED"},
        "FILE CATALOG - Filter: approvalState:NOT_APPROVED"
    )
    
    inspect_endpoint(
        client,
        "/api/bit9platform/v1/fileCatalog",
        {"rows": 3, "filter": "approvalState%3ANOT_APPROVED"},
        "FILE CATALOG - Filter: approvalState%3ANOT_APPROVED (URL encoded)"
    )
    
    # Inspect company name - try different filter syntaxes
    inspect_endpoint(
        client,
        "/api/bit9platform/v1/companyName",
        {"rows": 3},
        "COMPANY NAME - No Filter (all publishers)"
    )
    
    inspect_endpoint(
        client,
        "/api/bit9platform/v1/companyName",
        {"rows": 3, "filter": "reputation:TRUSTED"},
        "COMPANY NAME - Filter: reputation:TRUSTED"
    )
    
    inspect_endpoint(
        client,
        "/api/bit9platform/v1/companyName",
        {"rows": 3, "filter": "reputation=TRUSTED"},
        "COMPANY NAME - Filter: reputation=TRUSTED (equals syntax)"
    )
    
    inspect_endpoint(
        client,
        "/api/bit9platform/v1/companyName",
        {"rows": 3, "filter": "reputationId:TRUSTED"},
        "COMPANY NAME - Filter: reputationId:TRUSTED"
    )
    
    # Try facet to see all reputation values
    inspect_endpoint(
        client,
        "/api/bit9platform/v1/companyName",
        {"rows": 0, "facet": "reputation"},
        "COMPANY NAME - Facet: reputation (to see all values)"
    )


if __name__ == "__main__":
    main()
