# CB App Control API Endpoints for Enforcement Readiness
# Based on: https://developer.carbonblack.com/reference/enterprise-protection/8.11.0/rest-api/

# Base API path
API_BASE_PATH = "/api/bit9platform/v1"

# Pre-aggregated endpoints (preferred over raw event data)
API_ENDPOINTS = {
    # File Catalog - Binary inventory with publisher info
    "fileCatalog": {
        "path": f"{API_BASE_PATH}/fileCatalog",
        "description": "File inventory with publisher, signer, and approval state",
        "key_fields": [
            "id",
            "md5",
            "sha256",
            "fileName",
            "filePath",
            "publisherName",
            "signer",
            "certificateId",
            "approvalState",
            "fileType",
            "createdAt",
            "lastObserved"
        ],
        "facets": ["publisherName", "signer", "approvalState", "fileType"],
        "filters": ["approvalState", "publisherName", "signer"]
    },
    
    # Certificate - Signer trust data
    "certificate": {
        "path": f"{API_BASE_PATH}/certificate",
        "description": "Signer certificate information and trust status",
        "key_fields": [
            "id",
            "subject",
            "issuer",
            "thumbprint",
            "hasValidSignature",
            "validStartDate",
            "validEndDate",
            "certificateUsageCount"
        ],
        "facets": ["issuer", "hasValidSignature"],
        "filters": ["hasValidSignature"]
    },
    
    # Certificate Binary - Link binaries to certificates
    "certificateBinary": {
        "path": f"{API_BASE_PATH}/certificateBinary",
        "description": "Mapping between binaries and their certificates",
        "key_fields": [
            "certificateId",
            "fileCatalogId",
            "signer"
        ]
    },
    
    # Company Name - Publisher information
    "companyName": {
        "path": f"{API_BASE_PATH}/companyName",
        "description": "Publisher/company trust information",
        "key_fields": [
            "id",
            "name",
            "reputation",
            "productCount",
            "lastObserved"
        ],
        "facets": ["reputation"],
        "filters": ["reputation"]
    },
    
    # File Instance - Prevalence across endpoints
    "fileInstance": {
        "path": f"{API_BASE_PATH}/fileInstance",
        "description": "File occurrences across computers",
        "key_fields": [
            "fileCatalogId",
            "computerId",
            "computerName",
            "firstSeen",
            "lastSeen",
            "filePath"
        ],
        "facets": ["computerId"],
        "filters": ["fileCatalogId"]
    },
    
    # Computer - Endpoint information
    "computer": {
        "path": f"{API_BASE_PATH}/computer",
        "description": "Computer/endpoint details and policy",
        "key_fields": [
            "id",
            "name",
            "policyId",
            "policyName",
            "status",
            "lastPoll",
            "osVersion"
        ],
        "facets": ["policyId", "status"],
        "filters": ["policyId", "status"]
    },
    
    # Approval Request - Approval history
    "approvalRequest": {
        "path": f"{API_BASE_PATH}/approvalRequest",
        "description": "File approval requests and status",
        "key_fields": [
            "id",
            "fileCatalogId",
            "fileName",
            "status",
            "requestedBy",
            "requestedAt",
            "approvedBy",
            "approvedAt"
        ],
        "facets": ["status"],
        "filters": ["status", "fileCatalogId"]
    },
    
    # Event - Raw events (use sparingly, prefer aggregations)
    "event": {
        "path": f"{API_BASE_PATH}/event",
        "description": "Raw event data (last resort for analysis)",
        "key_fields": [
            "id",
            "eventType",
            "fileCatalogId",
            "computerId",
            "createdAt",
            "action"
        ],
        "facets": ["eventType", "action"],
        "filters": ["eventType", "createdAt"]
    }
}

# Trust Signal Queries
# Pre-defined queries to extract trust signals from API
TRUST_SIGNAL_QUERIES = {
    # Unknown binaries (not approved)
    "unknown_binaries": {
        "endpoint": "fileCatalog",
        "params": {
            "facet": "publisherName",
            "filter": "approvalState:NOT_APPROVED",
            "rows": 1000
        }
    },
    
    # Trusted publishers
    "trusted_publishers": {
        "endpoint": "companyName",
        "params": {
            "facet": "reputation",
            "filter": "reputation:TRUSTED",
            "rows": 100
        }
    },
    
    # Signed binaries
    "signed_binaries": {
        "endpoint": "fileCatalog",
        "params": {
            "facet": "signer",
            "filter": "signer:*",
            "rows": 1000
        }
    },
    
    # File prevalence (cross-host analysis)
    "file_prevalence": {
        "endpoint": "fileInstance",
        "params": {
            "facet": "fileCatalogId",
            "rows": 1000
        }
    },
    
    # Certificates with valid signatures
    "valid_certificates": {
        "endpoint": "certificate",
        "params": {
            "facet": "issuer",
            "filter": "hasValidSignature:true",
            "rows": 100
        }
    }
}