# Carbon Black App Control API Client
import requests
import json
import logging
import urllib3
from typing import Dict, List, Any, Optional
from urllib.parse import urlencode
from urllib3.exceptions import InsecureRequestWarning

logger = logging.getLogger(__name__)


class CBApiClient:
    """Client for interacting with Carbon Black App Control REST API"""
    
    def __init__(self, server_url: str, api_token: str, verify_ssl: bool = True):
        """
        Initialize the API client.
        
        Args:
            server_url: CB App Control server URL (e.g., https://server.example.com)
            api_token: API token for authentication
            verify_ssl: Whether to verify SSL certificates
        """
        self.server_url = server_url.rstrip('/')
        self.api_token = api_token
        self.verify_ssl = verify_ssl
        
        # Suppress urllib3 InsecureRequestWarning if SSL verification is disabled
        if not verify_ssl:
            urllib3.disable_warnings(InsecureRequestWarning)
        
        self.session = requests.Session()
        
        # CB App Control uses X-Auth-Token header for authentication
        self.session.headers.update({
            'X-Auth-Token': api_token,
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })
    
    def _build_url(self, endpoint: str, params: Optional[Dict] = None) -> str:
        """Build the full URL with query parameters."""
        url = f"{self.server_url}{endpoint}"
        if params:
            # Filter out None values
            filtered_params = {k: v for k, v in params.items() if v is not None}
            if filtered_params:
                url += f"?{urlencode(filtered_params)}"
        return url
    
    def get(self, endpoint: str, params: Optional[Dict] = None, 
            rows: Optional[int] = None, start: int = 0) -> Dict:
        """
        Make a GET request to the API.
        
        Args:
            endpoint: API endpoint path
            params: Query parameters
            rows: Number of rows to return (pagination)
            start: Starting row for pagination
            
        Returns:
            JSON response as dictionary
        """
        # Add pagination parameters
        query_params = params.copy() if params else {}
        if rows is not None:
            query_params['rows'] = rows
        if start > 0:
            query_params['start'] = start
        
        url = self._build_url(endpoint, query_params)
        
        try:
            logger.info(f"GET {url}")
            response = self.session.get(url, verify=self.verify_ssl)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"API request failed: {e}")
            raise
    
    def query(self, endpoint: str, filters: Optional[List[str]] = None,
             facets: Optional[List[str]] = None, rows: int = 1000,
             start: int = 0) -> Dict:
        """
        Make a query request with filters and facets.
        
        Args:
            endpoint: API endpoint
            filters: List of filter strings (e.g., ['approvalState:NOT_APPROVED'])
            facets: List of fields to facet on
            rows: Number of rows
            start: Starting row
            
        Returns:
            Query results
        """
        params = {
            'rows': rows,
            'start': start
        }
        
        # Add filters
        if filters:
            params['filter'] = ';'.join(filters)
        
        # Add facets
        if facets:
            params['facet'] = ','.join(facets)
        
        return self.get(endpoint, params)
    
    def facet_query(self, endpoint: str, facet_field: str,
                   filters: Optional[List[str]] = None, 
                   rows: int = 100) -> Dict:
        """
        Perform a facet query to get aggregated data.
        
        Args:
            endpoint: API endpoint
            facet_field: Field to facet on
            filters: Optional filters
            rows: Number of facet values to return
            
        Returns:
            Facet results
        """
        return self.query(endpoint, filters=filters, facets=[facet_field], rows=rows)
    
    def test_connection(self) -> bool:
        """
        Test the API connection.
        
        Returns:
            True if connection is successful
        """
        # Use the correct API path: /api/bit9platform/v1/
        test_path = '/api/bit9platform/v1/fileCatalog'
        
        try:
            response = self.get(test_path, rows=1)
            # Handle both dict and list responses
            if isinstance(response, list):
                logger.info(f"Connected to CB App Control server: {test_path}")
                logger.info(f"Response: {len(response)} records")
            else:
                logger.info(f"Connected to CB App Control server: {test_path}")
                logger.info(f"Response: {response.get('total', len(response))} records")
            return True
        except Exception as e:
            status_code = None
            resp = getattr(e, 'response', None)
            if resp is not None:
                status_code = getattr(resp, 'status_code', None)

            if status_code == 401:
                logger.error(
                    "Connection test failed: API token is unauthorized (401). "
                    "Verify the exact token value, ensure token generation was saved, "
                    "and confirm the token belongs to an enabled account with API access."
                )
            else:
                logger.error(f"Connection test failed: {e}")
            return False


class CBApiError(Exception):
    """Custom exception for CB API errors"""
    pass