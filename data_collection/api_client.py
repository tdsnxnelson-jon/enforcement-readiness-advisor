# Carbon Black App Control API Client
import requests
import json
import logging
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Any, Optional
from urllib.parse import urlencode
from urllib3.exceptions import InsecureRequestWarning

logger = logging.getLogger(__name__)


class CBApiClient:
    """Client for interacting with Carbon Black App Control REST API"""
    
    def __init__(self, server_url: str, api_token: str, verify_ssl: bool = True, max_workers: int = 4):
        """
        Initialize the API client.
        
        Args:
            server_url: CB App Control server URL (e.g., https://server.example.com)
            api_token: API token for authentication
            verify_ssl: Whether to verify SSL certificates
            max_workers: Max concurrent requests used when paginating large endpoints
        """
        self.server_url = server_url.rstrip('/')
        self.api_token = api_token
        self.verify_ssl = verify_ssl
        self.max_workers = max(1, max_workers)
        
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
        # Add pagination parameters.
        # NOTE: The App Control REST API uses 'limit'/'offset', NOT 'rows'/'start'.
        # Sending 'rows'/'start' is silently ignored by the server, which then
        # always falls back to its default of the first 1000 results - causing
        # large catalogs (fileCatalog/certificate/publisher) to be truncated and
        # any records outside that first page (e.g. some Mac binaries and their
        # publisher/certificate joins) to appear to be missing data.
        query_params = params.copy() if params else {}
        if rows is not None:
            query_params['limit'] = rows
        if start:
            query_params['offset'] = start
        
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
             start: int = 0, sort: Optional[str] = None) -> Dict:
        """
        Make a query request with filters and facets.
        
        Args:
            endpoint: API endpoint
            filters: List of filter strings (e.g., ['approvalState:NOT_APPROVED'])
            facets: List of fields to facet on
            rows: Number of rows
            start: Starting row
            sort: Sort clause (e.g. 'id ASC') - required for stable pagination
                on endpoints that can mutate while being paged through
            
        Returns:
            Query results
        """
        params = {
            'limit': rows,
            'offset': start
        }
        if sort:
            params['sort'] = sort
        
        # Add filters
        if filters:
            params['filter'] = ';'.join(filters)
        
        # Add facets
        if facets:
            params['facet'] = ','.join(facets)
        
        return self.get(endpoint, params)
    
    def query_all(self, endpoint: str, filters: Optional[List[str]] = None,
                  facets: Optional[List[str]] = None, max_rows: Optional[int] = None,
                  page_size: int = 1000, sort: str = 'id ASC',
                  max_workers: Optional[int] = None) -> List[Dict]:
        """
        Fetch all rows from an endpoint, paginating with limit/offset.

        A single request is capped by the server at ~1000 rows if no explicit
        limit is given, so any endpoint that can contain more rows than that
        (e.g. fileCatalog, certificate, publisher) must be paginated to avoid
        silently dropping records - including specific files whose fileCatalog
        row simply falls outside whatever single page was requested.

        Pages are fetched concurrently (bounded by max_workers) once the total
        row count is known, since sequential single-page-at-a-time fetching
        against a catalog with 10,000s-100,000s of rows is impractically slow.

        `sort` pins pagination to a stable, monotonic field. Without it, offset
        pagination against a live/mutating dataset can skip or duplicate rows
        as records are added/changed mid-fetch - a real risk on larger, busier
        servers where a full fetch can take a while.

        Args:
            endpoint: API endpoint
            filters: List of filter strings (best-effort; not all endpoints honor this)
            facets: List of fields to facet on
            max_rows: Overall cap across all pages. None or <= 0 fetches everything
                (some callers pass rows=0 intending "give me the full/true set",
                matching the App Control convention that limit=0 means "all rows")
            page_size: Rows requested per page
            sort: Stable sort clause used to keep pagination windows consistent
            max_workers: Concurrent page-fetch workers (defaults to client setting)

        Returns:
            Combined list of rows across all pages
        """
        unlimited = max_rows is None or max_rows <= 0
        workers = max(1, max_workers if max_workers is not None else self.max_workers)

        total = self._count(endpoint, filters=filters)
        if total is None:
            # Server didn't answer the count probe as expected; fall back to
            # sequential pagination rather than guessing how many pages exist.
            return self._query_all_sequential(endpoint, filters, facets, max_rows, page_size, sort)

        rows_to_fetch = total if unlimited else min(total, max_rows)
        if rows_to_fetch <= 0:
            return []

        page_starts = list(range(0, rows_to_fetch, page_size))
        if len(page_starts) <= 1 or workers <= 1:
            return self._query_all_sequential(endpoint, filters, facets, rows_to_fetch, page_size, sort)

        collected_by_offset: Dict[int, List[Dict]] = {}
        with ThreadPoolExecutor(max_workers=workers) as pool:
            future_to_offset = {
                pool.submit(
                    self.query, endpoint, filters, facets,
                    min(page_size, rows_to_fetch - offset), offset, sort
                ): offset
                for offset in page_starts
            }
            for future in as_completed(future_to_offset):
                offset = future_to_offset[future]
                try:
                    page = future.result()
                except Exception as exc:
                    logger.warning(f"Page fetch failed for {endpoint} offset={offset}: {exc}")
                    collected_by_offset[offset] = []
                    continue
                page_rows = page if isinstance(page, list) else page.get('results', page.get('rows', []))
                collected_by_offset[offset] = page_rows if isinstance(page_rows, list) else []

        collected: List[Dict] = []
        for offset in page_starts:
            collected.extend(collected_by_offset.get(offset, []))
        return collected

    def _count(self, endpoint: str, filters: Optional[List[str]] = None) -> Optional[int]:
        """Get an exact row count via limit=-1, without fetching any rows."""
        try:
            response = self.query(endpoint, filters=filters, rows=-1)
        except Exception as exc:
            logger.debug(f"Count probe failed for {endpoint}: {exc}")
            return None
        if isinstance(response, dict) and 'count' in response:
            return response['count']
        return None

    def _query_all_sequential(self, endpoint: str, filters: Optional[List[str]],
                               facets: Optional[List[str]], max_rows: Optional[int],
                               page_size: int, sort: str) -> List[Dict]:
        """Fallback pagination path for endpoints that don't support the limit=-1 count probe."""
        collected: List[Dict] = []
        offset = 0
        unlimited = max_rows is None or max_rows <= 0
        while True:
            remaining = None if unlimited else max_rows - len(collected)
            if remaining is not None and remaining <= 0:
                break
            limit = page_size if remaining is None else min(page_size, remaining)
            page = self.query(endpoint, filters=filters, facets=facets, rows=limit, start=offset, sort=sort)
            page_rows = page if isinstance(page, list) else page.get('results', page.get('rows', []))
            if not isinstance(page_rows, list) or not page_rows:
                break
            collected.extend(page_rows)
            if len(page_rows) < limit:
                break
            offset += len(page_rows)
        return collected
    
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