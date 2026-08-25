# Data Collectors for CB App Control API
# Each collector focuses on a specific data type for enforcement readiness

from datetime import datetime, timedelta, timezone
from typing import Dict, List, Any, Optional, Tuple
import logging
from .api_client import CBApiClient

logger = logging.getLogger(__name__)


class BaseCollector:
    """Base class for all data collectors."""
    
    def __init__(self, api_client: CBApiClient, endpoint: str):
        self.api_client = api_client
        # Use the correct API path: /api/bit9platform/v1/
        self.endpoint = f"/api/bit9platform/v1/{endpoint}"
    
    def collect(self, filters: Optional[List[str]] = None, 
                facets: Optional[List[str]] = None,
                rows: int = 1000) -> List[Dict]:
        """Collect data from the endpoint, paginating so results aren't truncated
        to a single page when the endpoint has more rows than fit in one request."""
        return self.api_client.query_all(self.endpoint, filters, facets, max_rows=rows)
    
    def collect_facet(self, facet_field: str, 
                     filters: Optional[List[str]] = None,
                     rows: int = 100) -> Dict:
        """Collect facet data from the endpoint."""
        return self.api_client.facet_query(self.endpoint, facet_field, filters, rows)


class FileCatalogCollector(BaseCollector):
    """Collects file catalog data for binary analysis."""
    
    def __init__(self, api_client: CBApiClient):
        super().__init__(api_client, 'fileCatalog')
        self._cache: Dict[int, list] = {}

    def _get_all(self, rows: int) -> list:
        """Fetch the full file catalog once per row cap and reuse it across
        get_all/get_unknown_binaries/get_approved_binaries instead of re-fetching."""
        if rows not in self._cache:
            all_files = self.collect(rows=rows)
            self._cache[rows] = all_files if isinstance(all_files, list) else []
        return self._cache[rows]

    def get_all(self, rows: int = 1000) -> list:
        """Get the full, unfiltered file catalog."""
        return self._get_all(rows)

    def get_unknown_binaries(self, rows: int = 1000) -> list:
        """Get all unapproved binaries (effectiveState == 'Unapproved').
        Note: the API ignores 'filter' query params, so state is filtered locally."""
        return [f for f in self._get_all(rows) if f.get('effectiveState') == 'Unapproved']
    
    def get_approved_binaries(self, rows: int = 1000) -> list:
        """Get all approved binaries (effectiveState == 'Approved').
        Note: the API ignores 'filter' query params, so state is filtered locally."""
        return [f for f in self._get_all(rows) if f.get('effectiveState') == 'Approved']
    
    def get_by_publisher(self, publisher: str, rows: int = 1000) -> Dict:
        """Get binaries by publisher."""
        return self.collect(
            filters=[f'publisherName:{publisher}'],
            facets=['approvalState', 'signer'],
            rows=rows
        )
    
    def get_by_signer(self, signer: str, rows: int = 1000) -> Dict:
        """Get binaries by signer."""
        return self.collect(
            filters=[f'signer:{signer}'],
            facets=['approvalState', 'publisherName'],
            rows=rows
        )


class CertificateCollector(BaseCollector):
    """Collects certificate data for signer trust analysis."""
    
    def __init__(self, api_client: CBApiClient):
        super().__init__(api_client, 'certificate')
        self._cache: Dict[int, list] = {}

    def _get_all(self, rows: int) -> list:
        """Fetch the full certificate list once per row cap and reuse it across
        the get_* variants below instead of re-fetching for each one."""
        if rows not in self._cache:
            all_certs = self.collect(rows=rows)
            self._cache[rows] = all_certs if isinstance(all_certs, list) else []
        return self._cache[rows]

    def get_valid_certificates(self, rows: int = 100) -> list:
        """Get certificates with valid signatures.
        Note: the API ignores 'filter' query params, so validity is filtered locally."""
        return [c for c in self._get_all(rows) if c.get('valid')]

    def get_invalid_certificates(self, rows: int = 100) -> list:
        """Get certificates with invalid signatures.
        Note: the API ignores 'filter' query params, so validity is filtered locally."""
        return [c for c in self._get_all(rows) if not c.get('valid')]

    def get_all_certificates(self, rows: int = 2000) -> list:
        """Get all certificates for full certificate-chain resolution."""
        return self._get_all(rows)
    
    def get_by_issuer(self, issuer: str, rows: int = 100) -> Dict:
        """Get certificates by issuer."""
        return self.collect(
            filters=[f'issuer:{issuer}'],
            rows=rows
        )


class PublisherCollector(BaseCollector):
    """Collects publisher trust data from /publisher endpoint with actual reputation values."""
    
    def __init__(self, api_client: CBApiClient):
        super().__init__(api_client, 'publisher')
        self._cache: Dict[int, list] = {}

    def _get_all(self, rows: int) -> list:
        """Fetch the full publisher list once per row cap and reuse it across
        the get_* variants below instead of re-fetching for each one."""
        if rows not in self._cache:
            all_pubs = self.collect(rows=rows)
            self._cache[rows] = all_pubs if isinstance(all_pubs, list) else []
        return self._cache[rows]

    def get_trusted_publishers(self, rows: int = 100) -> list:
        """Get trusted publishers (publisherReputation numeric value 3)."""
        return [p for p in self._get_all(rows) if p.get('publisherReputation') == 3]
    
    def get_blocked_publishers(self, rows: int = 100) -> list:
        """Get blocked publishers (publisherReputation numeric value 2)."""
        return [p for p in self._get_all(rows) if p.get('publisherReputation') == 2]
    
    def get_all_by_reputation(self, rows: int = 100) -> dict:
        """Get all publishers with reputation breakdown."""
        all_pubs = self._get_all(rows)
        return {
            'TRUSTED': [p for p in all_pubs if p.get('publisherReputation') == 3],
            'BLOCKED': [p for p in all_pubs if p.get('publisherReputation') == 2],
            'UNKNOWN': [p for p in all_pubs if p.get('publisherReputation') == 0],
        }


class CompanyNameCollector(BaseCollector):
    """Collects publisher/company trust data."""
    
    def __init__(self, api_client: CBApiClient):
        super().__init__(api_client, 'companyName')
    
    def get_trusted_publishers(self, rows: int = 100) -> Dict:
        """Get trusted publishers."""
        return self.collect(
            filters=['reputation:TRUSTED'],
            rows=rows
        )
    
    def get_blocked_publishers(self, rows: int = 100) -> Dict:
        """Get blocked publishers."""
        return self.collect(
            filters=['reputation:BLOCKED'],
            rows=rows
        )
    
    def get_all_by_reputation(self, rows: int = 100) -> Dict:
        """Get all publishers grouped by reputation."""
        return self.collect(
            facets=['reputation'],
            rows=rows
        )


class FileInstanceCollector(BaseCollector):
    """Collects file instance data for prevalence analysis."""
    
    def __init__(self, api_client: CBApiClient):
        super().__init__(api_client, 'fileInstance')
    
    def get_file_prevalence(self, rows: int = 1000) -> Dict:
        """Get file prevalence across computers."""
        return self.collect(
            facets=['fileCatalogId', 'computerId'],
            rows=rows
        )
    
    def get_computer_files(self, computer_id: str, rows: int = 1000) -> Dict:
        """Get all files on a specific computer."""
        return self.collect(
            filters=[f'computerId:{computer_id}'],
            rows=rows
        )


class ComputerCollector(BaseCollector):
    """Collects computer/endpoint data."""
    
    def __init__(self, api_client: CBApiClient):
        super().__init__(api_client, 'computer')
    
    def get_by_policy(self, policy_id: str, rows: int = 1000) -> Dict:
        """Get computers by policy."""
        return self.collect(
            filters=[f'policyId:{policy_id}'],
            rows=rows
        )
    
    def get_active_computers(self, rows: int = 1000) -> Dict:
        """Get active computers."""
        return self.collect(
            filters=['status:Active'],
            rows=rows
        )


class ApprovalRequestCollector(BaseCollector):
    """Collects approval request data."""
    
    def __init__(self, api_client: CBApiClient):
        super().__init__(api_client, 'approvalRequest')
    
    def get_pending_requests(self, rows: int = 100) -> Dict:
        """Get pending approval requests."""
        return self.collect(
            filters=['status:PENDING'],
            rows=rows
        )
    
    def get_approved_requests(self, rows: int = 100) -> Dict:
        """Get approved requests."""
        return self.collect(
            filters=['status:APPROVED'],
            rows=rows
        )
    
    def get_denied_requests(self, rows: int = 100) -> Dict:
        """Get denied requests."""
        return self.collect(
            filters=['status:DENIED'],
            rows=rows
        )


class EventCollector(BaseCollector):
    """Collects event data for approval workflow analysis."""

    def __init__(self, api_client: CBApiClient):
        super().__init__(api_client, 'event')

    def _get_event_history(self, candidate_filters: List[List[str]], rows: int, lookback_days: int) -> Dict:
        """Fetch a bounded event history, preserving only the requested event scope."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=max(1, lookback_days))
        for filters in candidate_filters:
            try:
                # query_all already paginates concurrently with stable sort=id ASC.
                all_rows = self.api_client.query_all(self.endpoint, filters=filters or None, max_rows=rows)
            except Exception as exc:
                logger.debug(f"Event filter failed {filters}: {exc}")
                continue
            collected = []
            for event in all_rows:
                timestamp = event.get('eventTime') or event.get('timestamp') or event.get('date') or event.get('createdTime')
                try:
                    parsed = datetime.fromisoformat(str(timestamp).replace('Z', '+00:00'))
                except (TypeError, ValueError):
                    parsed = None
                if parsed is None or parsed >= cutoff:
                    collected.append(event)
            return {'results': collected, 'lookback_days': lookback_days, 'query_succeeded': True}
        return {'results': [], 'lookback_days': lookback_days, 'query_succeeded': False}

    def get_event_history(self, rows: int = 5000, lookback_days: int = 60) -> Dict:
        """Fetch the complete event history for the configured analysis window."""
        return self._get_event_history([[]], rows, lookback_days)

    def get_new_unapproved_file_events(self, rows: int = 5000, lookback_days: int = 60, computer_ids: Optional[List[str]] = None, event_history: Optional[Dict] = None) -> Dict:
        """Get all new unapproved-file-on-computer events in the analysis window."""
        history = event_history or self.get_event_history(rows, lookback_days)
        return self._filter_unapproved_events(history, lookback_days, computer_ids)

    def _filter_unapproved_events(self, history: Dict, lookback_days: int, computer_ids: Optional[List[str]]) -> Dict:
        """Filter a shared event history to new unapproved files on computers."""
        events = []
        allowed_ids = {str(computer_id) for computer_id in computer_ids or []}
        for event in history.get('results', []):
            subtype_name = str(event.get('subtypeName', '')).lower()
            description = str(event.get('description', '')).lower()
            if 'new file on network' in subtype_name:
                continue
            is_unapproved_computer_file = (
                'new unapproved file' in subtype_name and 'computer' in subtype_name
            ) or (
                'new unapproved file' in description and 'computer' in description
            )
            if is_unapproved_computer_file and (not allowed_ids or str(event.get('computerId')) in allowed_ids):
                events.append(event)
        return {
            'results': events,
            'lookback_days': lookback_days,
            'collection_mode': 'shared-history-local-filter',
        }

    def get_block_events(self, rows: int = 5000, lookback_days: int = 60, computer_ids: Optional[List[str]] = None, event_history: Optional[Dict] = None) -> Dict:
        """Get block events from the complete history without including network-file events."""
        history = event_history or self.get_event_history(rows, lookback_days)
        return self._filter_block_events(history, lookback_days, computer_ids)

    def _filter_block_events(self, history: Dict, lookback_days: int, computer_ids: Optional[List[str]]) -> Dict:
        """Filter a shared event history to block events."""
        block_events = []
        allowed_ids = {str(computer_id) for computer_id in computer_ids or []}
        for event in history.get('results', []):
            if (
                'new file on network' not in str(event.get('subtypeName', '')).lower()
                and ('block' in str(event.get('subtypeName', '')).lower() or 'blocked' in str(event.get('description', '')).lower())
                and (not allowed_ids or str(event.get('computerId')) in allowed_ids)
            ):
                block_events.append(event)
        return {
            'results': block_events,
            'lookback_days': lookback_days,
            'collection_mode': 'shared-history-local-filter',
        }


class SoftwareRuleCollector(BaseCollector):
    """Collects software rule metadata for existing-rule checks."""

    def __init__(self, api_client: CBApiClient):
        # Keep BaseCollector initialized for compatibility; discovery is endpoint-driven.
        super().__init__(api_client, 'softwareRule')
        self.candidate_endpoints = [
            '/api/bit9platform/v1/executionControlRule',
            '/api/bit9platform/v1/fileCreationControlRule',
            '/api/bit9platform/v1/trustedPathRule',
            '/api/bit9platform/v1/advancedRule',
            '/api/bit9platform/v1/expertRule',
            '/api/bit9platform/v1/trustedDirectory',
            '/api/bit9platform/v1/trustedUser',
            '/api/bit9platform/v1/rapidConfig',
            '/api/bit9platform/v1/updater',
            '/api/bit9platform/v1/scriptRule',
        ]

    def get_all_rules(self, rows: int = 2000) -> Dict:
        """Get rule-like objects from API endpoints available in this server build."""
        collected_rows: List[Dict[str, Any]] = []
        accessible_endpoints: List[str] = []
        forbidden_endpoints: List[str] = []
        missing_endpoints: List[str] = []
        other_errors: List[str] = []

        for endpoint in self.candidate_endpoints:
            # Cheap single-row probe first: distinguishes "not permitted"/"not on
            # this server build" from a real fetch failure, without retrying
            # against endpoints that are expected to 403/404 on some servers.
            status_code, _, error_text = self._query_endpoint_soft(endpoint, rows=1)

            if status_code == 200:
                rows_payload = self.api_client.query_all(endpoint, max_rows=rows, sort='id ASC')
                for row in rows_payload:
                    if isinstance(row, dict):
                        row['_ruleSourceEndpoint'] = endpoint
                collected_rows.extend(rows_payload)
                accessible_endpoints.append(endpoint)
                continue

            if status_code == 403:
                logger.info(f"Rule endpoint denied (403): {endpoint}")
                forbidden_endpoints.append(endpoint)
                continue

            if status_code == 404:
                logger.debug(f"Rule endpoint not available (404): {endpoint}")
                missing_endpoints.append(endpoint)
                continue

            if status_code is None:
                logger.warning(f"Rule endpoint probe failed for {endpoint}: {error_text}")
                other_errors.append(f"{endpoint}: {error_text}")
                continue

            # Unexpected HTTP status.
            logger.warning(f"Rule endpoint probe returned HTTP {status_code}: {endpoint}")
            other_errors.append(f"{endpoint}: HTTP {status_code}")

        if collected_rows:
            result: Dict[str, Any] = {
                'results': collected_rows,
                'source': 'softwareRule',
                'resolved_rule_endpoint': ','.join(accessible_endpoints),
                'rule_endpoints_accessible': accessible_endpoints,
                'rule_endpoints_forbidden': forbidden_endpoints,
                'rule_endpoints_missing': missing_endpoints,
            }
            if forbidden_endpoints or missing_endpoints or other_errors:
                result['error_type'] = 'PARTIAL_ACCESS'
                result['hint'] = 'Some rule endpoints are unavailable or denied; using accessible rule sources only.'
            if other_errors:
                result['error'] = '; '.join(other_errors)
            return result

        if forbidden_endpoints:
            return {
                'results': [],
                'error': '; '.join(other_errors) if other_errors else '403 Forbidden',
                'source': 'softwareRule',
                'resolved_rule_endpoint': None,
                'rule_endpoints_accessible': [],
                'rule_endpoints_forbidden': forbidden_endpoints,
                'rule_endpoints_missing': missing_endpoints,
                'error_type': 'FORBIDDEN',
                'hint': 'Token lacks permission to read the available rule endpoints in this server build.'
            }

        if missing_endpoints:
            return {
                'results': [],
                'error': '; '.join(other_errors) if other_errors else None,
                'source': 'softwareRule',
                'resolved_rule_endpoint': None,
                'rule_endpoints_accessible': [],
                'rule_endpoints_forbidden': forbidden_endpoints,
                'rule_endpoints_missing': missing_endpoints,
                'error_type': 'NOT_FOUND',
                'hint': 'No known rule endpoints were available in this server build.'
            }

        return {
            'results': [],
            'source': 'softwareRule',
            'resolved_rule_endpoint': None,
            'rule_endpoints_accessible': [],
            'rule_endpoints_forbidden': [],
            'rule_endpoints_missing': [],
        }

    def _query_endpoint_soft(self, endpoint: str, rows: int) -> Tuple[Optional[int], Optional[Dict], Optional[str]]:
        """Query endpoint without raising/logging hard errors for expected fallback statuses."""
        # App Control REST API pagination params are 'limit'/'offset', not 'rows'/'start'.
        params = {'limit': rows, 'offset': 0}
        url = self.api_client._build_url(endpoint, params)

        try:
            response = self.api_client.session.get(url, verify=self.api_client.verify_ssl)
        except Exception as exc:
            return None, None, str(exc)

        if response.status_code == 200:
            try:
                return 200, response.json(), None
            except Exception as exc:
                return 200, None, f"Failed to parse JSON from {endpoint}: {exc}"

        error_text = None
        try:
            error_text = response.text
        except Exception:
            error_text = f"HTTP {response.status_code}"

        return response.status_code, None, error_text


class EnforcementReadinessCollector:
    """Main collector that orchestrates all data collection for enforcement readiness."""
    
    def __init__(self, api_client: CBApiClient, max_rows: int = 0, lookback_days: int = 60):
        self.api_client = api_client
        # max_rows <= 0 means "no cap" - fetch the full dataset via pagination.
        self.max_rows = max_rows
        self.lookback_days = lookback_days
        self.file_catalog = FileCatalogCollector(api_client)
        self.certificate = CertificateCollector(api_client)
        self.publisher = PublisherCollector(api_client)
        self.file_instance = FileInstanceCollector(api_client)
        self.computer = ComputerCollector(api_client)
        self.event = EventCollector(api_client)
        self.software_rule = SoftwareRuleCollector(api_client)

    def _safe_collect(self, fn, source_name: str) -> Dict:
        """Collect data without aborting full workflow when optional endpoints fail."""
        try:
            return fn()
        except Exception as exc:
            logger.warning(f"Optional collection failed for {source_name}: {exc}")
            return {'results': [], 'error': str(exc), 'source': source_name}
    
    def collect_all_trust_signals(self) -> Dict:
        """
        Collect all data needed for trust signal analysis.

        Warns when the file catalog exceeds max_rows so callers know the
        analysis covers a partial sample rather than the full catalog.

        Returns:
            Dictionary containing all trust signal data
        """
        logger.info("Collecting trust signals for enforcement readiness...")

        # Check catalog size upfront so we can warn before analysis begins.
        # rows=0 always means "fetch everything" here (used purely to get an exact count).
        catalog_total = self._get_count(self.file_catalog.get_unknown_binaries(rows=0))
        capped = self.max_rows > 0
        if capped and catalog_total > self.max_rows:
            logger.warning(
                f"File catalog contains {catalog_total:,} unknown binaries but analysis "
                f"is capped at {self.max_rows:,} rows. Results represent a partial sample. "
                f"Use --max-rows to increase the limit."
            )
        elif capped:
            logger.info(f"File catalog: {catalog_total:,} unknown binaries (within {self.max_rows:,} row cap)")
        else:
            logger.info(f"File catalog: {catalog_total:,} unknown binaries (no row cap, fetching full catalog)")

        active_computers = self.computer.get_active_computers(rows=self.max_rows)
        active_computer_rows = active_computers if isinstance(active_computers, list) else active_computers.get('results', [])
        active_computer_ids = [
            str(computer.get('id')) for computer in active_computer_rows
            if isinstance(computer, dict) and computer.get('id') is not None
        ]
        event_history = self.event.get_event_history(rows=self.max_rows, lookback_days=self.lookback_days)
        all_catalog_files = self.file_catalog.get_all(rows=self.max_rows)
        all_catalog_rows = all_catalog_files if isinstance(all_catalog_files, list) else []
        trust_signals = {
            'catalog_files': all_catalog_rows,
            'unknown_binaries': [row for row in all_catalog_rows if row.get('effectiveState') == 'Unapproved'],
            'approved_binaries': [row for row in all_catalog_rows if row.get('effectiveState') == 'Approved'],
            'trusted_publishers': self.publisher.get_trusted_publishers(rows=self.max_rows),
            'blocked_publishers': self.publisher.get_blocked_publishers(rows=self.max_rows),
            'all_publishers': self.publisher.get_all_by_reputation(rows=self.max_rows),
            'valid_certificates': self.certificate.get_valid_certificates(rows=self.max_rows),
            'invalid_certificates': self.certificate.get_invalid_certificates(rows=self.max_rows),
            'all_certificates': self.certificate.get_all_certificates(rows=self.max_rows),
            'file_prevalence': self.file_instance.get_file_prevalence(rows=self.max_rows),
            'active_computers': active_computers,
            'all_events': event_history,
            'new_unapproved_events': self._safe_collect(
                lambda: self.event.get_new_unapproved_file_events(rows=self.max_rows, lookback_days=self.lookback_days, computer_ids=active_computer_ids, event_history=event_history),
                'event'
            ),
            'block_events': self._safe_collect(
                lambda: self.event.get_block_events(rows=self.max_rows, lookback_days=self.lookback_days, computer_ids=active_computer_ids, event_history=event_history),
                'block event'
            ),
            'software_rules': self._safe_collect(
                lambda: self.software_rule.get_all_rules(rows=self.max_rows),
                'softwareRule'
            ),
            'catalog_total': catalog_total,
            'catalog_sampled': capped and catalog_total > self.max_rows,
        }

        logger.info(f"Collected trust signals from {len(trust_signals)} sources")
        return trust_signals
    
    def collect_summary(self) -> Dict:
        """
        Collect a summary of key metrics for enforcement readiness scoring.
        
        Returns:
            Summary dictionary
        """
        unknown = self._get_count(self.file_catalog.get_unknown_binaries(rows=0))
        approved = self._get_count(self.file_catalog.get_approved_binaries(rows=0))
        trusted_pub = self._get_count(self.publisher.get_trusted_publishers(rows=0))
        blocked_pub = self._get_count(self.publisher.get_blocked_publishers(rows=0))
        
        logger.info(f"Summary counts - unknown: {unknown}, approved: {approved}, trusted_pub: {trusted_pub}, blocked_pub: {blocked_pub}")
        
        return {
            'unknown_count': unknown,
            'approved_count': approved,
            'trusted_publisher_count': trusted_pub,
            'blocked_publisher_count': blocked_pub,
            'valid_certificate_count': self._get_count(self.certificate.get_valid_certificates(rows=0)),
            'active_computer_count': self._get_count(self.computer.get_active_computers(rows=0)),
        }
    
    def _get_count(self, response: Dict) -> int:
        """Extract count from API response."""
        # Handle both list and dict responses
        if isinstance(response, list):
            count = len(response)
        else:
            count = response.get('total', response.get('count', 0))
        
        logger.debug(f"API response count extraction: {response if isinstance(response, dict) else f'list({len(response)} items)'} → {count}")
        return count