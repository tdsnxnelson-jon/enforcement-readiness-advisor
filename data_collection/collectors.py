# Data Collectors for CB App Control API
# Each collector focuses on a specific data type for enforcement readiness

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
                rows: int = 1000) -> Dict:
        """Collect data from the endpoint."""
        return self.api_client.query(self.endpoint, filters, facets, rows)
    
    def collect_facet(self, facet_field: str, 
                     filters: Optional[List[str]] = None,
                     rows: int = 100) -> Dict:
        """Collect facet data from the endpoint."""
        return self.api_client.facet_query(self.endpoint, facet_field, filters, rows)


class FileCatalogCollector(BaseCollector):
    """Collects file catalog data for binary analysis."""
    
    def __init__(self, api_client: CBApiClient):
        super().__init__(api_client, 'fileCatalog')
    
    def get_unknown_binaries(self, rows: int = 1000) -> Dict:
        """Get all unapproved binaries."""
        return self.collect(
            filters=['approvalState:NOT_APPROVED'],
            facets=['publisherName', 'signer', 'fileType'],
            rows=rows
        )
    
    def get_approved_binaries(self, rows: int = 1000) -> Dict:
        """Get all approved binaries."""
        return self.collect(
            filters=['approvalState:APPROVED'],
            facets=['publisherName', 'signer'],
            rows=rows
        )
    
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
    
    def get_valid_certificates(self, rows: int = 100) -> Dict:
        """Get certificates with valid signatures."""
        return self.collect(
            filters=['hasValidSignature:true'],
            facets=['issuer'],
            rows=rows
        )
    
    def get_invalid_certificates(self, rows: int = 100) -> Dict:
        """Get certificates with invalid signatures."""
        return self.collect(
            filters=['hasValidSignature:false'],
            facets=['issuer'],
            rows=rows
        )

    def get_all_certificates(self, rows: int = 2000) -> Dict:
        """Get all certificates for full certificate-chain resolution."""
        return self.collect(rows=rows)
    
    def get_by_issuer(self, issuer: str, rows: int = 100) -> Dict:
        """Get certificates by issuer."""
        return self.collect(
            filters=[f'issuer:{issuer}'],
            rows=rows
        )


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

    def get_new_unapproved_file_events(self, rows: int = 1000) -> Dict:
        """Get events related to new unapproved files with resilient filter fallback."""
        candidate_filters = [
            ['subtype:NEW_UNAPPROVED_FILE_TO_COMPUTER', 'fileState:UNAPPROVED'],
            ['eventType:NEW_UNAPPROVED_FILE_TO_COMPUTER'],
            ['description:*New Unapproved File to Computer*'],
            ['fileState:UNAPPROVED'],
        ]

        last_error: Optional[Exception] = None
        for filters in candidate_filters:
            try:
                return self.collect(filters=filters, rows=rows)
            except Exception as exc:
                last_error = exc
                logger.debug(f"Event filter failed {filters}: {exc}")

        if last_error:
            raise last_error

        return {'results': []}


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
            status_code, payload, error_text = self._query_endpoint_soft(endpoint, rows)

            if status_code == 200 and payload is not None:
                rows_payload = self._extract_payload_rows(payload)
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
        params = {'rows': rows, 'start': 0}
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

    def _extract_payload_rows(self, payload: Any) -> List[Dict[str, Any]]:
        """Normalize endpoint payload into a list of row dictionaries."""
        if payload is None:
            return []
        if isinstance(payload, list):
            return [row for row in payload if isinstance(row, dict)]
        if isinstance(payload, dict):
            rows = payload.get('results', payload.get('rows', []))
            if isinstance(rows, list):
                return [row for row in rows if isinstance(row, dict)]
        return []


class EnforcementReadinessCollector:
    """Main collector that orchestrates all data collection for enforcement readiness."""
    
    def __init__(self, api_client: CBApiClient, max_rows: int = 5000):
        self.api_client = api_client
        self.max_rows = max_rows
        self.file_catalog = FileCatalogCollector(api_client)
        self.certificate = CertificateCollector(api_client)
        self.company_name = CompanyNameCollector(api_client)
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
        catalog_total = self._get_count(self.file_catalog.get_unknown_binaries(rows=0))
        if catalog_total > self.max_rows:
            logger.warning(
                f"File catalog contains {catalog_total:,} unknown binaries but analysis "
                f"is capped at {self.max_rows:,} rows. Results represent a partial sample. "
                f"Use --max-rows to increase the limit."
            )
        else:
            logger.info(f"File catalog: {catalog_total:,} unknown binaries (within {self.max_rows:,} row cap)")

        trust_signals = {
            'unknown_binaries': self.file_catalog.get_unknown_binaries(rows=self.max_rows),
            'approved_binaries': self.file_catalog.get_approved_binaries(rows=self.max_rows),
            'trusted_publishers': self.company_name.get_trusted_publishers(rows=100),
            'blocked_publishers': self.company_name.get_blocked_publishers(rows=100),
            'valid_certificates': self.certificate.get_valid_certificates(rows=100),
            'invalid_certificates': self.certificate.get_invalid_certificates(rows=100),
            'all_certificates': self.certificate.get_all_certificates(rows=self.max_rows),
            'file_prevalence': self.file_instance.get_file_prevalence(rows=self.max_rows),
            'active_computers': self.computer.get_active_computers(rows=self.max_rows),
            'new_unapproved_events': self._safe_collect(
                lambda: self.event.get_new_unapproved_file_events(rows=self.max_rows),
                'event'
            ),
            'software_rules': self._safe_collect(
                lambda: self.software_rule.get_all_rules(rows=self.max_rows),
                'softwareRule'
            ),
            'catalog_total': catalog_total,
            'catalog_sampled': catalog_total > self.max_rows,
        }

        logger.info(f"Collected trust signals from {len(trust_signals)} sources")
        return trust_signals
    
    def collect_summary(self) -> Dict:
        """
        Collect a summary of key metrics for enforcement readiness scoring.
        
        Returns:
            Summary dictionary
        """
        return {
            'unknown_count': self._get_count(self.file_catalog.get_unknown_binaries(rows=0)),
            'approved_count': self._get_count(self.file_catalog.get_approved_binaries(rows=0)),
            'trusted_publisher_count': self._get_count(self.company_name.get_trusted_publishers(rows=0)),
            'blocked_publisher_count': self._get_count(self.company_name.get_blocked_publishers(rows=0)),
            'valid_certificate_count': self._get_count(self.certificate.get_valid_certificates(rows=0)),
            'active_computer_count': self._get_count(self.computer.get_active_computers(rows=0)),
        }
    
    def _get_count(self, response: Dict) -> int:
        """Extract count from API response."""
        # Handle both list and dict responses
        if isinstance(response, list):
            return len(response)
        return response.get('total', response.get('count', 0))