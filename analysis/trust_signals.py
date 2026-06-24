# Trust Signal Analysis Module
# Extracts and analyzes trust signals from collected data

from typing import Dict, List, Any, Optional
import logging
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class TrustSignal:
    """Represents a single trust signal."""
    signal_type: str          # e.g., "publisher_trust", "signer_valid", "prevalence"
    value: Any                # The signal value
    confidence: float         # 0.0 to 1.0
    source: str               # Source endpoint
    metadata: Dict = field(default_factory=dict)


@dataclass
class BinaryAnalysis:
    """Analysis result for a single binary."""
    file_id: str
    file_name: str
    file_path: str
    publisher: Optional[str] = None
    signer: Optional[str] = None
    certificate_id: Optional[str] = None
    approval_state: str = "UNKNOWN"
    prevalence: int = 0
    trust_level: Optional[str] = None  # From CB API: "TRUSTED", "UNTRUSTED", etc.
    threat_level: Optional[str] = None  # From CB API: "CRITICAL", "WARNING", etc.
    trust_signals: List[TrustSignal] = field(default_factory=list)
    risk_score: float = 0.0
    recommendation: str = "REVIEW"


class TrustSignalAnalyzer:
    """Analyzes collected data to extract trust signals."""
    
    def __init__(self, acceleration_mode: str = 'conservative'):
        self.acceleration_mode = acceleration_mode
        self.signals = []
    
    def analyze_unknown_binaries(self, data: Dict, prevalence_data: Optional[Dict] = None, 
                                 certificate_data: Optional[Dict] = None, 
                                 computer_data: Optional[Dict] = None) -> List[BinaryAnalysis]:
        """
        Analyze unknown binaries to find trust signals.
        
        Args:
            data: Response from fileCatalog endpoint with unknown binaries
            prevalence_data: Optional prevalence data from fileInstance endpoint
            certificate_data: Optional certificate details
            computer_data: Optional computer/endpoint information
            
        Returns:
            List of BinaryAnalysis with trust signals
        """
        results = []
        
        # Handle both list and dict responses
        if isinstance(data, list):
            rows = data
        else:
            rows = data.get('results', data.get('rows', []))
        
        # Build prevalence lookup with OS diversity
        prevalence_lookup = {}
        os_diversity = {}
        if prevalence_data and computer_data:
            prevalence_lookup, os_diversity = self._build_enhanced_prevalence_lookup(
                prevalence_data, computer_data)
        elif prevalence_data:
            if isinstance(prevalence_data, list):
                instances = prevalence_data
            else:
                instances = prevalence_data.get('results', prevalence_data.get('rows', []))
            
            for instance in instances:
                file_id = instance.get('fileCatalogId')
                if file_id:
                    prevalence_lookup[file_id] = prevalence_lookup.get(file_id, 0) + 1
        
        # Build certificate lookup for enhanced validation
        cert_lookup = {}
        if certificate_data:
            if isinstance(certificate_data, list):
                certs = certificate_data
            else:
                certs = certificate_data.get('results', certificate_data.get('rows', []))
            
            for cert in certs:
                cert_lookup[cert.get('id')] = cert
        
        for row in rows:
            file_id = row.get('id', '')
            prevalence = prevalence_lookup.get(file_id, 0)
            os_diversity_score = os_diversity.get(file_id, 0)
            
            # Enhanced certificate validation
            cert_info = None
            if row.get('certificateId') and row['certificateId'] in cert_lookup:
                cert_info = cert_lookup[row['certificateId']]
            
            analysis = BinaryAnalysis(
                file_id=file_id,
                file_name=row.get('fileName', ''),
                file_path=row.get('pathName', ''),
                publisher=row.get('company') or row.get('publisherOrCompany') or row.get('publisher'),
                signer=row.get('signer'),
                certificate_id=row.get('certificateId'),
                approval_state=row.get('effectiveState', row.get('approvalState', 'NOT_APPROVED')),
                prevalence=prevalence,
                trust_level=row.get('trust'),  # CB API trust indicator
                threat_level=row.get('threat')  # CB API threat indicator
            )
            
            # Extract enhanced trust signals
            analysis.trust_signals = self._extract_enhanced_signals(row, cert_info, os_diversity_score)
            analysis.risk_score = self._calculate_enhanced_risk_score(analysis)
            analysis.recommendation = self._generate_recommendation(analysis)
            
            results.append(analysis)
        
        logger.info(f"Analyzed {len(results)} unknown binaries with enhanced signals")
        return results
    
    def _build_enhanced_prevalence_lookup(self, prevalence_data: Dict, computer_data: Dict) -> tuple:
        """Build prevalence lookup with OS diversity scoring."""
        prevalence_lookup = {}
        os_diversity = {}
        
        # Build computer OS lookup
        computer_os = {}
        if isinstance(computer_data, list):
            computers = computer_data
        else:
            computers = computer_data.get('results', computer_data.get('rows', []))
        
        for comp in computers:
            comp_id = comp.get('id')
            # Try to infer OS from computer name or other fields
            name = comp.get('name', '').lower()
            if 'win' in name or 'windows' in name:
                computer_os[comp_id] = 'windows'
            elif 'mac' in name or 'osx' in name or 'darwin' in name:
                computer_os[comp_id] = 'mac'
            elif 'linux' in name:
                computer_os[comp_id] = 'linux'
            else:
                computer_os[comp_id] = 'unknown'
        
        # Build prevalence with OS diversity
        if isinstance(prevalence_data, list):
            instances = prevalence_data
        else:
            instances = prevalence_data.get('results', prevalence_data.get('rows', []))
        
        for instance in instances:
            file_id = instance.get('fileCatalogId')
            comp_id = instance.get('computerId')
            
            if file_id:
                prevalence_lookup[file_id] = prevalence_lookup.get(file_id, 0) + 1
                
                # Track OS diversity
                if file_id not in os_diversity:
                    os_diversity[file_id] = set()
                os_type = computer_os.get(comp_id, 'unknown')
                os_diversity[file_id].add(os_type)
        
        # Convert OS diversity sets to scores (more OS types = higher score)
        for file_id, os_set in os_diversity.items():
            os_diversity[file_id] = len(os_set)  # 1-3 score based on OS diversity
        
        return prevalence_lookup, os_diversity
    
    def _extract_enhanced_signals(self, row: Dict, cert_info: Optional[Dict] = None, 
                                 os_diversity: int = 0) -> List[TrustSignal]:
        """Extract enhanced trust signals including certificate validation, OS diversity, and CB trust indicators."""
        signals = []
        
        # CB API Trust Indicator - Most important signal!
        trust_field = row.get('trust')
        trust_value = None
        trust_confidence = 0.2
        if trust_field is not None:
            if isinstance(trust_field, (int, float)):
                if trust_field >= 8:
                    trust_value = 'TRUSTED'
                    trust_confidence = 0.95
                elif trust_field >= 5:
                    trust_value = 'KNOWN'
                    trust_confidence = 0.85
                elif trust_field >= 1:
                    trust_value = 'UNKNOWN'
                    trust_confidence = 0.3
                else:
                    trust_value = 'UNTRUSTED'
                    trust_confidence = 0.05
            else:
                trust_value = str(trust_field).upper()
                trust_confidence = {
                    'TRUSTED': 0.95,
                    'KNOWN': 0.85,
                    'UNKNOWN': 0.3,
                    'SUSPECT': 0.1,
                    'UNTRUSTED': 0.05
                }.get(trust_value, 0.2)
        
        if trust_value:
            signals.append(TrustSignal(
                signal_type='cb_trust_indicator',
                value=trust_value,
                confidence=trust_confidence,
                source='fileCatalog',
                metadata={'trust_level': trust_value}
            ))
        
        # CB API Threat Indicator
        threat_field = row.get('threat')
        threat_value = None
        threat_penalty = 0.0
        if threat_field is not None:
            if isinstance(threat_field, (int, float)):
                if threat_field >= 5:
                    threat_value = 'CRITICAL'
                    threat_penalty = -0.8
                elif threat_field >= 2:
                    threat_value = 'WARNING'
                    threat_penalty = -0.4
                elif threat_field >= 1:
                    threat_value = 'CAUTION'
                    threat_penalty = -0.2
                else:
                    threat_value = 'SAFE'
                    threat_penalty = 0.3
            else:
                threat_value = str(threat_field).upper()
                threat_penalty = {
                    'CRITICAL': -0.8,
                    'WARNING': -0.4,
                    'CAUTION': -0.2,
                    'SAFE': 0.3,
                    'UNKNOWN': 0.0
                }.get(threat_value, 0.0)
        
        if threat_value:
            signals.append(TrustSignal(
                signal_type='cb_threat_indicator',
                value=threat_value,
                confidence=abs(threat_penalty),
                source='fileCatalog',
                metadata={'threat_level': threat_value, 'penalty': threat_penalty}
            ))
        
        # Original signals
        publisher_name = row.get('company') or row.get('publisherOrCompany') or row.get('publisher')
        if publisher_name:
            signals.append(TrustSignal(
                signal_type='publisher_present',
                value=publisher_name,
                confidence=0.7,
                source='fileCatalog',
                metadata={'field': 'company'}
            ))
        
        if row.get('signer') and row.get('certificateId'):
            signals.append(TrustSignal(
                signal_type='signed_binary',
                value=row['signer'],
                confidence=0.8,
                source='fileCatalog',
                metadata={'certificateId': row.get('certificateId')}
            ))
        
        if row.get('certificateId'):
            base_confidence = 0.6
            metadata = {'certificateId': row['certificateId']}
            
            # Enhanced certificate validation
            if cert_info:
                # Check if certificate is currently valid
                if cert_info.get('hasValidSignature'):
                    base_confidence += 0.2
                    metadata['valid_signature'] = True
                
                # Check certificate age/maturity (older = more trustworthy)
                if cert_info.get('validStartDate'):
                    # This is a rough approximation - could be enhanced
                    base_confidence += 0.1
                    metadata['has_valid_dates'] = True
                
                # Trusted issuer bonus
                issuer = cert_info.get('issuer', '').upper()
                if any(trusted in issuer for trusted in ['MICROSOFT', 'VERISIGN', 'DIGICERT', 'GLOBALSIGN']):
                    base_confidence += 0.15
                    metadata['trusted_issuer'] = True
            
            signals.append(TrustSignal(
                signal_type='certificate_validated',
                value=row['certificateId'],
                confidence=min(base_confidence, 0.95),
                source='certificate',
                metadata=metadata
            ))
        
        # New signals for enhanced confidence
        
        # File age/maturity signal
        if row.get('createdAt') or row.get('lastObserved'):
            # Files that have been observed for longer periods are more trustworthy
            signals.append(TrustSignal(
                signal_type='file_maturity',
                value=row.get('createdAt') or row.get('lastObserved'),
                confidence=0.4,  # Base confidence, will be adjusted by age
                source='fileCatalog',
                metadata={'age_indicator': True}
            ))
        
        # OS diversity signal
        if os_diversity > 1:
            signals.append(TrustSignal(
                signal_type='os_diversity',
                value=os_diversity,
                confidence=min(0.3 + (os_diversity * 0.2), 0.8),  # 1 OS = 0.5, 2 OS = 0.7, 3+ OS = 0.8
                source='prevalence',
                metadata={'os_types': os_diversity}
            ))
        
        # File type trust signal
        file_type = row.get('fileType', '').lower()
        if file_type:
            type_confidence = self._calculate_file_type_trust(file_type)
            if type_confidence > 0:
                signals.append(TrustSignal(
                    signal_type='file_type_trust',
                    value=file_type,
                    confidence=type_confidence,
                    source='fileCatalog',
                    metadata={'file_type': file_type}
                ))
        
        return signals
    
    def _calculate_file_type_trust(self, file_type: str) -> float:
        """Calculate trust score based on file type."""
        trust_scores = {
            'exe': 0.3,      # Common, needs other signals
            'dll': 0.4,      # Libraries are generally trustworthy
            'sys': 0.6,      # Drivers are critical system components
            'ocx': 0.2,      # ActiveX, less common now
            'scr': 0.1,      # Screen savers, potential risk
            'cpl': 0.5,      # Control panel, system component
            'drv': 0.5,      # Legacy drivers
        }
        
        # Default trust for unknown types
        return trust_scores.get(file_type, 0.2)
    
    def _calculate_enhanced_risk_score(self, analysis: BinaryAnalysis) -> float:
        """
        Calculate enhanced risk score with CB trust indicators as primary signals.
        
        Scoring priorities:
        1. CB Trust Indicator (if available) - HIGHEST priority
        2. CB Threat Indicator (if available)
        3. Certificate & signature validation
        4. Publisher information
        5. File maturity and prevalence
        """
        score = 0.0
        
        # Check for CB API trust indicator first (this is the authoritative signal)
        cb_trust_signal = None
        cb_threat_signal = None
        
        for signal in analysis.trust_signals:
            if signal.signal_type == 'cb_trust_indicator':
                cb_trust_signal = signal
                break
        
        for signal in analysis.trust_signals:
            if signal.signal_type == 'cb_threat_indicator':
                cb_threat_signal = signal
                break
        
        # If CB indicates TRUSTED, high confidence
        if cb_trust_signal:
            trust_value = cb_trust_signal.value
            if trust_value == 'TRUSTED':
                score += 0.85  # Very high score for trusted
            elif trust_value == 'KNOWN':
                score += 0.70  # Good score for known
            elif trust_value == 'UNKNOWN':
                score += 0.30  # Lower score for unknown
            elif trust_value in ['SUSPECT', 'UNTRUSTED']:
                score += 0.05  # Very low score for untrusted
        else:
            # No CB trust indicator, use base score
            score += 0.15
        
        # Apply threat penalty
        if cb_threat_signal:
            threat_penalty = cb_threat_signal.metadata.get('penalty', 0)
            score += threat_penalty  # This can reduce score
        
        # Add secondary signals if CB trust is not available
        if not cb_trust_signal:
            signal_count = 0
            for signal in analysis.trust_signals:
                if signal.signal_type == 'publisher_present':
                    score += 0.15
                    signal_count += 1
                elif signal.signal_type == 'signed_binary':
                    score += 0.20
                    signal_count += 1
                elif signal.signal_type == 'certificate_validated':
                    score += 0.15
                    signal_count += 1
                elif signal.signal_type == 'file_maturity':
                    score += 0.10
                    signal_count += 1
                elif signal.signal_type == 'os_diversity':
                    score += 0.10
                    signal_count += 1
                elif signal.signal_type == 'file_type_trust':
                    score += 0.05
                    signal_count += 1
            
            # Diversity bonus
            if signal_count >= 3:
                score += 0.10
        
        # Cap at 1.0 and ensure minimum of 0.05 for files with some signals
        return max(0.05, min(score, 1.0))
    
    def _extract_signals(self, row: Dict) -> List[TrustSignal]:
        """Extract trust signals from a single binary record."""
        signals = []
        
        # Signal 1: Publisher trust
        if row.get('publisherName'):
            signals.append(TrustSignal(
                signal_type='publisher_present',
                value=row['publisherName'],
                confidence=0.7,
                source='fileCatalog',
                metadata={'field': 'publisherName'}
            ))
        
        # Signal 2: Valid signer
        if row.get('signer') and row.get('certificateId'):
            signals.append(TrustSignal(
                signal_type='signed_binary',
                value=row['signer'],
                confidence=0.8,
                source='fileCatalog',
                metadata={'certificateId': row.get('certificateId')}
            ))
        
        # Signal 3: Has certificate
        if row.get('certificateId'):
            signals.append(TrustSignal(
                signal_type='has_certificate',
                value=row['certificateId'],
                confidence=0.9,
                source='fileCatalog',
                metadata={'field': 'certificateId'}
            ))
        
        return signals
    
    def _calculate_risk_score(self, analysis: BinaryAnalysis) -> float:
        """
        Calculate risk score for a binary.
        
        Lower score = more risky (less trust signals)
        Higher score = safer (more trust signals)
        
        Scoring weights:
        - Base score: 0.2 (increased from 0.1)
        - Publisher present: +0.25 (even unknown publishers provide some trust)
        - Signed binary: +0.35 (strong trust signal)
        - Has certificate: +0.2 (valid certificate present)
        - Multiple signals bonus: +0.1 (diversity bonus)
        """
        score = 0.0
        
        # Base score for unknown binaries (increased)
        score += 0.2
        
        # Add points for trust signals
        signal_count = 0
        for signal in analysis.trust_signals:
            if signal.signal_type == 'publisher_present':
                score += 0.25
                signal_count += 1
            elif signal.signal_type == 'signed_binary':
                score += 0.35
                signal_count += 1
            elif signal.signal_type == 'has_certificate':
                score += 0.2
                signal_count += 1
        
        # Diversity bonus for multiple signal types
        if signal_count >= 2:
            score += 0.1
        
        # Cap at 1.0 and ensure minimum of 0.1
        return max(0.1, min(score, 1.0))
    
    def _generate_recommendation(self, analysis: BinaryAnalysis) -> str:
        """Generate recommendation based on analysis and acceleration mode."""
        if self.acceleration_mode == 'accelerated':
            # Lower thresholds for accelerated mode
            if analysis.risk_score >= 0.5:
                return "AUTO_APPROVE_CANDIDATE"
            elif analysis.risk_score >= 0.3:
                return "ACCELERATION_CANDIDATE"
            else:
                return "MANUAL_REVIEW_REQUIRED"
        else:
            # Conservative mode (original thresholds)
            if analysis.risk_score >= 0.7:
                return "AUTO_APPROVE_CANDIDATE"
            elif analysis.risk_score >= 0.4:
                return "ACCELERATION_CANDIDATE"
            else:
                return "MANUAL_REVIEW_REQUIRED"
    
    def get_acceleration_candidates(self, binaries: List[BinaryAnalysis], 
                                   certificate_data: Optional[Dict] = None,
                                   max_candidates: int = 10) -> List[Dict]:
        """
        Get acceleration recommendations focused on certificates and real publishers.
        
        Returns recommendations like:
        - Approve certificate 'Microsoft Corporation' (thumbprint: XXXX) which will approve Y files
        - Approve publisher X (will approve Y files, reduce blocks by Z%, increase readiness by A%)
        
        Args:
            binaries: List of analyzed binaries
            certificate_data: Optional certificate details with thumbprints
            max_candidates: Maximum number of recommendations to return
            
        Returns:
            List of acceleration recommendations with impact analysis
        """
        recommendations = []
        
        # Build certificate lookup with details
        cert_lookup = {}
        if certificate_data:
            if isinstance(certificate_data, list):
                certs = certificate_data
            else:
                certs = certificate_data.get('results', certificate_data.get('rows', []))
            
            for cert in certs:
                cert_id = cert.get('id')
                cert_lookup[cert_id] = {
                    'id': cert_id,
                    'parentCertificateId': cert.get('parentCertificateId'),
                    'subjectName': cert.get('subjectName', cert.get('subject', 'Unknown')),
                    'subject': cert.get('subject', cert.get('subjectName', 'Unknown')),
                    'issuer': cert.get('issuer', cert.get('issuerName', 'Unknown')),
                    'issuerName': cert.get('issuerName', cert.get('issuer', 'Unknown')),
                    'thumbprint': cert.get('thumbprint', 'N/A'),
                    'hasValidSignature': cert.get('hasValidSignature', cert.get('valid', False)),
                    'validStartDate': cert.get('validFrom', cert.get('validStartDate')),
                    'validEndDate': cert.get('validTo', cert.get('validEndDate'))
                }
        
        # Group binaries by certificate
        cert_groups = {}
        publisher_groups = {}  # For files with publishers but no certs
        
        for binary in binaries:
            if binary.certificate_id and binary.certificate_id in cert_lookup:
                # Group by certificate
                cert_id = binary.certificate_id
                if cert_id not in cert_groups:
                    cert_groups[cert_id] = []
                cert_groups[cert_id].append(binary)
            elif binary.publisher and binary.publisher != 'null':
                # Group by actual publisher
                pub = binary.publisher
                if pub not in publisher_groups:
                    publisher_groups[pub] = []
                publisher_groups[pub].append(binary)
        
        # Generate certificate recommendations (highest priority)
        for cert_id, files in cert_groups.items():
            if len(files) >= 2:  # Only recommend certs with multiple files
                cert_info = cert_lookup[cert_id]
                rec = self._create_certificate_recommendation(cert_id, cert_info, files, cert_lookup)
                if rec:
                    recommendations.append(rec)
        
        # Generate publisher recommendations (for files with real publishers)
        for publisher, files in publisher_groups.items():
            if len(files) >= 3:  # Only recommend publishers with multiple files
                rec = self._create_publisher_recommendation(publisher, files)
                if rec:
                    recommendations.append(rec)
        
        # If no specific recommendations, create general ones
        if not recommendations:
            recommendations = self._create_general_recommendations(binaries)
        
        # Sort by potential impact and confidence
        recommendations.sort(key=lambda x: (x['confidence_percent'], x['readiness_improvement_percent']), reverse=True)
        
        return recommendations[:max_candidates]
    
    def _create_certificate_recommendation(self, cert_id: str, cert_info: Dict,
                                           files: List[BinaryAnalysis],
                                           cert_lookup: Optional[Dict[int, Dict]] = None) -> Dict:
        """Create a certificate-based recommendation with thumbprint."""
        total_files = len(files)
        avg_risk_score = sum(f.risk_score for f in files) / total_files
        
        # Extract cert subject (usually contains the publisher name)
        subject_full = str(cert_info.get('subjectName') or cert_info.get('subject') or 'Unknown')
        subject = subject_full.splitlines()[0] if subject_full else 'Unknown'
        issuer = self._resolve_certificate_issuer(cert_info, cert_lookup or {})
        thumbprint = str(cert_info.get('thumbprint') or 'N/A')
        has_valid_sig = bool(cert_info.get('hasValidSignature', cert_info.get('valid', False)))
        
        # Calculate impact metrics
        blocks_reduction_percent = min(total_files * 1.5, 20.0)
        readiness_improvement_percent = min(total_files * 0.8, 12.0)
        
        # Confidence calculation
        base_confidence = avg_risk_score * 100
        
        # Valid signature bonus
        sig_bonus = 20 if has_valid_sig else 5
        
        # Trusted issuer bonus
        issuer_bonus = 0
        if any(trusted in issuer.upper() for trusted in ['MICROSOFT', 'VERISIGN', 'DIGICERT', 'GLOBALSIGN', 'THAWTE']):
            issuer_bonus = 15
        
        confidence_percent = min(base_confidence + sig_bonus + issuer_bonus, 95.0)
        
        return {
            'type': 'certificate_approval',
            'target': subject,
            'thumbprint': thumbprint,
            'issuer': issuer,
            'cert_id': cert_id,
            'has_valid_signature': has_valid_sig,
            'files_to_approve': total_files,
            'blocks_reduction_percent': round(blocks_reduction_percent, 1),
            'readiness_improvement_percent': round(readiness_improvement_percent, 1),
            'confidence_percent': round(confidence_percent, 1),
            'rationale': f"Approve certificate '{subject}' (thumbprint: {thumbprint[:16]}...). {total_files} unknown files will be approved with {round(confidence_percent, 1)}% confidence.",
            'priority': 'high' if confidence_percent >= 80 else 'medium' if confidence_percent >= 70 else 'low'
        }

    def _resolve_certificate_issuer(self, cert_info: Dict,
                                    cert_lookup: Dict[int, Dict]) -> str:
        """Resolve issuer, walking parent certificate chain when issuer is missing."""
        issuer = cert_info.get('issuer') or cert_info.get('issuerName')
        if issuer and str(issuer).strip() and str(issuer).strip().lower() != 'unknown':
            return str(issuer)

        parent_id = cert_info.get('parentCertificateId')
        visited = set()

        while parent_id and parent_id not in visited and parent_id in cert_lookup:
            visited.add(parent_id)
            parent = cert_lookup[parent_id]

            parent_subject = parent.get('subjectName') or parent.get('subject')
            if parent_subject and str(parent_subject).strip():
                return str(parent_subject).splitlines()[0]

            parent_issuer = parent.get('issuer') or parent.get('issuerName')
            if parent_issuer and str(parent_issuer).strip() and str(parent_issuer).strip().lower() != 'unknown':
                return str(parent_issuer)

            parent_id = parent.get('parentCertificateId')

        return 'Unknown'
    
    def _normalize_publisher_name(self, publisher: Optional[str], binary: BinaryAnalysis) -> str:
        """Use only real publisher names from CB API - NO file name heuristics."""
        # Return only actual publishers from the API, or None for unknowns
        if publisher and publisher != "null" and publisher.strip() and len(publisher.strip()) > 2:
            return publisher
        
        # If no real publisher, return None so this binary isn't included in recommendations
        return None
    
    def _create_general_recommendations(self, binaries: List[BinaryAnalysis]) -> List[Dict]:
        """Create general recommendations when specific ones aren't available."""
        recommendations = []
        
        # Group by risk score ranges
        high_risk = [b for b in binaries if b.risk_score >= 0.6]
        medium_risk = [b for b in binaries if 0.3 <= b.risk_score < 0.6]
        
        if high_risk:
            recommendations.append({
                'type': 'bulk_approval',
                'target': 'High-confidence files',
                'files_to_approve': len(high_risk),
                'blocks_reduction_percent': min(len(high_risk) * 0.5, 20.0),
                'readiness_improvement_percent': min(len(high_risk) * 0.3, 12.0),
                'confidence_percent': 75.0,
                'rationale': f"Bulk approve {len(high_risk)} high-confidence files (risk score >= 0.6)",
                'priority': 'high'
            })
            
        if medium_risk:
            recommendations.append({
                'type': 'bulk_approval', 
                'target': 'Medium-confidence files',
                'files_to_approve': len(medium_risk),
                'blocks_reduction_percent': min(len(medium_risk) * 0.3, 15.0),
                'readiness_improvement_percent': min(len(medium_risk) * 0.2, 8.0),
                'confidence_percent': 60.0,
                'rationale': f"Bulk approve {len(medium_risk)} medium-confidence files (risk score 0.3-0.6)",
                'priority': 'medium'
            })
            
        return recommendations
    
    def _is_installer_candidate(self, binary: BinaryAnalysis) -> bool:
        """Check if a binary could be a trusted installer candidate."""
        installer_keywords = ['setup', 'install', 'installer', 'msiexec', 'sccm', 'wsus']
        file_name_lower = binary.file_name.lower()
        
        # Check filename for installer patterns
        if any(keyword in file_name_lower for keyword in installer_keywords):
            return True
            
        # Check path for installer patterns
        path_lower = binary.file_path.lower()
        if any(keyword in path_lower for keyword in ['program files', 'windows\\installer', 'temp\\']):
            return True
            
        return False
    
    def _group_installers(self, installer_candidates: List[BinaryAnalysis]) -> Dict[str, List[BinaryAnalysis]]:
        """Group installer candidates by application/installer name."""
        groups = {}
        
        for binary in installer_candidates:
            # Extract installer name from filename/path
            installer_name = self._extract_installer_name(binary)
            if installer_name not in groups:
                groups[installer_name] = []
            groups[installer_name].append(binary)
            
        return groups
    
    def _extract_installer_name(self, binary: BinaryAnalysis) -> str:
        """Extract installer/application name from binary info."""
        # Simple extraction - could be enhanced with more sophisticated logic
        file_name = binary.file_name.lower()
        
        # Common installer patterns
        if 'setup' in file_name or 'install' in file_name:
            return binary.file_name
        elif binary.publisher:
            return f"{binary.publisher} Installer"
        else:
            return binary.file_name
    
    def _create_publisher_recommendation(self, publisher: str, files: List[BinaryAnalysis]) -> Dict:
        """Create a publisher-based recommendation."""
        total_files = len(files)
        avg_risk_score = sum(f.risk_score for f in files) / total_files
        high_prevalence_count = sum(1 for f in files if f.prevalence >= 3)
        
        # Calculate impact metrics
        blocks_reduction_percent = min(total_files / 10.0, 15.0)  # Rough estimate
        readiness_improvement_percent = min(total_files * 0.5, 10.0)  # Rough estimate
        confidence_percent = min(avg_risk_score * 100, 95.0)
        
        # Enhanced confidence calculation with more signals
        # Base confidence from risk score
        base_confidence = avg_risk_score * 100
        
        # Publisher reputation bonus (if we have trusted publisher data)
        publisher_bonus = 0
        if publisher in ['Microsoft Corporation', 'Windows System Files']:
            publisher_bonus = 25  # Known Microsoft components get bonus
        elif 'Hardware Drivers' in publisher:
            publisher_bonus = 15  # Drivers are generally trustworthy
        
        # Prevalence bonus (files that appear on more endpoints)
        prevalence_bonus = min(high_prevalence_count / total_files * 30, 20)
        
        # Diversity bonus (multiple trust signals per file)
        avg_signals = sum(len(f.trust_signals) for f in files) / total_files
        diversity_bonus = min(avg_signals * 5, 15)  # Up to 15% for diverse signals
        
        confidence_percent = min(base_confidence + publisher_bonus + prevalence_bonus + diversity_bonus, 95.0)
        
        return {
            'type': 'publisher_approval',
            'target': publisher,
            'files_to_approve': total_files,
            'blocks_reduction_percent': round(blocks_reduction_percent, 1),
            'readiness_improvement_percent': round(readiness_improvement_percent, 1),
            'confidence_percent': round(confidence_percent, 1),
            'rationale': (
                f"Approve publisher '{publisher}' — {total_files} unknown files, "
                f"avg risk score {avg_risk_score:.2f}, "
                f"{high_prevalence_count} file(s) seen on 3+ endpoints. "
                f"Confidence based on risk score, prevalence, and trust signal diversity."
            ),
            'priority': 'high' if confidence_percent >= 70 else 'medium'
        }
    
    def _create_installer_recommendation(self, installer_name: str, files: List[BinaryAnalysis]) -> Dict:
        """Create an installer-based recommendation."""
        total_files = len(files)
        avg_risk_score = sum(f.risk_score for f in files) / total_files
        
        # Installers typically have higher impact
        blocks_reduction_percent = min(total_files * 2.0, 25.0)  # Higher impact for installers
        readiness_improvement_percent = min(total_files * 1.0, 15.0)  # Higher impact for installers
        confidence_percent = min(avg_risk_score * 120, 90.0)  # Installers get confidence boost
        
        return {
            'type': 'trusted_installer',
            'target': installer_name,
            'files_to_approve': total_files,
            'blocks_reduction_percent': round(blocks_reduction_percent, 1),
            'readiness_improvement_percent': round(readiness_improvement_percent, 1),
            'confidence_percent': round(confidence_percent, 1),
            'rationale': f"Adding '{installer_name}' as trusted installer will approve {total_files} related files",
            'priority': 'high' if confidence_percent >= 75 else 'medium'
        }
    
    def _calculate_approval_impact(self, binary: BinaryAnalysis) -> float:
        """
        Calculate the impact of approving this binary on overall readiness score.
        
        Returns:
            Impact score (0.0 to 1.0) representing potential readiness improvement
        """
        impact = 0.0
        
        # Base impact from risk score
        impact += binary.risk_score * 0.4
        
        # Additional impact from prevalence (more endpoints = more impact)
        prevalence_factor = min(binary.prevalence / 10.0, 1.0)  # Cap at 10 endpoints
        impact += prevalence_factor * 0.3
        
        # Trust signal diversity bonus
        signal_types = set(s.signal_type for s in binary.trust_signals)
        diversity_bonus = len(signal_types) / 5.0  # Max 5 different signal types
        impact += diversity_bonus * 0.3
        
        return min(impact, 1.0)
    
    def analyze_publisher_trust(self, data: Dict) -> Dict:
        """
        Analyze publisher trust levels.
        
        Args:
            data: Response from companyName endpoint
            
        Returns:
            Dictionary of publisher trust analysis
        """
        # Handle both list and dict responses
        if isinstance(data, list):
            publishers = data
        else:
            publishers = data.get('results', data.get('rows', []))
        
        analysis = {
            'trusted': [],
            'blocked': [],
            'unknown': []
        }
        
        for pub in publishers:
            reputation = pub.get('reputation', 'UNKNOWN').upper()
            pub_info = {
                'id': pub.get('id'),
                'name': pub.get('name'),
                'reputation': reputation,
                'product_count': pub.get('productCount', 0)
            }
            
            if reputation == 'TRUSTED':
                analysis['trusted'].append(pub_info)
            elif reputation == 'BLOCKED':
                analysis['blocked'].append(pub_info)
            else:
                analysis['unknown'].append(pub_info)
        
        logger.info(f"Publisher analysis: {len(analysis['trusted'])} trusted, "
                   f"{len(analysis['blocked'])} blocked, "
                   f"{len(analysis['unknown'])} unknown")
        
        return analysis
    
    def analyze_certificate_trust(self, valid_data: Dict, 
                                  invalid_data: Dict) -> Dict:
        """
        Analyze certificate trust.
        
        Args:
            valid_data: Response with valid certificates
            invalid_data: Response with invalid certificates
            
        Returns:
            Certificate trust analysis
        """
        # Handle both list and dict responses
        if isinstance(valid_data, list):
            valid_results = valid_data
        else:
            valid_results = valid_data.get('results', valid_data.get('rows', []))
            
        if isinstance(invalid_data, list):
            invalid_results = invalid_data
        else:
            invalid_results = invalid_data.get('results', invalid_data.get('rows', []))
        
        return {
            'valid_count': len(valid_results),
            'invalid_count': len(invalid_results),
            'valid_signers': [c.get('subject') for c in valid_results],
            'invalid_signers': [c.get('subject') for c in invalid_results]
        }
    
    def analyze_prevalence(self, data: Dict) -> Dict:
        """
        Analyze file prevalence across endpoints.
        
        Args:
            data: Response from fileInstance endpoint
            
        Returns:
            Prevalence analysis
        """
        # Handle both list and dict responses
        if isinstance(data, list):
            instances = data
        else:
            instances = data.get('results', data.get('rows', []))
        
        # Count occurrences per file
        file_counts = {}
        for instance in instances:
            file_id = instance.get('fileCatalogId')
            if file_id:
                file_counts[file_id] = file_counts.get(file_id, 0) + 1
        
        # Categorize by prevalence
        analysis = {
            'high_prevalence': [],   # > 100 endpoints
            'medium_prevalence': [], # 10-100 endpoints
            'low_prevalence': [],    # < 10 endpoints
            'single_endpoint': []    # 1 endpoint
        }
        
        for file_id, count in file_counts.items():
            if count > 100:
                analysis['high_prevalence'].append({'file_id': file_id, 'count': count})
            elif count > 10:
                analysis['medium_prevalence'].append({'file_id': file_id, 'count': count})
            elif count > 1:
                analysis['low_prevalence'].append({'file_id': file_id, 'count': count})
            else:
                analysis['single_endpoint'].append({'file_id': file_id, 'count': count})
        
        logger.info(f"Prevalence analysis: {len(analysis['high_prevalence'])} high, "
                   f"{len(analysis['medium_prevalence'])} medium, "
                   f"{len(analysis['low_prevalence'])} low, "
                   f"{len(analysis['single_endpoint'])} single")
        
        return analysis


class EnforcementReadinessScorer:
    """Calculates enforcement readiness scores."""
    
    def __init__(self):
        self.weights = {
            'unknown_binaries': 0.35,
            'publisher_trust': 0.25,
            'certificate_trust': 0.15,
            'prevalence': 0.15,
            'computer_coverage': 0.10
        }
    
    def calculate_readiness_score(self, summary: Dict, 
                                   detailed_analysis: Dict) -> Dict:
        """
        Calculate overall enforcement readiness score.
        
        Args:
            summary: Summary metrics from collectors
            detailed_analysis: Detailed analysis from TrustSignalAnalyzer
            
        Returns:
            Readiness score and breakdown
        """
        scores = {}
        
        # Score 1: Unknown binary reduction
        unknown_pct = self._calculate_unknown_percentage(summary)
        scores['unknown_binaries'] = self._score_unknown_binaries(unknown_pct)
        
        # Score 2: Publisher trust coverage
        scores['publisher_trust'] = self._score_publisher_trust(detailed_analysis.get('publisher_analysis', {}))
        
        # Score 3: Certificate trust
        scores['certificate_trust'] = self._score_certificate_trust(detailed_analysis.get('certificate_analysis', {}))
        
        # Score 4: Prevalence patterns
        scores['prevalence'] = self._score_prevalence(detailed_analysis.get('prevalence_analysis', {}))

        # Score 5: Computer coverage
        scores['computer_coverage'] = self._score_computer_coverage(summary)
        
        # Calculate weighted total
        total_score = sum(
            scores[key] * self.weights[key] 
            for key in scores
        )
        
        return {
            'total_score': round(total_score * 100, 1),
            'breakdown': {k: round(v * 100, 1) for k, v in scores.items()},
            'weights': self.weights,
            'ready_for_high_enforcement': total_score >= 0.7,
            'recommendation': self._get_recommendation(total_score)
        }
    
    def _calculate_unknown_percentage(self, summary: Dict) -> float:
        """Calculate percentage of unknown binaries."""
        unknown = summary.get('unknown_count', 0)
        approved = summary.get('approved_count', 0)
        total = unknown + approved
        return (unknown / total) if total > 0 else 1.0
    
    def _score_unknown_binaries(self, unknown_pct: float) -> float:
        """Score based on unknown binary percentage."""
        # Lower unknown = higher score
        return 1.0 - unknown_pct
    
    def _score_publisher_trust(self, analysis: Dict) -> float:
        """Score based on publisher trust."""
        trusted = len(analysis.get('trusted', []))
        total = trusted + len(analysis.get('unknown', []))
        return trusted / total if total > 0 else 0.0
    
    def _score_certificate_trust(self, analysis: Dict) -> float:
        """Score based on certificate trust."""
        valid = analysis.get('valid_count', 0)
        invalid = analysis.get('invalid_count', 0)
        total = valid + invalid
        return valid / total if total > 0 else 0.5
    
    def _score_prevalence(self, analysis: Dict) -> float:
        """Score based on file prevalence patterns."""
        high = len(analysis.get('high_prevalence', []))
        medium = len(analysis.get('medium_prevalence', []))
        low = len(analysis.get('low_prevalence', []))
        single = len(analysis.get('single_endpoint', []))
        
        total = high + medium + low + single
        if total == 0:
            return 0.5
        
        # More high prevalence = more established = higher score
        return (high * 1.0 + medium * 0.7 + low * 0.3 + single * 0.1) / total
    
    def _score_computer_coverage(self, summary: Dict) -> float:
        """Score based on active computer coverage collected from the API."""
        count = summary.get('active_computer_count', 0)
        if count == 0:
            return 0.2
        if count < 6:
            return 0.4
        if count < 26:
            return 0.6
        if count < 101:
            return 0.8
        return 0.95
    
    def _get_recommendation(self, score: float) -> str:
        """Get recommendation based on score."""
        if score >= 0.8:
            return "READY_FOR_HIGH_ENFORCEMENT"
        elif score >= 0.6:
            return "NEAR_READY - ADDRESS REMAINING UNKNOWNS"
        elif score >= 0.4:
            return "MEDIUM ENFORCEMENT RECOMMENDED"
        else:
            return "MAINTAIN LOW ENFORCEMENT"