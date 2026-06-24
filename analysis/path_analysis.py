# Path Analysis Module
# Identifies and classifies file paths for trust signal analysis

import re
import logging
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class PathCategory(Enum):
    """Categories for file path classification."""
    SYSTEM = "system"           # System directories - high trust
    APPLICATION = "application" # Application directories - medium trust
    USER_PROFILE = "user_profile" # User profile directories - medium trust
    USER_WRITABLE = "user_writable" # User-writable - LOW trust, exclude from auto-approve
    TEMP = "temp"               # Temp directories - LOW trust
    DOWNLOADS = "downloads"     # Downloads - LOW trust
    REMOVABLE = "removable"     # Removable media - LOW trust
    NETWORK = "network"         # Network shares - medium trust
    UNKNOWN = "unknown"         # Unclassified


@dataclass
class PathClassification:
    """Result of path classification."""
    original_path: str
    category: PathCategory
    is_user_writable: bool
    confidence: float
    reason: str


class PathClassifier:
    """Classifies file paths for trust analysis."""
    
    # Patterns for user-writable paths (NEVER auto-approve)
    USER_WRITABLE_PATTERNS = [
        # Windows user-writable locations
        r'(?i)\\Users\\[^\\]+\\AppData\\Local\\Temp',
        r'(?i)\\Users\\[^\\]+\\AppData\\Local\\Temporary Internet Files',
        r'(?i)\\Users\\[^\\]+\\Downloads',
        r'(?i)\\Users\\[^\\]+\\Desktop',
        r'(?i)\\Users\\[^\\]+\\Documents\\My Documents',
        r'(?i)\\Windows\\Temp',
        r'(?i)\\Temp\\',
        r'(?i)\\tmp\\',
        # Linux/Mac user-writable
        r'(?i)/tmp/',
        r'(?i)/var/tmp/',
        r'(?i)/Users/[^/]+/Downloads',
        r'(?i)/Users/[^/]+/Desktop',
        r'(?i)/home/[^/]+/Downloads',
        r'(?i)/home/[^/]+/Desktop',
    ]
    
    # Patterns for system directories (high trust)
    SYSTEM_PATTERNS = [
        # Windows system
        r'(?i)\\Windows\\System32',
        r'(?i)\\Windows\\SysWOW64',
        r'(?i)\\Program Files\\',
        r'(?i)\\Program Files \(x86\)\\' ,
        r'(?i)\\Windows\\',
        # Linux/Mac system
        r'(?i)/usr/bin/',
        r'(?i)/usr/lib/',
        r'(?i)/System/',
        r'(?i)/bin/',
        r'(?i)/sbin/',
    ]
    
    # Patterns for application directories (medium trust)
    APPLICATION_PATTERNS = [
        r'(?i)\\Program Files\\',
        r'(?i)\\Program Files \(x86\)\\' ,
        r'(?i)/opt/',
        r'(?i)/Applications/',
    ]
    
    # Patterns for user profile directories (medium trust)
    USER_PROFILE_PATTERNS = [
        r'(?i)\\Users\\[^\\]+\\AppData\\Roaming',
        r'(?i)\\Users\\[^\\]+\\AppData\\Local',
        r'(?i)/Users/[^/]+/Library/Application Support',
        r'(?i)/home/[^/]+/.',
    ]
    
    # Patterns for temp directories (low trust)
    TEMP_PATTERNS = [
        r'(?i)\\Temp\\',
        r'(?i)\\tmp\\',
        r'(?i)/tmp/',
        r'(?i)/var/tmp/',
    ]
    
    # Patterns for downloads (low trust)
    DOWNLOADS_PATTERNS = [
        r'(?i)\\Downloads',
        r'(?i)/Downloads',
    ]
    
    # Patterns for removable media (low trust)
    REMOVABLE_PATTERNS = [
        r'(?i)[A-Z]:\\Users\\[^\\]+\\Documents\\My removable devices',
        r'(?i)/media/',
        r'(?i)/mnt/',
        r'(?i)/Volumes/',
    ]
    
    # Patterns for network shares (medium trust)
    NETWORK_PATTERNS = [
        r'(?i)\\\\\\[^\\]+\\',
        r'(?i)//[^/]+/',
        r'(?i)\\\\',
        r'(?i)/network/',
        r'(?i)/net/',
    ]
    
    def __init__(self):
        # Compile regex patterns for performance
        self._user_writable_re = [re.compile(p) for p in self.USER_WRITABLE_PATTERNS]
        self._system_re = [re.compile(p) for p in self.SYSTEM_PATTERNS]
        self._application_re = [re.compile(p) for p in self.APPLICATION_PATTERNS]
        self._user_profile_re = [re.compile(p) for p in self.USER_PROFILE_PATTERNS]
        self._temp_re = [re.compile(p) for p in self.TEMP_PATTERNS]
        self._downloads_re = [re.compile(p) for p in self.DOWNLOADS_PATTERNS]
        self._removable_re = [re.compile(p) for p in self.REMOVABLE_PATTERNS]
        self._network_re = [re.compile(p) for p in self.NETWORK_PATTERNS]
    
    def classify_path(self, file_path: str) -> PathClassification:
        """
        Classify a single file path.
        
        Args:
            file_path: The file path to classify
            
        Returns:
            PathClassification with category and confidence
        """
        if not file_path:
            return PathClassification(
                original_path=file_path or "",
                category=PathCategory.UNKNOWN,
                is_user_writable=False,
                confidence=0.0,
                reason="Empty or null path"
            )
        
        # Check user-writable patterns first (highest priority - never auto-approve)
        for pattern in self._user_writable_re:
            if pattern.search(file_path):
                return PathClassification(
                    original_path=file_path,
                    category=PathCategory.USER_WRITABLE,
                    is_user_writable=True,
                    confidence=0.95,
                    reason=f"Matched user-writable pattern: {pattern.pattern}"
                )
        
        # Check temp patterns
        for pattern in self._temp_re:
            if pattern.search(file_path):
                return PathClassification(
                    original_path=file_path,
                    category=PathCategory.TEMP,
                    is_user_writable=True,
                    confidence=0.95,
                    reason="Matched temp directory pattern"
                )
        
        # Check downloads
        for pattern in self._downloads_re:
            if pattern.search(file_path):
                return PathClassification(
                    original_path=file_path,
                    category=PathCategory.DOWNLOADS,
                    is_user_writable=True,
                    confidence=0.90,
                    reason="Matched downloads directory"
                )
        
        # Check removable media
        for pattern in self._removable_re:
            if pattern.search(file_path):
                return PathClassification(
                    original_path=file_path,
                    category=PathCategory.REMOVABLE,
                    is_user_writable=True,
                    confidence=0.85,
                    reason="Matched removable media pattern"
                )
        
        # Check system patterns
        for pattern in self._system_re:
            if pattern.search(file_path):
                return PathClassification(
                    original_path=file_path,
                    category=PathCategory.SYSTEM,
                    is_user_writable=False,
                    confidence=0.90,
                    reason="Matched system directory pattern"
                )
        
        # Check application patterns
        for pattern in self._application_re:
            if pattern.search(file_path):
                return PathClassification(
                    original_path=file_path,
                    category=PathCategory.APPLICATION,
                    is_user_writable=False,
                    confidence=0.80,
                    reason="Matched application directory pattern"
                )
        
        # Check user profile patterns
        for pattern in self._user_profile_re:
            if pattern.search(file_path):
                return PathClassification(
                    original_path=file_path,
                    category=PathCategory.USER_PROFILE,
                    is_user_writable=False,
                    confidence=0.75,
                    reason="Matched user profile directory pattern"
                )
        
        # Check network patterns
        for pattern in self._network_re:
            if pattern.search(file_path):
                return PathClassification(
                    original_path=file_path,
                    category=PathCategory.NETWORK,
                    is_user_writable=False,
                    confidence=0.70,
                    reason="Matched network share pattern"
                )
        
        # No match found
        return PathClassification(
            original_path=file_path,
            category=PathCategory.UNKNOWN,
            is_user_writable=False,
            confidence=0.5,
            reason="Path did not match any known patterns"
        )
    
    def classify_paths(self, file_paths: List[str]) -> List[PathClassification]:
        """
        Classify multiple file paths.
        
        Args:
            file_paths: List of file paths to classify
            
        Returns:
            List of PathClassification results
        """
        return [self.classify_path(path) for path in file_paths]
    
    def filter_user_writable(self, file_paths: List[str]) -> Tuple[List[str], List[str]]:
        """
        Filter out user-writable paths.
        
        Args:
            file_paths: List of file paths to filter
            
        Returns:
            Tuple of (safe_paths, user_writable_paths)
        """
        safe = []
        user_writable = []
        
        for path in file_paths:
            classification = self.classify_path(path)
            if classification.is_user_writable:
                user_writable.append(path)
            else:
                safe.append(path)
        
        logger.info(f"Path filter: {len(safe)} safe, {len(user_writable)} user-writable")
        return safe, user_writable
    
    def get_path_distribution(self, file_paths: List[str]) -> Dict:
        """
        Get distribution of path categories.
        
        Args:
            file_paths: List of file paths to analyze
            
        Returns:
            Dictionary with category counts
        """
        distribution = {
            'system': 0,
            'application': 0,
            'user_profile': 0,
            'user_writable': 0,
            'temp': 0,
            'downloads': 0,
            'removable': 0,
            'network': 0,
            'unknown': 0
        }
        
        for path in file_paths:
            classification = self.classify_path(path)
            distribution[classification.category.value] += 1
        
        return distribution


class InstallerLineageAnalyzer:
    """Analyzes file creation patterns to identify installer-generated binaries."""
    
    # Known installer patterns
    INSTALLER_INDICATORS = [
        # MSI installers
        r'(?i)\.msi',
        r'(?i)msiexec',
        # Setup executables
        r'(?i)setup\.exe',
        r'(?i)install\.exe',
        r'(?i)_setup\.exe',
        r'(?i)unins\d+\.exe',
        # Common installers
        r'(?i)installers?',
        r'(?i)setup',
        r'(?i)uninstall',
    ]
    
    # File extensions commonly created by installers
    INSTALLER_CREATED_EXTENSIONS = [
        '.dll', '.exe', '.ocx', '.sys', '.cpl', '.ax', '.acm'
    ]
    
    def __init__(self):
        self._installer_re = [re.compile(p) for p in self.INSTALLER_INDICATORS]
    
    def is_installer_related(self, file_path: str) -> bool:
        """Check if file is installer-related."""
        for pattern in self._installer_re:
            if pattern.search(file_path):
                return True
        return False
    
    def is_installer_created_extension(self, file_path: str) -> bool:
        """Check if file has installer-created extension."""
        lower_path = file_path.lower()
        return any(lower_path.endswith(ext) for ext in self.INSTALLER_CREATED_EXTENSIONS)
    
    def analyze_installer_lineage(self, binaries: List[Dict]) -> Dict:
        """
        Analyze potential installer-created binaries.
        
        Args:
            binaries: List of binary records with file paths
            
        Returns:
            Analysis of installer lineage
        """
        installer_related = []
        installer_extensions = []
        other = []
        
        for binary in binaries:
            file_path = binary.get('filePath', '')
            
            if self.is_installer_related(file_path):
                installer_related.append(binary)
            elif self.is_installer_created_extension(file_path):
                installer_extensions.append(binary)
            else:
                other.append(binary)
        
        return {
            'installer_related_count': len(installer_related),
            'installer_extensions_count': len(installer_extensions),
            'other_count': len(other),
            'installer_related': installer_related[:10],  # Sample
            'installer_extensions': installer_extensions[:10]  # Sample
        }