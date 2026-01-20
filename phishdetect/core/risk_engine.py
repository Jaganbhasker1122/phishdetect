"""
PhishDetect v2.0 - Risk Scoring Engine
Calculates weighted phishing risk scores (0-100)
"""

from typing import Dict, List, Tuple
from dataclasses import dataclass, field
import logging
import re

logger = logging.getLogger(__name__)


@dataclass
class RiskScoreBreakdown:
    """Detailed risk score component"""
    url_score: float
    ai_score: float
    ti_score: float
    keyword_score: float
    header_score: float
    obfuscation_score: float
    
    # Weights
    url_weight: float = 0.25
    ai_weight: float = 0.20
    ti_weight: float = 0.25
    keyword_weight: float = 0.15
    header_weight: float = 0.10
    obfuscation_weight: float = 0.05
    
    # Final score
    final_risk_score: float = 0.0
    risk_band: str = "LOW"  # LOW, MEDIUM, HIGH, CRITICAL
    contributing_factors: List[str] = field(default_factory=list)
    confidence: float = 1.0


class RiskEngine:
    """
    Calculate phishing risk score from multiple factors
    
    RISK BANDS:
    0-20:    LOW RISK (Green)
    21-50:   MEDIUM RISK (Yellow)
    51-75:   HIGH RISK (Orange)
    76-100:  CRITICAL RISK (Red)
    """
    
    # Urgency keywords with base points
    URGENCY_KEYWORDS = {
        "urgent": 8,
        "immediate action required": 10,
        "immediate action": 9,
        "verify your account": 12,
        "verify account": 10,
        "confirm your identity": 11,
        "confirm identity": 10,
        "suspension": 9,
        "suspended": 9,
        "click here": 6,
        "update your information": 8,
        "limited time": 7,
        "final notice": 10,
        "act now": 8,
        "today only": 7,
        "expires today": 8,
        "expires in 24 hours": 9,
        "within 24 hours": 8,
    }
    
    # Fear/threat keywords
    FEAR_KEYWORDS = {
        "compromised": 9,
        "breach": 8,
        "attack": 7,
        "locked": 8,
        "disabled": 7,
        "payment failed": 6,
        "suspicious activity": 8,
        "unauthorized access": 11,
        "access denied": 7,
        "confirm password": 8,
        "security alert": 8,
        "unusual activity": 7,
    }
    
    # Suspicious TLDs
    SUSPICIOUS_TLDS = [
        '.tk', '.ml', '.ga', '.cf',  # Free registrars
        '.info', '.biz', '.pw',  # Abuse-prone
        '.work', '.download',  # Suspicious
    ]
    
    # URL shorteners
    URL_SHORTENERS = [
        'bit.ly', 'tinyurl', 'short.link', 'goo.gl',
        'ow.ly', 'tiny.cc', 't.co', 'u.to',
    ]
    
    def __init__(self, threat_intel_matches: List[Dict] = None):
        """
        Initialize risk engine
        threat_intel_matches: List of TI hit objects from threat intelligence
        """
        self.threat_intel_matches = threat_intel_matches or []
    
    def calculate_risk(self,
                      urls: List[str] = None,
                      ai_score: float = 0.0,
                      ti_score: float = 0.0,
                      keywords_found: List[str] = None,
                      header_anomalies_count: int = 0,
                      obfuscation_techniques: List[str] = None,
                      attachments: List[Dict] = None) -> RiskScoreBreakdown:
        """
        Calculate overall phishing risk score
        
        Returns: RiskScoreBreakdown with detailed scoring
        """
        
        # Calculate component scores
        url_score = self._calculate_url_score(urls or [])
        keyword_score = self._calculate_keyword_score(keywords_found or [])
        header_score = self._calculate_header_score(header_anomalies_count, attachments or [])
        obfuscation_score = self._calculate_obfuscation_score(obfuscation_techniques or [])
        
        # Create breakdown
        breakdown = RiskScoreBreakdown(
            url_score=url_score,
            ai_score=ai_score,
            ti_score=ti_score,
            keyword_score=keyword_score,
            header_score=header_score,
            obfuscation_score=obfuscation_score
        )
        
        # Calculate weighted final score
        final_score = (
            url_score * breakdown.url_weight +
            ai_score * breakdown.ai_weight +
            ti_score * breakdown.ti_weight +
            keyword_score * breakdown.keyword_weight +
            header_score * breakdown.header_weight +
            obfuscation_score * breakdown.obfuscation_weight
        )
        
        # Clamp to 0-100
        breakdown.final_risk_score = min(100, max(0, final_score))
        
        # Determine risk band
        breakdown.risk_band = self._determine_risk_band(breakdown.final_risk_score)
        
        # Identify top contributing factors
        breakdown.contributing_factors = self._identify_factors(breakdown)
        
        return breakdown
    
    def _calculate_url_score(self, urls: List[str]) -> float:
        """
        Calculate URL risk score (0-100)
        
        Factors:
        - Malicious domain matching (TI)
        - URL obfuscation (Base64, Hex, etc.)
        - Suspicious TLDs
        - Newly registered domains
        - Homoglyph attacks
        - URL shorteners
        - Redirect chains
        - Direct IP usage
        """
        
        if not urls:
            return 0.0
        
        base_points = 0
        
        for url in urls:
            url_lower = url.lower()
            
            # TI match check
            if self._check_ti_match(url):
                base_points += 50
            
            # Obfuscation detection
            if self._is_base64_url(url):
                base_points += 15
            if self._is_hex_encoded(url):
                base_points += 15
            if self._has_url_shortener(url):
                base_points += 10
            
            # Domain analysis
            if self._has_suspicious_tld(url):
                base_points += 8
            
            # Homoglyph detection
            if self._detect_homoglyph(url):
                base_points += 20
            
            # Punycode abuse
            if self._detect_punycode_abuse(url):
                base_points += 25
            
            # Direct IP usage
            if self._is_direct_ip(url):
                base_points += 10
            
            # Private IP (legitimate but unusual)
            if self._is_private_ip(url):
                base_points += 5
        
        return min(100, base_points)
    
    def _calculate_keyword_score(self, keywords: List[str]) -> float:
        """
        Calculate keyword urgency score (0-100)
        
        Combines urgency and fear keywords with frequency multiplier
        """
        if not keywords:
            return 0.0
        
        base_score = 0
        frequency_multiplier = 1.0
        
        # Score urgency keywords
        urgency_count = 0
        for keyword in keywords:
            keyword_lower = keyword.lower()
            if keyword_lower in self.URGENCY_KEYWORDS:
                base_score += self.URGENCY_KEYWORDS[keyword_lower]
                urgency_count += 1
            elif keyword_lower in self.FEAR_KEYWORDS:
                base_score += self.FEAR_KEYWORDS[keyword_lower]
        
        # Frequency multiplier (diminishing returns)
        if len(keywords) >= 3:
            frequency_multiplier = 1.2
        if len(keywords) >= 5:
            frequency_multiplier = 1.3
        if len(keywords) >= 8:
            frequency_multiplier = 1.4
        
        final_score = base_score * frequency_multiplier
        return min(100, final_score)
    
    def _calculate_header_score(self, anomalies_count: int, 
                               attachments: List[Dict] = None) -> float:
        """
        Calculate header anomaly risk score (0-100)
        
        Factors:
        - From/Reply-To domain mismatch
        - Authentication failures (SPF/DKIM/DMARC)
        - Suspicious attachments
        - Header injection attempts
        """
        
        base_points = 0
        
        # Header anomalies scoring
        if anomalies_count >= 3:
            base_points += 25
        elif anomalies_count >= 2:
            base_points += 15
        elif anomalies_count >= 1:
            base_points += 10
        
        # Attachment risks
        if attachments:
            for att in attachments:
                if self._is_risky_attachment(att):
                    base_points += 15
                if self._has_double_extension(att.get('filename', '')):
                    base_points += 20
                if self._is_macro_enabled(att.get('filename', '')):
                    base_points += 12
        
        return min(100, base_points)
    
    def _calculate_obfuscation_score(self, techniques: List[str]) -> float:
        """
        Calculate obfuscation technique risk (0-100)
        
        Factors:
        - ROT13/Caesar cipher
        - Unicode obfuscation
        - HTML entity abuse
        - Control character injection
        """
        
        if not techniques:
            return 0.0
        
        base_points = 0
        
        technique_points = {
            'rot13': 15,
            'caesar': 15,
            'unicode': 20,
            'html_entity': 10,
            'control_chars': 15,
            'encoded_payload': 25,
            'punycode': 20,
        }
        
        for technique in techniques:
            if technique in technique_points:
                base_points += technique_points[technique]
        
        return min(100, base_points)
    
    # Helper methods
    
    def _check_ti_match(self, url: str) -> bool:
        """Check if URL/domain matches threat intelligence"""
        if not self.threat_intel_matches:
            return False
        
        for match in self.threat_intel_matches:
            if url in match.get('url', '') or match.get('domain', '') in url:
                return True
        
        return False
    
    def _is_base64_url(self, url: str) -> bool:
        """Detect Base64 encoding in URL parameters"""
        param_match = re.search(r'[=?&](\w+)=([A-Za-z0-9+/=]{20,})', url)
        if not param_match:
            return False
        
        encoded = param_match.group(2)
        # Check if it looks like base64
        return len(encoded) > 20 and '=' in encoded or len(encoded) % 4 == 0
    
    def _is_hex_encoded(self, url: str) -> bool:
        """Detect hex encoding"""
        param_match = re.search(r'[=?&](\w+)=([0-9a-fA-F]{20,})', url)
        return bool(param_match)
    
    def _has_url_shortener(self, url: str) -> bool:
        """Check for known URL shortener patterns"""
        url_lower = url.lower()
        return any(shortener in url_lower for shortener in self.URL_SHORTENERS)
    
    def _has_suspicious_tld(self, url: str) -> bool:
        """Check for suspicious TLDs"""
        for tld in self.SUSPICIOUS_TLDS:
            if url.lower().endswith(tld):
                return True
        return False
    
    def _detect_homoglyph(self, url: str) -> bool:
        """
        Detect Unicode homoglyph attacks
        Example: Cyrillic 'а' instead of Latin 'a'
        """
        # Check for mixed scripts (simplified check)
        cyrillic_chars = re.findall(r'[а-яА-ЯЁё]', url)
        latin_chars = re.findall(r'[a-zA-Z]', url)
        
        # If mix of Cyrillic and Latin, suspicious
        return len(cyrillic_chars) > 0 and len(latin_chars) > 0
    
    def _detect_punycode_abuse(self, url: str) -> bool:
        """
        Detect Punycode/IDN abuse
        Example: xn--domain (internationalized domain names)
        """
        return 'xn--' in url.lower()
    
    def _is_direct_ip(self, url: str) -> bool:
        """Check if URL uses direct IP address"""
        ip_pattern = r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}'
        return bool(re.search(ip_pattern, url))
    
    def _is_private_ip(self, url: str) -> bool:
        """Check for private IP ranges"""
        ip_pattern = r'(\d+\.\d+\.\d+\.\d+)'
        match = re.search(ip_pattern, url)
        if not match:
            return False
        
        ip = match.group(1)
        parts = [int(p) for p in ip.split('.')]
        
        # Check private IP ranges
        if parts[0] == 10:
            return True
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        if parts[0] == 192 and parts[1] == 168:
            return True
        
        return False
    
    def _is_risky_attachment(self, attachment: Dict) -> bool:
        """Check if attachment is risky"""
        risky_extensions = {
            'exe', 'scr', 'msi', 'msp', 'vbs', 'js', 'bat',
            'com', 'pif', 'zip', 'rar', '7z', 'ps1', 'psm1',
            'app', 'deb', 'rpm', 'dmg'
        }
        
        ext = attachment.get('extension', '').lower()
        return ext in risky_extensions
    
    def _has_double_extension(self, filename: str) -> bool:
        """Detect double extension (e.g., invoice.pdf.exe)"""
        parts = filename.split('.')
        
        if len(parts) < 3:
            return False
        
        risky_exts = {'exe', 'scr', 'msi', 'vbs', 'js', 'bat', 'ps1'}
        
        # Check if final extension is risky
        if parts[-1].lower() in risky_exts:
            # Check if previous extension is common safe extension
            safe_exts = {'pdf', 'doc', 'docx', 'xls', 'xlsx', 'jpg', 'png'}
            return parts[-2].lower() in safe_exts
        
        return False
    
    def _is_macro_enabled(self, filename: str) -> bool:
        """Detect macro-enabled Office documents"""
        macro_extensions = {'docm', 'xlsm', 'pptm', 'ppsx', 'potm'}
        ext = filename.split('.')[-1].lower() if '.' in filename else ''
        return ext in macro_extensions
    
    def _determine_risk_band(self, score: float) -> str:
        """Determine risk band from score"""
        if score >= 76:
            return "CRITICAL"
        elif score >= 51:
            return "HIGH"
        elif score >= 21:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _identify_factors(self, breakdown: RiskScoreBreakdown) -> List[str]:
        """Identify top contributing risk factors"""
        factors = []
        
        # Score components with their importance
        components = [
            (breakdown.ti_score * breakdown.ti_weight, "Threat intelligence match"),
            (breakdown.url_score * breakdown.url_weight, "Suspicious URLs detected"),
            (breakdown.ai_score * breakdown.ai_weight, "Likely AI-generated content"),
            (breakdown.header_score * breakdown.header_weight, "Header anomalies"),
            (breakdown.keyword_score * breakdown.keyword_weight, "Urgency/fear keywords"),
            (breakdown.obfuscation_score * breakdown.obfuscation_weight, "Obfuscation techniques"),
        ]
        
        # Sort and get top 3
        components.sort(reverse=True)
        for score, factor in components[:3]:
            if score > 0:
                factors.append(factor)
        
        return factors