"""
PhishDetect v2.0 - Local Threat Intelligence Engine
Loads and matches against offline threat feeds
"""

import json
import re
from typing import Dict, List, Optional, Set
from dataclasses import dataclass
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


@dataclass
class ThreatIntelligenceHit:
    """Threat intelligence match result"""
    indicator: str  # domain, URL, phone, IP, email
    indicator_type: str  # "domain", "url", "phone", "ip", "email"
    threat_type: str  # "phishing", "malware", "scam", "botnet-c2"
    confidence: int  # 1-100 (percentage)
    threat_source: str  # e.g., "industry-feed-1", "community-report"
    category: str  # "credential-harvesting", "trojan", etc.
    last_seen: str  # Date ISO format
    notes: str  # Additional context
    target_brand: Optional[str] = None  # For phishing (e.g., "Apple", "PayPal")


class ThreatIntelligenceEngine:
    """
    Load and manage offline threat intelligence feeds
    Supports JSON feeds with domain, URL, phone, and IP data
    """
    
    def __init__(self, feeds_directory: str = "data/threat_feeds"):
        """Initialize TI engine and load feeds"""
        self.feeds_directory = Path(feeds_directory)
        self.malicious_domains: Set[str] = set()
        self.phishing_urls: Set[str] = set()
        self.scam_phones: Set[str] = set()
        self.botnet_ips: Set[str] = set()
        
        # Detailed records for scoring
        self.domain_records: Dict[str, ThreatIntelligenceHit] = {}
        self.url_records: Dict[str, ThreatIntelligenceHit] = {}
        self.phone_records: Dict[str, ThreatIntelligenceHit] = {}
        self.ip_records: Dict[str, ThreatIntelligenceHit] = {}
        
        # Domain index for fast lookup
        self.domain_index: Dict[str, ThreatIntelligenceHit] = {}
        
        self.load_feeds()
    
    def load_feeds(self):
        """Load all threat intelligence feeds from directory"""
        
        if not self.feeds_directory.exists():
            logger.warning(f"Threat feeds directory not found: {self.feeds_directory}")
            return
        
        # Load malicious domains
        self._load_json_feed("malicious_domains.json", self._parse_domains)
        
        # Load phishing URLs
        self._load_json_feed("phishing_urls.json", self._parse_urls)
        
        # Load scam phone numbers
        self._load_json_feed("scam_phones.json", self._parse_phones)
        
        # Load IP blocklists
        self._load_json_feed("ip_blocklist.json", self._parse_ips)
        
        logger.info(f"Loaded TI feeds: {len(self.domain_index)} domains, "
                   f"{len(self.url_records)} URLs, {len(self.phone_records)} phones")
    
    def _load_json_feed(self, filename: str, parser_func):
        """Load a JSON feed file"""
        filepath = self.feeds_directory / filename
        
        if not filepath.exists():
            logger.debug(f"Feed not found: {filename}")
            return
        
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            parser_func(data)
            logger.debug(f"Loaded {filename}")
        except Exception as e:
            logger.error(f"Error loading {filename}: {e}")
    
    def _parse_domains(self, data: Dict):
        """Parse malicious domains feed"""
        entries = data.get('malicious_domains', [])
        
        for entry in entries:
            domain = entry.get('domain', '').lower()
            if not domain:
                continue
            
            hit = ThreatIntelligenceHit(
                indicator=domain,
                indicator_type='domain',
                threat_type=entry.get('threat_type', 'phishing'),
                confidence=entry.get('confidence', 50),
                threat_source=entry.get('source', 'unknown'),
                category=entry.get('category', 'malicious'),
                last_seen=entry.get('last_seen', 'unknown'),
                notes=entry.get('notes', ''),
            )
            
            self.domain_records[domain] = hit
            self.domain_index[domain] = hit
            self.malicious_domains.add(domain)
    
    def _parse_urls(self, data: Dict):
        """Parse phishing URLs feed"""
        entries = data.get('phishing_urls', [])
        
        for entry in entries:
            url = entry.get('url', '').lower()
            if not url:
                continue
            
            hit = ThreatIntelligenceHit(
                indicator=url,
                indicator_type='url',
                threat_type=entry.get('threat_type', 'phishing'),
                confidence=entry.get('confidence', 50),
                threat_source=entry.get('source', 'unknown'),
                category=entry.get('category', 'credential-harvesting'),
                last_seen=entry.get('last_seen', 'unknown'),
                notes=entry.get('notes', ''),
                target_brand=entry.get('target_brand'),
            )
            
            self.url_records[url] = hit
            self.phishing_urls.add(url)
    
    def _parse_phones(self, data: Dict):
        """Parse scam phone numbers feed"""
        entries = data.get('scam_phone_numbers', [])
        
        for entry in entries:
            phone = entry.get('number', '').lower()
            if not phone:
                continue
            
            hit = ThreatIntelligenceHit(
                indicator=phone,
                indicator_type='phone',
                threat_type=entry.get('threat_type', 'scam'),
                confidence=entry.get('confidence', 50),
                threat_source=entry.get('source', 'unknown'),
                category=entry.get('category', 'tech-support-scam'),
                last_seen=entry.get('last_seen', 'unknown'),
                notes=entry.get('notes', ''),
                target_brand=entry.get('target_brand'),
            )
            
            self.phone_records[phone] = hit
            self.scam_phones.add(phone)
    
    def _parse_ips(self, data: Dict):
        """Parse suspicious IP addresses feed"""
        entries = data.get('suspicious_ips', [])
        
        for entry in entries:
            ip = entry.get('ip', '')
            if not ip:
                continue
            
            hit = ThreatIntelligenceHit(
                indicator=ip,
                indicator_type='ip',
                threat_type=entry.get('threat_type', 'suspicious'),
                confidence=entry.get('confidence', 50),
                threat_source=entry.get('source', 'unknown'),
                category=entry.get('category', 'suspicious-ip'),
                last_seen=entry.get('last_seen', 'unknown'),
                notes=entry.get('notes', ''),
            )
            
            self.ip_records[ip] = hit
            self.botnet_ips.add(ip)
    
    def match_domain(self, domain: str) -> Optional[ThreatIntelligenceHit]:
        """
        Match domain against threat intelligence
        Supports:
        - Exact domain match
        - Subdomain match (e.g., phishing.malicious-domain.com)
        """
        domain_lower = domain.lower()
        
        # Exact match
        if domain_lower in self.domain_index:
            return self.domain_index[domain_lower]
        
        # Subdomain match
        parts = domain_lower.split('.')
        for i in range(len(parts) - 1):
            root_domain = '.'.join(parts[i:])
            if root_domain in self.domain_index:
                return self.domain_index[root_domain]
        
        return None
    
    def match_url(self, url: str) -> Optional[ThreatIntelligenceHit]:
        """
        Match full URL against threat intelligence
        """
        url_lower = url.lower()
        
        # Exact match
        if url_lower in self.url_records:
            return self.url_records[url_lower]
        
        # Partial match (for redirects/variations)
        for stored_url, record in self.url_records.items():
            if stored_url in url_lower or url_lower.startswith(stored_url):
                return record
        
        return None
    
    def match_phone(self, phone: str) -> Optional[ThreatIntelligenceHit]:
        """
        Match phone number against threat intelligence
        """
        phone_normalized = self._normalize_phone(phone)
        
        if phone_normalized in self.phone_records:
            return self.phone_records[phone_normalized]
        
        # Partial match for known variations
        for stored_phone, record in self.phone_records.items():
            stored_normalized = self._normalize_phone(stored_phone)
            if self._phones_similar(phone_normalized, stored_normalized):
                return record
        
        return None
    
    def match_ip(self, ip: str) -> Optional[ThreatIntelligenceHit]:
        """Match IP address against threat intelligence"""
        if ip in self.ip_records:
            return self.ip_records[ip]
        
        return None
    
    def match_email(self, email: str) -> Optional[ThreatIntelligenceHit]:
        """
        Match email address against threat intelligence
        Currently checks domain reputation
        """
        domain = email.split('@')[1].lower() if '@' in email else ''
        return self.match_domain(domain) if domain else None
    
    def check_all_indicators(self, 
                            urls: List[str] = None,
                            domains: List[str] = None,
                            phones: List[str] = None,
                            email_addresses: List[str] = None) -> List[ThreatIntelligenceHit]:
        """
        Check multiple indicators and return all matches
        """
        matches = []
        
        # Check URLs
        for url in (urls or []):
            match = self.match_url(url)
            if match:
                matches.append(match)
        
        # Check domains
        for domain in (domains or []):
            match = self.match_domain(domain)
            if match:
                matches.append(match)
        
        # Check phone numbers
        for phone in (phones or []):
            match = self.match_phone(phone)
            if match:
                matches.append(match)
        
        # Check email addresses
        for email in (email_addresses or []):
            match = self.match_email(email)
            if match:
                matches.append(match)
        
        # Remove duplicates
        return list({m.indicator: m for m in matches}.values())
    
    def get_threat_score_from_hits(self, hits: List[ThreatIntelligenceHit]) -> float:
        """
        Calculate aggregate threat score from TI matches
        Returns 0-100 score
        """
        if not hits:
            return 0.0
        
        # Use highest confidence score
        max_confidence = max(hit.confidence for hit in hits)
        return float(max_confidence)
    
    @staticmethod
    def _normalize_phone(phone: str) -> str:
        """Normalize phone number for comparison"""
        # Remove common separators
        normalized = re.sub(r'[\s\-\(\)\.]+', '', phone)
        # Remove leading +
        normalized = normalized.lstrip('+')
        return normalized.lower()
    
    @staticmethod
    def _phones_similar(phone1: str, phone2: str) -> bool:
        """Check if two phone numbers are similar"""
        # Simple check: if one is substring of other or vice versa
        return phone1 in phone2 or phone2 in phone1
    
    def create_sample_feeds(self):
        """Create sample threat feed files for testing"""
        
        sample_data = {
            "malicious_domains": [
                {
                    "domain": "fake-verify-account.com",
                    "threat_type": "phishing",
                    "confidence": 95,
                    "last_seen": "2025-01-20",
                    "source": "industry-feed-1",
                    "category": "credential-harvesting",
                    "notes": "Targets PayPal users"
                },
                {
                    "domain": "secure-update.net",
                    "threat_type": "malware-distribution",
                    "confidence": 88,
                    "last_seen": "2025-01-18",
                    "source": "community-report",
                    "category": "trojan",
                    "notes": "Distributes TrickBot variant"
                }
            ],
            "phishing_urls": [
                {
                    "url": "https://secure-update.net/apple/verify?session=abc123",
                    "threat_type": "phishing",
                    "confidence": 99,
                    "last_seen": "2025-01-19",
                    "source": "user-report",
                    "target_brand": "Apple",
                    "notes": "Login credential harvesting"
                }
            ],
            "scam_phone_numbers": [
                {
                    "number": "+1-800-FAKE-SUPPORT",
                    "threat_type": "tech-support-scam",
                    "confidence": 85,
                    "last_seen": "2025-01-15",
                    "source": "fcc-complaints",
                    "target_brand": "Microsoft",
                    "notes": "Call center in India, requests payment"
                }
            ],
            "suspicious_ips": []
        }
        
        # Ensure directory exists
        self.feeds_directory.mkdir(parents=True, exist_ok=True)
        
        # Write sample feeds
        for filename, key in [
            ("malicious_domains.json", "malicious_domains"),
            ("phishing_urls.json", "phishing_urls"),
            ("scam_phones.json", "scam_phone_numbers"),
            ("ip_blocklist.json", "suspicious_ips")
        ]:
            filepath = self.feeds_directory / filename
            with open(filepath, 'w') as f:
                json.dump({key: sample_data[key]}, f, indent=2)
            logger.info(f"Created sample feed: {filename}")