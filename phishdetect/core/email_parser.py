"""
PhishDetect v2.0 - Email Parser Module
Handles EML/TXT email parsing, header extraction, and anomaly detection
"""

import re
import email
from email.policy import default as email_policy
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, field
from urllib.parse import urlparse
import logging

logger = logging.getLogger(__name__)


@dataclass
class EmailMetadata:
    """Structured email metadata"""
    sender: str
    sender_display: str
    reply_to: str
    recipients: List[str]
    subject: str
    date: str
    message_id: str
    user_agent: str
    content_type: str
    body_plain: str
    body_html: str
    urls: List[str] = field(default_factory=list)
    attachments: List[Dict] = field(default_factory=list)


@dataclass
class HeaderAnomalies:
    """Header-level security issues"""
    from_reply_to_mismatch: bool = False
    from_envelope_mismatch: bool = False
    reply_to_absent: bool = False
    display_name_abuse: bool = False
    spf_fail: bool = False
    dkim_fail: bool = False
    dmarc_fail: bool = False
    suspicious_user_agent: bool = False
    impossible_timestamp: bool = False
    header_injection_attempt: bool = False
    anomalies: List[str] = field(default_factory=list)


class EmailParser:
    """Parse and extract features from EML/TXT email formats"""
    
    # Regex patterns
    URL_PATTERN = re.compile(
        r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    )
    EMAIL_PATTERN = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
    SUSPICIOUS_USER_AGENTS = [
        "unknown", "suspicious", "spoofed", "fake", "malicious",
        "phishing", "botnet", "trojan", "none", ""
    ]
    
    def __init__(self):
        self.email_message = None
        self.metadata = None
        self.anomalies = HeaderAnomalies()
    
    def parse_eml(self, filepath: str) -> EmailMetadata:
        """Parse EML file"""
        try:
            with open(filepath, 'rb') as f:
                self.email_message = email.message_from_binary_file(f, policy=email_policy)
            return self._extract_metadata()
        except Exception as e:
            logger.error(f"Error parsing EML file: {e}")
            raise
    
    def parse_raw(self, raw_email: str) -> EmailMetadata:
        """Parse raw email text"""
        try:
            self.email_message = email.message_from_string(raw_email, policy=email_policy)
            return self._extract_metadata()
        except Exception as e:
            logger.error(f"Error parsing raw email: {e}")
            raise
    
    def _extract_metadata(self) -> EmailMetadata:
        """Extract all metadata from parsed email"""
        
        # Basic headers
        sender = self.email_message.get('From', 'unknown')
        reply_to = self.email_message.get('Reply-To', '')
        recipients = self._extract_recipients()
        subject = self.email_message.get('Subject', '[No Subject]')
        date = self.email_message.get('Date', '')
        message_id = self.email_message.get('Message-ID', '')
        user_agent = self.email_message.get('User-Agent', '')
        content_type = self.email_message.get('Content-Type', '')
        
        # Extract sender display name and address
        sender_display, sender_addr = self._parse_email_address(sender)
        
        # Extract body
        body_plain, body_html = self._extract_body()
        
        # Extract URLs from body
        urls = self._extract_urls(body_plain + body_html)
        
        # Extract attachments
        attachments = self._extract_attachments()
        
        self.metadata = EmailMetadata(
            sender=sender_addr,
            sender_display=sender_display,
            reply_to=reply_to,
            recipients=recipients,
            subject=subject,
            date=date,
            message_id=message_id,
            user_agent=user_agent,
            content_type=content_type,
            body_plain=body_plain,
            body_html=body_html,
            urls=urls,
            attachments=attachments
        )
        
        # Analyze header anomalies
        self._check_header_anomalies()
        
        return self.metadata
    
    def _extract_recipients(self) -> List[str]:
        """Extract all recipient addresses"""
        recipients = []
        for field in ['To', 'Cc', 'Bcc']:
            header = self.email_message.get(field, '')
            if header:
                addresses = self.EMAIL_PATTERN.findall(header)
                recipients.extend(addresses)
        return list(set(recipients))  # Remove duplicates
    
    def _parse_email_address(self, addr_str: str) -> Tuple[str, str]:
        """Parse email address into display name and address"""
        if '<' in addr_str and '>' in addr_str:
            display = addr_str.split('<')[0].strip().strip('"\'')
            addr = addr_str.split('<')[1].split('>')[0].strip()
            return display, addr
        else:
            return '', addr_str.strip()
    
    def _extract_body(self) -> Tuple[str, str]:
        """Extract plain text and HTML body"""
        body_plain = ''
        body_html = ''
        
        if self.email_message.is_multipart():
            for part in self.email_message.iter_parts():
                content_type = part.get_content_type()
                try:
                    payload = part.get_payload(decode=True)
                    if isinstance(payload, bytes):
                        payload = payload.decode('utf-8', errors='ignore')
                    
                    if content_type == 'text/plain':
                        body_plain += payload
                    elif content_type == 'text/html':
                        body_html += payload
                except Exception as e:
                    logger.warning(f"Error extracting body part: {e}")
        else:
            body_plain = self.email_message.get_payload(decode=True)
            if isinstance(body_plain, bytes):
                body_plain = body_plain.decode('utf-8', errors='ignore')
        
        return body_plain, body_html
    
    def _extract_urls(self, text: str) -> List[str]:
        """Extract URLs from text"""
        urls = self.URL_PATTERN.findall(text)
        
        # Also extract from href attributes
        href_pattern = r'href=["\']([^"\']+)["\']'
        hrefs = re.findall(href_pattern, text, re.IGNORECASE)
        
        # Combine and deduplicate
        all_urls = list(set(urls + hrefs))
        return [url for url in all_urls if url.startswith('http')]
    
    def _extract_attachments(self) -> List[Dict]:
        """Extract attachment metadata"""
        attachments = []
        
        if not self.email_message.is_multipart():
            return attachments
        
        for part in self.email_message.iter_parts():
            filename = part.get_filename()
            if filename:
                attachments.append({
                    'filename': filename,
                    'size': len(part.get_payload()),
                    'mime_type': part.get_content_type(),
                    'extension': self._extract_extension(filename)
                })
        
        return attachments
    
    @staticmethod
    def _extract_extension(filename: str) -> str:
        """Extract file extension"""
        if '.' in filename:
            return filename.split('.')[-1].lower()
        return ''
    
    def _check_header_anomalies(self):
        """Detect header-based phishing indicators"""
        if not self.metadata:
            return
        
        sender_domain = self._extract_domain(self.metadata.sender)
        reply_to_domain = self._extract_domain(self.metadata.reply_to)
        
        # Check From/Reply-To mismatch
        if self.metadata.reply_to and sender_domain != reply_to_domain:
            self.anomalies.from_reply_to_mismatch = True
            self.anomalies.anomalies.append(
                f"From domain ({sender_domain}) differs from Reply-To ({reply_to_domain})"
            )
        
        # Check for suspicious user agent
        if self.metadata.user_agent.lower() in self.SUSPICIOUS_USER_AGENTS:
            self.anomalies.suspicious_user_agent = True
            self.anomalies.anomalies.append("Suspicious or missing User-Agent header")
        
        # Check for SPF/DKIM/DMARC (header parsing)
        auth_results = self.email_message.get('Authentication-Results', '')
        if auth_results:
            if 'spf=fail' in auth_results.lower():
                self.anomalies.spf_fail = True
                self.anomalies.anomalies.append("SPF authentication failed")
            if 'dkim=fail' in auth_results.lower():
                self.anomalies.dkim_fail = True
                self.anomalies.anomalies.append("DKIM authentication failed")
            if 'dmarc=fail' in auth_results.lower():
                self.anomalies.dmarc_fail = True
                self.anomalies.anomalies.append("DMARC authentication failed")
        
        # Check for header injection attempts (null bytes, newlines)
        for header_value in [self.metadata.sender, self.metadata.subject, self.metadata.reply_to]:
            if '\x00' in header_value or '\n' in header_value or '\r' in header_value:
                self.anomalies.header_injection_attempt = True
                self.anomalies.anomalies.append("Header injection attempt detected")
                break
        
        # Check if Reply-To is missing but body requests reply
        if not self.metadata.reply_to and any(phrase in self.metadata.body_plain.lower() 
                                              for phrase in ['please reply', 'respond to', 'contact us']):
            self.anomalies.reply_to_absent = True
            self.anomalies.anomalies.append("Reply-To absent but body requests response")
    
    @staticmethod
    def _extract_domain(email_address: str) -> str:
        """Extract domain from email address"""
        try:
            match = re.search(r'@([a-zA-Z0-9.-]+)', email_address)
            return match.group(1).lower() if match else ''
        except:
            return ''
    
    def get_anomalies(self) -> HeaderAnomalies:
        """Return detected header anomalies"""
        return self.anomalies
    
    def get_html_links(self) -> List[Dict]:
        """Extract HTML links with display text and href"""
        links = []
        href_pattern = r'<a\s+(?:[^>]*?\s+)?href=(["\'])([^"\']*)\1[^>]*>([^<]*)</a>'
        
        matches = re.finditer(href_pattern, self.metadata.body_html, re.IGNORECASE)
        for match in matches:
            href = match.group(2)
            display_text = match.group(3).strip()
            links.append({
                'href': href,
                'display_text': display_text,
                'mismatch': href != display_text and not display_text.startswith('http')
            })
        
        return links
    
    def extract_sender_ip(self) -> Optional[str]:
        """Extract sender IP from Received header (if available)"""
        received = self.email_message.get('Received', '')
        ip_pattern = r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}'
        match = re.search(ip_pattern, received)
        return match.group(0) if match else None