"""
PhishDetect v2.0 - Report Generator
Generates professional TXT and JSON reports
"""

import json
from datetime import datetime
from typing import Dict, List, Any
from dataclasses import asdict
import logging

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generate professional scan reports"""
    
    def __init__(self):
        self.timestamp = datetime.utcnow().isoformat() + 'Z'
    
    def generate_txt_report(self, 
                           scan_data: Dict[str, Any],
                           filename: str = None) -> str:
        """Generate human-readable TXT report"""
        
        report = []
        
        # Header
        report.append("╔════════════════════════════════════════════════════════════════════╗")
        report.append("║                     PhishDetect v2.0 - SCAN REPORT                ║")
        report.append("╚════════════════════════════════════════════════════════════════════╝\n")
        
        # Email metadata
        report.append("📧 EMAIL METADATA")
        report.append("─" * 73)
        metadata = scan_data.get('email_metadata', {})
        report.append(f"From:              {metadata.get('sender', 'N/A')}")
        report.append(f"To:                {metadata.get('recipients', 'N/A')}")
        report.append(f"Subject:           {metadata.get('subject', '[No Subject]')}")
        report.append(f"Date:              {metadata.get('date', 'N/A')}")
        report.append(f"Message-ID:        {metadata.get('message_id', 'N/A')}")
        report.append(f"Content-Type:      {metadata.get('content_type', 'N/A')}\n")
        
        # Header anomalies
        anomalies = scan_data.get('header_anomalies', {})
        if anomalies.get('anomalies'):
            report.append("⚠️  HEADER ANOMALIES DETECTED")
            report.append("─" * 73)
            for anomaly in anomalies.get('anomalies', []):
                report.append(f"[!] {anomaly}")
            report.append()
        else:
            report.append("✅ No header anomalies detected\n")
        
        # AI detection
        ai_result = scan_data.get('ai_detection', {})
        report.append("🔍 AI-GENERATED ANALYSIS")
        report.append("─" * 73)
        ai_score = ai_result.get('ai_likelihood_score', 0)
        confidence = ai_result.get('confidence', 0)
        
        if ai_score > 70:
            status = "⚠️ (LIKELY AI-GENERATED)"
        elif ai_score > 50:
            status = "⚠️ (POSSIBLY AI)"
        else:
            status = "✓ (LIKELY HUMAN)"
        
        report.append(f"AI Likelihood Score: {ai_score}% {status}\n")
        report.append("Contributing Signals:")
        for signal in ai_result.get('reasoning', []):
            report.append(f"  ✓ {signal}")
        report.append(f"\nConfidence: {'HIGH' if confidence > 0.8 else 'MEDIUM' if confidence > 0.6 else 'LOW'} ({confidence:.0%})")
        report.append(f"\nVerdict: {ai_result.get('verdict', 'unknown')}\n")
        
        # URL analysis
        urls = scan_data.get('urls', [])
        report.append("🔗 URL ANALYSIS")
        report.append("─" * 73)
        
        if urls:
            for i, url in enumerate(urls, 1):
                report.append(f"[{i}] {url}")
                risk = scan_data.get('url_risks', {}).get(url, {})
                report.append(f"    Risk: {risk.get('risk_score', 0)}/100")
                for detail in risk.get('details', []):
                    report.append(f"    └─ {detail}")
            report.append()
        else:
            report.append("[+] No URLs detected\n")
        
        # Keyword analysis
        keywords = scan_data.get('keywords_found', [])
        report.append("📋 KEYWORD ANALYSIS")
        report.append("─" * 73)
        
        if keywords:
            report.append(f"Keywords Found: {len(keywords)}")
            for keyword in keywords[:10]:  # Show first 10
                report.append(f"  • {keyword}")
            if len(keywords) > 10:
                report.append(f"  ... and {len(keywords) - 10} more")
        else:
            report.append("No suspicious keywords detected")
        report.append()
        
        # Threat Intelligence
        ti_matches = scan_data.get('ti_matches', [])
        report.append("🎯 THREAT INTELLIGENCE MATCHES")
        report.append("─" * 73)
        
        if ti_matches:
            for match in ti_matches:
                report.append(f"[✗] {match.get('indicator_type', '').upper()}: {match.get('indicator', 'N/A')}")
                report.append(f"    Threat Type: {match.get('threat_type', 'N/A')}")
                report.append(f"    Confidence: {match.get('confidence', 0)}%")
                report.append(f"    Source: {match.get('threat_source', 'N/A')}")
                report.append(f"    Last Seen: {match.get('last_seen', 'N/A')}")
                if match.get('notes'):
                    report.append(f"    Notes: {match['notes']}")
                report.append()
        else:
            report.append("No threat intelligence matches found\n")
        
        # Attachments
        attachments = scan_data.get('attachments', [])
        report.append("📎 ATTACHMENT ANALYSIS")
        report.append("─" * 73)
        
        if attachments:
            report.append(f"Attachments Found: {len(attachments)}\n")
            for att in attachments:
                risk_indicator = "[⚠️] " if att.get('is_risky') else "[ ] "
                report.append(f"{risk_indicator}{att.get('filename', 'unknown')}")
                report.append(f"      Extension: .{att.get('extension', 'unknown')}")
                report.append(f"      Size: {att.get('size', 0)} bytes")
                report.append(f"      Risk: {att.get('risk_explanation', 'safe')}\n")
        else:
            report.append("No attachments\n")
        
        # Risk scoring
        risk_data = scan_data.get('risk_scoring', {})
        report.append("═" * 73)
        report.append()
        
        final_score = risk_data.get('final_risk_score', 0)
        risk_band = risk_data.get('risk_band', 'UNKNOWN')
        
        report.append(f"🚨 OVERALL RISK SCORE: {final_score}/100 [{risk_band}] 🚨\n")
        
        report.append("Risk Calculation Breakdown:")
        report.append(f"  • URL Score:           {risk_data.get('url_score', 0)}/100 × 0.25 = {risk_data.get('url_score', 0) * 0.25:.2f}")
        report.append(f"  • AI Score:            {risk_data.get('ai_score', 0)}/100 × 0.20 = {risk_data.get('ai_score', 0) * 0.20:.2f}")
        report.append(f"  • TI Score:            {risk_data.get('ti_score', 0)}/100 × 0.25 = {risk_data.get('ti_score', 0) * 0.25:.2f}")
        report.append(f"  • Keyword Score:       {risk_data.get('keyword_score', 0)}/100 × 0.15 = {risk_data.get('keyword_score', 0) * 0.15:.2f}")
        report.append(f"  • Header Score:        {risk_data.get('header_score', 0)}/100 × 0.10 = {risk_data.get('header_score', 0) * 0.10:.2f}")
        report.append(f"  • Obfuscation Score:   {risk_data.get('obfuscation_score', 0)}/100 × 0.05 = {risk_data.get('obfuscation_score', 0) * 0.05:.2f}")
        report.append("  " + "─" * 65)
        report.append(f"  TOTAL RISK SCORE:      {final_score:.2f}/100\n")
        
        # Contributing factors
        report.append("═" * 73)
        report.append()
        report.append("📊 TOP CONTRIBUTING FACTORS")
        report.append("─" * 73)
        
        factors = risk_data.get('contributing_factors', [])
        for i, factor in enumerate(factors, 1):
            report.append(f"{i}. {factor}")
        
        report.append()
        
        # Analyst verdict
        report.append("═" * 73)
        report.append()
        report.append("✅ ANALYST VERDICT")
        report.append("─" * 73)
        
        verdict = scan_data.get('analyst_verdict', {})
        recommendation = verdict.get('recommendation', 'REVIEW REQUIRED')
        report.append(f"RECOMMENDATION: {recommendation}\n")
        
        if recommendation == "IMMEDIATE QUARANTINE & INCIDENT RESPONSE":
            report.append("Actions:")
            report.append("  ☐ Block sender domain entirely")
            report.append("  ☐ Quarantine email from all recipients")
            report.append("  ☐ Alert end-user: Do NOT click links or download attachments")
            report.append("  ☐ Escalate to security team for investigation")
            report.append("  ☐ Monitor for similar phishing waves")
            report.append("  ☐ Check if recipient accessed malicious links (EDR logs)\n")
        
        reasoning = verdict.get('reasoning', [])
        if reasoning:
            report.append("Reasoning:")
            for reason in reasoning[:3]:
                report.append(f"  • {reason}")
            report.append()
        
        confidence_str = f"({verdict.get('confidence', 0):.0%})" if verdict.get('confidence') else ""
        report.append(f"⚡ CONFIDENCE: {verdict.get('verdict', 'UNKNOWN').upper()} {confidence_str}\n")
        
        # IOCs
        report.append("═" * 73)
        report.append()
        report.append("📈 INDICATORS OF COMPROMISE (IOCs)")
        report.append("─" * 73)
        
        iocs = scan_data.get('iocs', {})
        
        if iocs.get('domains'):
            report.append("Domains:")
            for domain in iocs['domains']:
                report.append(f"  • {domain}")
            report.append()
        
        if iocs.get('urls'):
            report.append("URLs:")
            for url in iocs['urls'][:10]:
                report.append(f"  • {url}")
            if len(iocs['urls']) > 10:
                report.append(f"  ... and {len(iocs['urls']) - 10} more")
            report.append()
        
        if iocs.get('emails'):
            report.append("Email Addresses:")
            for email in iocs['emails']:
                report.append(f"  • {email}")
            report.append()
        
        if iocs.get('phones'):
            report.append("Phone Numbers:")
            for phone in iocs['phones']:
                report.append(f"  • {phone}")
            report.append()
        
        # Footer
        report.append("═" * 73)
        report.append(f"Generated: {self.timestamp}")
        report.append("Report Version: PhishDetect v2.0")
        report.append("═" * 73)
        
        report_text = '\n'.join(report)
        
        # Save to file if requested
        if filename:
            with open(filename, 'w') as f:
                f.write(report_text)
            logger.info(f"TXT report saved: {filename}")
        
        return report_text
    
    def generate_json_report(self, 
                            scan_data: Dict[str, Any],
                            filename: str = None) -> str:
        """Generate machine-readable JSON report"""
        
        # Prepare report structure
        report = {
            "scan_metadata": {
                "version": "2.0",
                "timestamp": self.timestamp,
                "tool": "PhishDetect"
            },
            "scan_results": scan_data
        }
        
        json_str = json.dumps(report, indent=2, default=str)
        
        # Save to file if requested
        if filename:
            with open(filename, 'w') as f:
                f.write(json_str)
            logger.info(f"JSON report saved: {filename}")
        
        return json_str
    
    def generate_summary(self, risk_score: float, risk_band: str) -> str:
        """Generate brief summary of risk"""
        
        summary = {
            "score": risk_score,
            "band": risk_band,
            "recommendation": self._get_recommendation(risk_band),
            "action_level": self._get_action_level(risk_band)
        }
        
        return json.dumps(summary, indent=2)
    
    @staticmethod
    def _get_recommendation(risk_band: str) -> str:
        """Get recommendation based on risk band"""
        recommendations = {
            "CRITICAL": "IMMEDIATE QUARANTINE & INCIDENT RESPONSE",
            "HIGH": "ESCALATE TO SECURITY TEAM & BLOCK SENDER",
            "MEDIUM": "REVIEW CAREFULLY & VERIFY SENDER",
            "LOW": "NO ACTION REQUIRED"
        }
        return recommendations.get(risk_band, "REVIEW REQUIRED")
    
    @staticmethod
    def _get_action_level(risk_band: str) -> str:
        """Get action level for SOC prioritization"""
        levels = {
            "CRITICAL": "P1",
            "HIGH": "P2",
            "MEDIUM": "P3",
            "LOW": "P4"
        }
        return levels.get(risk_band, "UNKNOWN")