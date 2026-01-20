# PhishDetect v2.0

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![Status: Research/Educational](https://img.shields.io/badge/Status-Research%2FEducational-orange.svg)]()
[![Code Style: PEP 8](https://img.shields.io/badge/Code%20Style-PEP%208-brightgreen.svg)](https://www.python.org/dev/peps/pep-0008/)
[![Version 2.0](https://img.shields.io/badge/Version-2.0-blue.svg)]()
[![Last Updated: Jan 2026](https://img.shields.io/badge/Updated-Jan%202026-green.svg)]()

---

A **research-oriented email security analysis tool** built to understand phishing detection mechanisms, email forensics, and security operations workflows.

---

## ⚠️ Project Status & Scope

**PhishDetect v2.0 is a learning and research project**, not a commercial security product.

### Implementation Status

✅ **Fully Implemented**
- Email parsing (.eml, .txt, raw content)
- Header anomaly detection (heuristic-based)
- URL extraction and analysis
- Threat intelligence feed integration (JSON-based)
- AI-generated email detection (linguistic heuristics)
- Risk scoring system (weighted multi-factor)
- Professional CLI interface
- Report generation (TXT/JSON)
- Configuration menu

🟡 **Partially Implemented**
- Attachment analysis (detection framework exists)
- Advanced AI detection (basic patterns only)
- Custom threat feed management
- Settings persistence

⏳ **Planned (Not Yet Implemented)**
- Batch email processing (v2.1)
- Parallel analysis
- CSV/Excel export
- Email scheduling
- Database integration
- Web dashboard
- API endpoint

---

## What This Tool Does

PhishDetect analyzes emails using **heuristic-based security analysis**. It:

1. **Parses Email Content** - Extracts headers, body, URLs, attachments
2. **Detects Anomalies** - Identifies suspicious header patterns and mismatches
3. **Analyzes URLs** - Checks against threat feeds and detects obfuscation
4. **Linguistic Analysis** - Uses heuristics to identify AI-generated patterns
5. **Risk Scoring** - Combines multiple signals into 0-100 risk score
6. **Generates Reports** - Creates detailed analysis reports

### What This Tool Does NOT Do

- 🚫 Replace enterprise email security solutions
- 🚫 Guarantee detection of all phishing attacks
- 🚫 Provide real-time threat feeds (you load your own)
- 🚫 Protect against zero-day exploits
- 🚫 Execute or sandbox attachments
- 🚫 Integrate with email clients (yet)

---

## Why This Project Exists

This tool was built to:
- Understand email security fundamentals
- Learn how SOC analysts evaluate threats
- Explore phishing detection mechanisms
- Practice secure Python development
- Create an educational reference implementation

**This is not intended to replace commercial solutions** like Proofpoint, Mimecast, or Microsoft Defender.

---

## Quick Start

### Installation

```bash
# Clone repository
git clone https://github.com/Jaganbhasker1122/phishdetect.git
cd phishdetect

# Install dependencies
pip install -r requirements.txt

# Create directories
mkdir -p data/threat_feeds logs reports
```

### Running PhishDetect

```bash
python phishdetect.py
```

### Basic Usage

**Option [2] - Analyze Raw Email (Recommended)**

1. Select option: `2`
2. Paste email content
3. Press `Ctrl+D` (Mac/Linux) or `Ctrl+Z + Enter` (Windows)
4. Review risk score and recommendations
5. Export report if needed

**Option [1] - Analyze Email File**

1. Select option: `1`
2. Enter path to `.eml` or `.txt` file
3. Review analysis results

---

## Features

### Email Analysis

- Header extraction and anomaly detection
- URL detection and obfuscation analysis
- Attachment metadata inspection
- Recipient and sender analysis

### Risk Scoring

Combines multiple factors with adjustable weights:

| Factor | Default Weight | What It Detects |
|--------|---|---|
| Threat Intelligence | 25% | Known malicious domains/URLs |
| URL Analysis | 25% | Suspicious URL patterns |
| AI-Generated Content | 20% | Linguistic patterns suggesting AI generation |
| Keywords | 15% | Phishing-common words/phrases |
| Header Anomalies | 10% | SPF/DKIM failures, domain mismatches |
| Obfuscation | 5% | URL shorteners, encoding tricks |

**Risk Bands:**
- 0-20: Low Risk
- 21-50: Medium Risk
- 51-75: High Risk
- 76-100: Critical Risk

### Threat Intelligence

Load your own threat feeds as JSON files in `data/threat_feeds/`:

**Example: `data/threat_feeds/custom_domains.json`**

```json
{
  "malicious_domains": [
    {
      "domain": "paypal-secure.com",
      "threat_type": "phishing",
      "confidence": 95,
      "last_seen": "2025-01-20",
      "source": "custom",
      "category": "credential-harvesting",
      "notes": "Known phishing domain"
    }
  ]
}
```

**File Format Options:**
- `malicious_domains.json` - Suspicious domains
- `phishing_urls.json` - Phishing URLs
- `scam_phones.json` - Fraud phone numbers
- `botnet_ips.json` - Suspicious IP addresses

---

## Menu Options (7 Total)

| Option | Status | What It Does |
|--------|--------|---|
| [1] Analyze Email File | ✅ | Upload .eml or .txt file for analysis |
| [2] Analyze Raw Email | ✅ | Paste email content directly |
| [3] Batch Analysis | ⏳ | Scan multiple emails (v2.1) |
| [4] Threat Intelligence | ✅ | View loaded threat feeds |
| [5] Settings | 🟡 | Configure risk weights (partial) |
| [6] Documentation | ✅ | Help & usage guide |
| [7] Exit | ✅ | Close application |

---

## Architecture

### Core Modules

**`phishdetect/core/`** - Analysis engines
- `email_parser.py` - Email parsing and header extraction
- `ai_detector.py` - Linguistic analysis for AI detection
- `risk_engine.py` - Risk scoring calculations

**`phishdetect/intelligence/`** - Threat intelligence
- `threat_intel.py` - TI feed loading and matching

**`phishdetect/reporting/`** - Output generation
- `report_generator.py` - TXT/JSON report creation

**`phishdetect/cli/`** - User interface
- `interface.py` - Professional CLI interface

### Data Flow

```
Email Input
    ↓
Email Parser (extract headers, URLs, content)
    ↓
Analysis Engines (AI, URL, TI matching)
    ↓
Risk Engine (calculate composite score)
    ↓
Report Generator (format output)
    ↓
User Output (terminal + export)
```

---

## Example Analysis Output

```
────────────────────────────────────────────────────────
ANALYSIS RESULTS
────────────────────────────────────────────────────────

Email Information:
  From:     noreply@paypal-secure.com
  To:       victim@example.com
  Subject:  Verify Your Account Now

Risk Assessment:
  Overall Risk Score: 73/100
  Risk Level: HIGH

Score Breakdown:
  Threat Intelligence     ▓▓▓▓▓▓▓░░░ 70.0/100 (25% weight)
  URL Analysis            ▓▓▓▓▓▓░░░░ 60.0/100 (25% weight)
  AI-Generated Content    ▓▓▓▓░░░░░░ 40.0/100 (20% weight)
  Keywords                ▓▓▓▓▓▓░░░░ 60.0/100 (15% weight)
  Header Anomalies        ▓▓▓░░░░░░░ 30.0/100 (10% weight)
  Obfuscation             ▓▓░░░░░░░░ 20.0/100 (5% weight)

────────────────────────────────────────────────────────
RECOMMENDATION
────────────────────────────────────────────────────────

⚠️  HIGH RISK - ESCALATE TO SECURITY TEAM
  • Block sender domain
  • Alert recipient to suspicious content
  • Do not interact with email content
```

---

## Limitations & Caveats

### Current Limitations

⚠️ **Threat Intelligence**
- Relies on manually loaded JSON feeds
- No real-time threat updates
- No integration with commercial feeds

⚠️ **AI Detection**
- Based on linguistic heuristics only
- Not ML/neural network-based
- Experimental accuracy (not benchmarked)
- May produce false positives/negatives

⚠️ **Attachment Analysis**
- Detects mime types and double extensions
- Does NOT execute or sandbox files
- Cannot detect obfuscated malware

⚠️ **Email Parsing**
- Handles standard SMTP format
- May struggle with complex MIME structures
- Limited HTML/CSS parsing

⚠️ **Performance**
- Single-threaded analysis
- Batch processing not yet implemented
- Suitable for <100 emails/hour

### What It Won't Catch

- Zero-day phishing techniques
- Advanced obfuscation (unless in threat feed)
- Legitimate emails spoofed very carefully
- Attacks using social engineering only
- Advanced image-based phishing

---

## Testing

### Running the Tool

**Test with built-in samples:**

```
Option [2] → Paste sample email
```

**Expected Results:**

| Email Type | Expected Score | Time |
|---|---|---|
| Legitimate (GitHub) | 5-15/100 | ~80ms |
| Medium Risk | 40-55/100 | ~110ms |
| High Risk | 65-80/100 | ~120ms |
| Critical (with TI match) | 80-95/100 | ~130ms |

### Performance Metrics

Current system performance:
- Email parsing: 10-50ms
- Header analysis: 5-15ms
- AI detection: 40-100ms
- TI matching: 5-20ms
- Risk scoring: 15-30ms
- **Total per email: 100-200ms** (single-threaded)

---

## How Accuracy Is NOT Claimed

**This tool does NOT claim:**
- X% detection accuracy
- Y% false positive rate
- Z% true positive rate

**Why?**
- No standardized dataset tested
- No controlled benchmark
- Results depend heavily on threat feeds loaded
- Heuristics vary by email complexity

**If you need verified accuracy:**
- Use NIST TREC Spam collections
- Run controlled benchmarks
- Keep detailed logs
- Compare against known samples

---

## Project Structure

```
phishdetect/
├── phishdetect.py                 # Main entry point
├── setup.py                       # Setup script
├── requirements.txt               # Dependencies
├── README.md                      # Documentation
├── phishdetect/
│   ├── __init__.py
│   ├── cli/
│   │   ├── __init__.py
│   │   └── interface.py           # Professional CLI
│   ├── core/
│   │   ├── __init__.py
│   │   ├── email_parser.py        # Email parsing
│   │   ├── ai_detector.py         # AI detection
│   │   └── risk_engine.py         # Risk scoring
│   ├── intelligence/
│   │   ├── __init__.py
│   │   └── threat_intel.py        # TI loading
│   └── reporting/
│       ├── __init__.py
│       └── report_generator.py    # Report generation
├── data/
│   └── threat_feeds/              # Add JSON feeds here
├── logs/                          # Generated logs
└── reports/                       # Generated reports
```

---

## Roadmap (v2.1+)

**Near Term (v2.1)**
- [ ] Batch analysis (multi-email processing)
- [ ] Parallel analysis with threading
- [ ] CSV export format
- [ ] Settings persistence to config file
- [ ] Email scheduling/automation

**Medium Term (v2.2+)**
- [ ] Web dashboard (Flask/FastAPI)
- [ ] SQLite database for storing analyses
- [ ] Integration with real threat feeds
- [ ] YARA rule support for attachments
- [ ] Email client plugins

**Long Term (v3.0+)**
- [ ] REST API
- [ ] Machine learning models (if benchmarked)
- [ ] Integration with SOAR platforms
- [ ] Multi-language support

---

## Dependencies

```
termcolor>=1.1.0      # Colored terminal output
requests>=2.28.0      # HTTP requests (for future TI feeds)
```

Optional (for future features):
```
flask>=2.0.0          # Web framework
sqlite3               # Database
numpy>=1.20.0         # ML preprocessing
scikit-learn>=1.0.0   # ML models
```

---

## Contributing

This is a learning project. Contributions welcome!

Areas for improvement:
- Better AI detection algorithms
- More email format support
- Enhanced threat feed integration
- Performance optimization
- Documentation improvements

---

## Contact & Support

**Author:** Gurram Jagan Bhasker  
**Email:** jaganbhaskergurram@gmail.com  
**GitHub:** https://github.com/Jaganbhasker1122

**For Questions:**
- Open an issue on GitHub
- Email directly
- Check documentation in Option [6]

---

## License

This project is provided as-is for educational and research purposes.

---

## Disclaimers

### Security Disclaimer

⚠️ **This tool is experimental software.**

- Use at your own risk
- Do not rely solely on this for security decisions
- Always verify suspicious emails through other channels
- Consider phishing attempts from multiple angles
- Use in conjunction with established security controls

### Liability

- The authors assume no liability for missed threats
- This tool cannot detect all phishing attacks
- False negatives are possible and likely
- False positives will occur
- This tool should augment, not replace, professional security services

### Responsible Disclosure

If you find security vulnerabilities in this tool:
1. Do NOT post publicly
2. Email jaganbhasker1122@gmail.com with details
3. Allow time for patching
4. Follow responsible disclosure practices

---

## What This Tool Actually Is

✅ **A learning project** exploring email security  
✅ **A reference implementation** of phishing detection concepts  
✅ **Educational software** for understanding email forensics  
✅ **Research code** demonstrating multiple detection techniques  

❌ **NOT** a commercial product  
❌ **NOT** production-ready for critical systems  
❌ **NOT** a replacement for professional email security  
❌ **NOT** backed by benchmarked accuracy claims  

---

## Acknowledgments

Built with inspiration from:
- Security research literature
- OWASP email security guidelines
- SOC workflow best practices
- Open-source security projects

---

## Version History

**v2.0 (Current)**
- Professional CLI interface
- Multi-factor risk scoring
- Threat intelligence integration
- Report generation

**v1.0**
- Basic email parsing
- Simple heuristic detection

---

## Further Reading

Recommended resources for email security:

- [OWASP Phishing](https://owasp.org/www-community/attacks/phishing)
- [Email Authentication (SPF, DKIM, DMARC)](https://tools.ietf.org/html/dmarc)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [RFC 5322 - Internet Message Format](https://tools.ietf.org/html/rfc5322)

---

## Summary

PhishDetect is a **research-oriented security analysis tool** designed to educate and demonstrate phishing detection concepts. It provides useful heuristic-based analysis but should be used as one signal among many in a comprehensive security strategy.

**Use wisely. Question results. Validate independently.**

---

*Last Updated: January 20, 2026*  
*Status: Research/Educational Grade*  
*Maturity: Early/Experimental*
