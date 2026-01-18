# PhishDetect

A lightweight command-line tool for identifying potential phishing attempts through rule-based analysis of email and message content.

[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Language](https://img.shields.io/badge/python-3.6%2B-blue)](https://www.python.org/downloads/)
[![Status](https://img.shields.io/badge/status-stable-brightgreen)]()

---

## Table of Contents

1. [Problem Statement](#problem-statement)
2. [What is PhishDetect](#what-is-phishdetect)
3. [Detection Logic](#detection-logic)
4. [Features](#features)
5. [Installation](#installation)
6. [Usage](#usage)
7. [Example Scenario](#example-scenario)
8. [Architecture](#architecture)
9. [Limitations](#limitations)
10. [Future Scope](#future-scope)
11. [Contributing](#contributing)
12. [License](#license)
13. [Author](#author)

---

## Problem Statement

Phishing remains one of the most common and effective attack vectors against individuals and organizations. According to security research, phishing emails are responsible for the majority of successful data breaches and credential thefts.

**Why phishing is dangerous:**
- Users can be deceived by authentic-looking emails from fake accounts
- Phishing attacks are difficult to detect visually without security awareness
- Attackers use psychological manipulation combined with technical deception
- A single compromised credential can lead to widespread unauthorized access
- Traditional spam filters miss many sophisticated phishing attempts

**The challenge:** Users need a simple way to analyze potentially suspicious emails before clicking links or providing information. PhishDetect provides a lightweight, rule-based tool for this purpose.

---

## What is PhishDetect

PhishDetect is a command-line tool that analyzes email and message content for indicators of phishing attacks. It uses rule-based detection to identify:
- Suspicious keywords commonly found in phishing messages
- Known malicious URLs
- Fraudulent phone numbers
- Risk patterns based on content analysis

**How it works:** Users paste email content into the tool, which scans for predefined phishing indicators and assigns a risk level (Low, Medium, High) based on findings.

**Important:** PhishDetect uses simple pattern matching and keyword detection. It is not a machine learning system and cannot detect sophisticated, zero-day, or obfuscated phishing attempts. It should be used as one component of a broader security awareness strategy, not as a complete phishing defense.

---

## Detection Logic

PhishDetect uses **rule-based detection** to identify phishing indicators:

### Phishing URL Detection
- Compares URLs in the message against a predefined list of known malicious domains
- Flags suspicious URL patterns and shorteners commonly used to hide destinations
- Does not validate URL authenticity beyond list matching

### Suspicious Keyword Detection
- Scans content for common phishing language patterns
- Examples: "verify account," "confirm identity," "urgent action required," "click here"
- Identifies urgency language, authority impersonation, and credential requests
- Does not understand context; keyword presence alone triggers detection

### Fraudulent Phone Number Detection
- Identifies and flags phone numbers in messages
- Checks against patterns associated with fraud and phishing
- Does not validate phone number legitimacy independently

### Risk Scoring
- Combines detection signals into an overall risk score
- Low Risk: Few or no indicators detected
- Medium Risk: Several suspicious elements present
- High Risk: Multiple or severe phishing indicators detected

**Limitations of Rule-Based Approach:**
- Cannot detect new or unknown phishing techniques
- May produce false positives for legitimate messages containing similar language
- Does not analyze sender authentication (SPF, DKIM, DMARC)
- Cannot detect image-based phishing or HTML-only attacks
- Does not verify URL destination before flagging

---

## Features

### Core Detection Capabilities
- Identifies phishing URLs from predefined malicious domain list
- Detects suspicious keywords associated with phishing campaigns
- Flags fraudulent phone numbers in messages
- Assigns risk level based on detected indicators

### User Interface
- Simple command-line interface with colored output
- Clear risk assessment report
- Straightforward input mechanism (paste and submit)
- Minimal learning curve for end users

### Quick Analysis
- Fast local processing with no external API calls
- Instant results without network latency
- Lightweight tool suitable for any environment

---

## Installation

### Prerequisites
- Python 3.6 or later
- pip (Python package manager)
- Terminal or command-line access

### Setup Instructions

1. **Clone the repository:**
```bash
git clone https://github.com/Jaganbhasker1122/phishdetect.git
cd phishdetect
```

2. **Install dependencies:**
```bash
pip install termcolor
```

3. **Verify installation:**
```bash
python3 phishdetect.py
```

---

## Usage

### Running the Tool

```bash
python3 phishdetect.py
```

### Input Method

1. The tool opens an interactive terminal interface
2. Paste the email or message content you want to analyze
3. Press `Ctrl+D` (on Linux/Mac) or `Ctrl+Z` followed by `Enter` (on Windows) to submit
4. The tool analyzes the content and displays a risk report

### Output Format

The tool displays:
- **Detected Indicators:** List of suspicious elements found (URLs, keywords, phone numbers)
- **Risk Level:** Overall assessment (Low, Medium, High)
- **Recommendations:** Suggested actions based on risk level

### Analyzing Multiple Messages

To analyze another email:
```bash
python3 phishdetect.py
```

Re-run the command for each message you want to analyze.

---

## Example Scenario

### Suspicious Email Input

```
From: noreply@paypa1-verify.com
Subject: Urgent: Verify Your PayPal Account

Dear Customer,

We detected suspicious activity on your PayPal account. You must verify your identity immediately or your account will be limited.

Click here to verify: http://paypa1-verify.com/confirm?user=12345

If you don't verify within 24 hours, your account access will be permanently suspended.

For urgent assistance, call 1-800-555-0123

Thank you,
PayPal Security Team
```

### PhishDetect Analysis

```
=====================================
PhishDetect - Risk Assessment Report
=====================================

DETECTED INDICATORS:
[+] Suspicious Keyword: "verify"
[+] Suspicious Keyword: "immediately"
[+] Suspicious Keyword: "suspended"
[+] Suspicious Keyword: "urgent"
[+] Phishing URL: http://paypa1-verify.com (domain similarity to PayPal)
[+] Phone Number Detected: 1-800-555-0123

RISK ASSESSMENT:
Risk Level: HIGH

RECOMMENDATIONS:
- Do NOT click any links in this message
- Do NOT enter credentials or personal information
- Contact PayPal directly using official website or phone number
- Report this message as phishing to your email provider
- Delete the message

=====================================
```

### What This Means

- **Multiple keywords** associated with phishing language detected
- **Malicious URL** flagged (domain spoofs legitimate service)
- **Urgency language** present to pressure user action
- **Phone number** included as alternative social engineering vector
- **Overall assessment:** High-risk phishing attempt

---

## Architecture

### Project Structure

```
phishdetect/
├── phishdetect.py          # Main CLI application
├── requirements.txt        # Python dependencies
├── data/
│   ├── phishing_urls.txt   # Known malicious URLs
│   ├── keywords.txt        # Phishing keywords list
│   └── phone_patterns.txt  # Fraudulent phone patterns
└── README.md              # Documentation
```

### Component Overview

**Input Handler:** Accepts email/message content from user

**URL Analyzer:** Checks URLs against known malicious domain list

**Keyword Scanner:** Searches for phishing-associated language patterns

**Phone Detector:** Identifies and flags phone numbers in content

**Risk Calculator:** Combines detection signals into risk score

**Output Formatter:** Displays analysis results with color-coded warnings

### Design Philosophy

**Simplicity:** Minimal dependencies and straightforward logic for maintainability

**Transparency:** Clear detection rules and reasoning for each flag

**Offline Operation:** No external API calls or network dependencies

**Educational Focus:** Tool designed to teach phishing awareness, not provide complete protection

---

## Limitations

PhishDetect has important limitations that users should understand:

### Detection Scope
- **Rule-based only:** Uses pattern matching and keyword detection, not machine learning
- **Known threats only:** Can only detect phishing patterns in predefined rule lists
- **No sender validation:** Does not check SPF, DKIM, or DMARC authentication records
- **Language-specific:** Detection rules tuned for English; limited support for other languages

### False Positives
- Legitimate emails with urgent language (password expiry, security alerts) may be flagged
- Innocent messages containing similar keywords may trigger warnings
- Overbroad keyword matching can result in false alarms

### False Negatives
- Sophisticated phishing attempts with obfuscated content may not be detected
- Graphical phishing (embedded images as links) cannot be analyzed
- New phishing techniques not yet in rule lists will be missed
- Context-aware attacks designed to avoid detection may succeed

### Technical Constraints
- URL validation is exact matching; URL variations may bypass detection
- Phone number detection is pattern-based; legitimate business numbers may be flagged
- Single-pass analysis; cannot track cross-message patterns or campaigns
- No access to actual email metadata (sender verification, routing information)

### Not a Complete Solution
- Should not be the only anti-phishing defense
- Does not replace email filtering or security gateways
- Cannot prevent all phishing attacks
- Designed for user awareness, not as a primary security control

---

## Future Scope

### Short-Term Improvements
- Expand phishing keyword and URL databases
- Add support for analyzing HTML email content
- Improve phone number pattern detection
- Add logging for analysis history

### Medium-Term Enhancements
- Support for multiple languages
- Integration with email clients for inline analysis
- User feedback mechanism to update detection rules
- Analysis of sender header information and spoofing patterns

### Long-Term Additions
- Configuration file for custom rule customization
- Batch analysis mode for processing multiple emails
- Report generation in structured formats (JSON, CSV)
- Integration with threat intelligence feeds for URL validation

### Potential Directions
- Command-line argument support for non-interactive mode
- Detection rule versioning and updates
- Community-contributed rule sets
- Performance optimizations for large messages

---

## Contributing

Contributions are welcome. Please follow these guidelines:

### Areas for Contribution
- New phishing keywords or URL patterns
- Improved detection logic and accuracy
- Bug reports and fixes
- Documentation and examples
- Translation to additional languages
- Testing across different environments

### How to Contribute
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/improvement`)
3. Commit your changes with clear messages
4. Push to the branch and open a pull request
5. Include description of the improvement and test results

### Guidelines
- Maintain the rule-based detection approach (no ML models)
- Keep changes focused and well-tested
- Document any new detection rules
- Ensure new rules don't significantly increase false positives
- Test changes before submitting

---

## License

PhishDetect is released under the MIT License. See the LICENSE file for details.

---

## Author

**Gurram Jagan Bhasker**  
B.Tech Cyber Security (3rd Year) | India

Cybersecurity enthusiast with focus on building practical security tools and awareness resources. Interested in application security, threat analysis, and phishing defense.

### Contact and Profiles

- GitHub: [github.com/Jaganbhasker1122](https://github.com/Jaganbhasker1122)
- LinkedIn: [linkedin.com/in/gurram-jagan-bhasker-a0906b29a](https://www.linkedin.com/in/gurram-jagan-bhasker-a0906b29a/)
- Email: jaganbhaskergurram@gmail.com

---

*PhishDetect: Rule-based phishing awareness for end users.*
