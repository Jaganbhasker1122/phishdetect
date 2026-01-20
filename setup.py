#!/usr/bin/env python3
"""
PhishDetect v2.0 - Setup Script
Installs dependencies and configures the tool
"""

import sys
import subprocess
import os
from pathlib import Path


def install_dependencies():
    """Install required Python packages"""
    print("[*] Installing dependencies...")
    
    packages = [
        "termcolor>=1.1.0",
        "requests>=2.28.0",
    ]
    
    for package in packages:
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])
        except subprocess.CalledProcessError:
            print(f"[!] Failed to install {package}")
            return False
    
    return True


def create_directories():
    """Create necessary directories"""
    print("[*] Creating project structure...")
    
    directories = [
        "data/threat_feeds",
        "data/sample_emails",
        "phishdetect/core",
        "phishdetect/detection",
        "phishdetect/intelligence",
        "phishdetect/reporting",
        "phishdetect/cli",
        "phishdetect/utils",
        "reports",
        "logs",
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        print(f"  ✓ {directory}")
    
    return True


def create_config_files():
    """Create configuration files"""
    print("[*] Creating configuration files...")
    
    # Create __init__ files
    init_files = [
        "phishdetect/__init__.py",
        "phishdetect/core/__init__.py",
        "phishdetect/detection/__init__.py",
        "phishdetect/intelligence/__init__.py",
        "phishdetect/reporting/__init__.py",
        "phishdetect/cli/__init__.py",
        "phishdetect/utils/__init__.py",
    ]
    
    for init_file in init_files:
        Path(init_file).touch(exist_ok=True)
    
    return True


def create_requirements_txt():
    """Create requirements.txt"""
    print("[*] Creating requirements.txt...")
    
    requirements = """
# PhishDetect v2.0 - Requirements

# Core dependencies
termcolor>=1.1.0
requests>=2.28.0

# Optional: ML support (for v3.0)
# scikit-learn>=1.0.0
# xgboost>=1.5.0
# numpy>=1.21.0

# Optional: Advanced features
# python-magic>=0.4.24
# pycurl>=7.44.0

# Development
pytest>=7.0.0
black>=22.0.0
flake8>=4.0.0
mypy>=0.950
"""
    
    with open("requirements.txt", "w") as f:
        f.write(requirements.strip())
    
    print("  ✓ requirements.txt created")
    return True


def create_main_script():
    """Create main phishdetect.py script"""
    print("[*] Creating main script...")
    
    script = """#!/usr/bin/env python3
\"\"\"
PhishDetect v2.0 - Main Entry Point
\"\"\"

import sys
from phishdetect.cli.interface import main

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\\n[!] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)
"""
    
    with open("phishdetect.py", "w") as f:
        f.write(script)
    
    # Make executable
    os.chmod("phishdetect.py", 0o755)
    print("  ✓ phishdetect.py created")
    return True


def create_readme():
    """Create README.md"""
    print("[*] Creating README...")
    
    readme = """# PhishDetect v2.0

Advanced Phishing & Fraud Detection Tool - Enterprise Grade

## Features

- ✅ **Email Parsing** - Support for .eml, .txt, and raw content
- ✅ **AI Detection** - Identify AI-generated emails offline
- ✅ **Advanced Scoring** - Weighted risk analysis (0-100)
- ✅ **Threat Intelligence** - Local offline TI feeds
- ✅ **Professional Reports** - TXT & JSON output formats
- ✅ **Header Analysis** - SPF/DKIM/DMARC checks
- ✅ **Obfuscation Detection** - Base64, Hex, Unicode, Punycode
- ✅ **Production Ready** - Secure, logged, tested

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Create sample threat feeds
python phishdetect.py

# 3. Analyze an email
# Choose option [2] to paste email content
```

## Risk Scoring

- **0-20**: LOW RISK (✓ Safe)
- **21-50**: MEDIUM RISK (⚠ Review)
- **51-75**: HIGH RISK (⚠⚠ Block)
- **76-100**: CRITICAL RISK (🚨 Quarantine)

## Scoring Components

| Component | Weight | Max Score |
|-----------|--------|-----------|
| Threat Intelligence | 25% | 100 |
| URL Analysis | 25% | 100 |
| AI-Generated Content | 20% | 100 |
| Keywords (Urgency/Fear) | 15% | 100 |
| Header Anomalies | 10% | 100 |
| Obfuscation Techniques | 5% | 100 |

## Project Structure

```
phishdetect-v2.0/
├── phishdetect/
│   ├── core/              # Core analysis engines
│   ├── detection/         # Detection modules
│   ├── intelligence/      # TI engine
│   ├── reporting/         # Report generation
│   └── cli/               # CLI interface
├── data/
│   ├── threat_feeds/      # TI feeds (JSON)
│   └── sample_emails/     # Test emails
├── reports/               # Generated reports
├── logs/                  # Application logs
└── tests/                 # Unit tests
```

## Configuration

### Adding Threat Feeds

Place JSON files in `data/threat_feeds/`:

```json
{
  "malicious_domains": [
    {
      "domain": "phishing.com",
      "threat_type": "phishing",
      "confidence": 95,
      "last_seen": "2025-01-20",
      "source": "industry-feed",
      "category": "credential-harvesting",
      "notes": "Known phishing domain"
    }
  ]
}
```

## API Usage

```python
from phishdetect.core.email_parser import EmailParser
from phishdetect.core.ai_detector import AILanguageDetector
from phishdetect.core.risk_engine import RiskEngine
from phishdetect.intelligence.threat_intel import ThreatIntelligenceEngine

# Parse email
parser = EmailParser()
metadata = parser.parse_eml("email.eml")

# Detect AI
ai_detector = AILanguageDetector()
ai_result = ai_detector.detect(metadata.body_plain)

# Calculate risk
risk_engine = RiskEngine()
risk = risk_engine.calculate_risk(
    urls=metadata.urls,
    ai_score=ai_result.ai_likelihood_score
)

print(f"Risk Score: {risk.final_risk_score}/100 [{risk.risk_band}]")
```

## v3.0 Roadmap

- [ ] Machine Learning models (XGBoost)
- [ ] Browser sandbox integration
- [ ] SIEM integration (Splunk, ELK)
- [ ] Email client plugins (Outlook, Gmail)
- [ ] REST API server
- [ ] HTML/PDF reports
- [ ] Performance optimization
- [ ] Database backend (PostgreSQL)

## Security Considerations

- ✓ No internet/API calls (fully offline)
- ✓ Input validation on all user inputs
- ✓ Secure file handling
- ✓ No stored credentials
- ✓ Comprehensive logging

## Testing

```bash
# Run unit tests
pytest tests/

# Check code quality
flake8 phishdetect/
black --check phishdetect/
mypy phishdetect/
```

## Development

```bash
# Install dev dependencies
pip install -r requirements-dev.txt

# Format code
black phishdetect/

# Run linter
flake8 phishdetect/

# Type check
mypy phishdetect/
```

## Troubleshooting

**Issue**: Threat feeds not loading
- Solution: Ensure JSON files are in `data/threat_feeds/`

**Issue**: Email parsing fails
- Solution: Check file format (.eml or raw email text)

**Issue**: Import errors
- Solution: Run `pip install -r requirements.txt`

## License

MIT License - See LICENSE file

## Contact & Support

- 📧 Email: security@example.com
- 🐛 Issues: https://github.com/phishdetect/phishdetect-v2/issues
- 💡 Discussions: https://github.com/phishdetect/phishdetect-v2/discussions

---

**Developed by**: Cybersecurity Team  
**Version**: 2.0  
**Status**: Production Ready  
**Last Updated**: January 2025
"""
    
    with open("README.md", "w") as f:
        f.write(readme)
    
    print("  ✓ README.md created")
    return True


def main():
    """Run setup"""
    print("""
╔════════════════════════════════════════════════════════════════════╗
║         PhishDetect v2.0 - Setup & Installation Script            ║
╚════════════════════════════════════════════════════════════════════╝
    """)
    
    steps = [
        ("Creating directories", create_directories),
        ("Creating configuration files", create_config_files),
        ("Creating requirements.txt", create_requirements_txt),
        ("Creating main script", create_main_script),
        ("Creating README", create_readme),
    ]
    
    for step_name, step_func in steps:
        print(f"\n[*] {step_name}...")
        try:
            if step_func():
                print(f"[✓] {step_name} completed")
            else:
                print(f"[!] {step_name} failed")
                return False
        except Exception as e:
            print(f"[!] Error: {e}")
            return False
    
    print("""
╔════════════════════════════════════════════════════════════════════╗
║               ✓ Setup Completed Successfully!                     ║
╚════════════════════════════════════════════════════════════════════╝

Next steps:
  1. Install dependencies: pip install -r requirements.txt
  2. Run the tool: python phishdetect.py
  3. Add threat feeds to: data/threat_feeds/
  4. Test with sample emails: data/sample_emails/

Happy scanning! 🔒
    """)
    
    return True


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)