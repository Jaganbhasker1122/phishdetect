#!/usr/bin/env python3
"""
PhishDetect v2.0 - Main Entry Point
"""

import sys
from phishdetect.cli.interface import main

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)