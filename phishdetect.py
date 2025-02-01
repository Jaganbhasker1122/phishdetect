import re
import sys

from termcolor import colored

# Predefined lists for suspicious patterns
SUSPICIOUS_DOMAINS = [
    "fake-verify-account.com",
    "support-login.com",
    "secure-update.com",
    "account-verify.net",
    "login-security.org",
    "paypal-secure.com",
    "appleid-support.com",
    "microsoft-update.com",
    "google-verify.com",
    "amazon-security.com"
]

SUSPICIOUS_KEYWORDS = [
    "urgent", "verify your account", "suspension", "click here", "update your information",
    "confidential", "password reset", "security breach", "immediate action required",
    "your account has been compromised", "unauthorized access detected", "final notice"
]

SUSPICIOUS_PHONE_NUMBERS = [
    "+1-800-FAKE-NUMBER", "+1-888-SCAM-CALL", "+44-7900-FAKE-NUM", "1-800-555-0199"
]


# ASCII Art for PhishDetect
def print_ascii_art():
    ascii_art = """
 _____   _      _       _      _____         _                _   
|  __ \\ | |    (_)     | |    |  __ \\       | |              | |  
| |__) || |__   _  ___ | |__  | |  | |  ___ | |_   ___   ___ | |_ 
|  ___/ | '_ \\ | |/ __|| '_ \\ | |  | | / _ \\| __| / _ \\ / __|| __|
| |     | | | || |\\__ \\| | | || |__| ||  __/| |_ |  __/| (__ | |_ 
|_|     |_| |_||_||___/|_| |_||_____/  \\___| \\__| \\___| \\___| \\__|

    """
    print(colored(ascii_art, "cyan"))
    print(colored("PhishDetect - Your Fraud Detection Tool", "green"))
    print(colored(
        "This tool analyzes emails and messages for phishing attempts, malicious links, and suspicious content.",
        "white"))
    print(colored("Developed by Jagan Bhasker © 2025. All rights reserved.", "yellow"))


# Function to display help message
def display_help():
    help_message = """
Usage: phishdetect [options]
Options:
  -h, --h       Show this help message and exit.
  -v, --version Show the version of PhishDetect.
How to Run:
  1. Run the program without arguments: python phishdetect.py
  2. Follow the on-screen menu to analyze emails or messages.
  3. Use 'phishdetect -h' or 'phishdetect --h' for help.
Examples:
  python phishdetect.py          # Start the interactive tool
  python phishdetect.py -h       # Display this help message
  python phishdetect.py -v       # Display the version information
"""
    print(colored(help_message, "cyan"))


# Function to extract URLs from text
def extract_urls(text):
    return re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text)


# Function to check URLs against suspicious domains
def check_urls(urls):
    suspicious_urls = []
    for url in urls:
        for domain in SUSPICIOUS_DOMAINS:
            if domain in url:
                suspicious_urls.append(url)
                break
    return suspicious_urls


# Function to check for suspicious keywords in text
def check_keywords(text):
    suspicious_keywords_found = []
    for keyword in SUSPICIOUS_KEYWORDS:
        if re.search(rf"\b{re.escape(keyword)}\b", text, re.IGNORECASE):
            suspicious_keywords_found.append(keyword)
    return suspicious_keywords_found


# Function to check for suspicious phone numbers
def check_phone_numbers(text):
    suspicious_numbers = []
    for number in SUSPICIOUS_PHONE_NUMBERS:
        if number in text:
            suspicious_numbers.append(number)
    return suspicious_numbers


# Function to calculate risk level
def calculate_risk_level(suspicious_urls, suspicious_keywords, suspicious_numbers):
    total_risks = len(suspicious_urls) + len(suspicious_keywords) + len(suspicious_numbers)
    if total_risks >= 5:
        return "High"
    elif 2 <= total_risks < 5:
        return "Medium"
    else:
        return "Low"


# Function to read multi-line input

def read_multiline_input(prompt):
    print(colored(prompt, "cyan"))
    print(colored("Paste your content below. Press Ctrl+D (Linux/macOS) or Ctrl+Z (Windows) and Enter to submit:", "yellow"))

    lines = []
    try:
        while True:
            line = sys.stdin.readline()
            if not line:  # EOF detected (Ctrl+D or Ctrl+Z)
                break
            lines.append(line.rstrip())  # Avoid adding extra newlines
    except KeyboardInterrupt:
        print(colored("\nAnalysis complete.", "cyan"))
        print(colored("If you want to check another email or message, please re-run the program.", "yellow"))
        sys.exit(0)  # Exit the program

    return "\n".join(lines)



# Main function
def main():
    # Check for command-line arguments
    if len(sys.argv) > 1:
        if sys.argv[1] in ["-h", "--h"]:
            display_help()
            sys.exit(0)
        elif sys.argv[1] in ["-v", "--version"]:
            print(colored("PhishDetect Version 1.0", "cyan"))
            sys.exit(0)
        else:
            print(colored("[!] Invalid argument. Use 'phishdetect -h' for help.", "red"))
            sys.exit(1)

    print_ascii_art()

    # Menu options
    print(colored("\n[1] Analyze Email", "blue"))
    print(colored("[2] Analyze Message", "blue"))
    print(colored("[3] Exit", "blue"))

    choice = input(colored("\n[?] Choose an option (1/2/3): ", "yellow")).strip()
    if choice not in ["1", "2", "3"]:
        print(colored("[!] Invalid choice. Please try again.", "red"))
        main()  # Recursively call main() to restart the menu
        return

    if choice == "3":
        print(colored("\nExiting PhishDetect. Stay safe!", "cyan"))
        return

    # Input: Email or Message content
    content_type = "email" if choice == "1" else "message"
    content = read_multiline_input(f"[+] Paste the {content_type} content below:")

    # Analyze URLs
    urls = extract_urls(content)
    suspicious_urls = check_urls(urls)
    if suspicious_urls:
        print(colored("\n[!] Potentially malicious URLs found:", "red"))
        for url in suspicious_urls:
            print(colored(f"    - {url}", "red"))
    else:
        print(colored("\n[+] No suspicious URLs detected.", "green"))

    # Analyze keywords
    suspicious_keywords = check_keywords(content)
    if suspicious_keywords:
        print(colored("\n[!] Suspicious keywords found:", "yellow"))
        for keyword in suspicious_keywords:
            print(colored(f"    - {keyword}", "yellow"))
    else:
        print(colored("\n[+] No suspicious keywords detected.", "green"))

    # Analyze phone numbers
    suspicious_numbers = check_phone_numbers(content)
    if suspicious_numbers:
        print(colored("\n[!] Suspicious phone numbers found:", "red"))
        for number in suspicious_numbers:
            print(colored(f"    - {number}", "red"))
    else:
        print(colored("\n[+] No suspicious phone numbers detected.", "green"))

    # Calculate risk level
    risk_level = calculate_risk_level(suspicious_urls, suspicious_keywords, suspicious_numbers)
    if risk_level == "High":
        print(colored("\n[!!!] WARNING: HIGH RISK DETECTED!", "red"))
        print(colored("This content is highly suspicious. Do NOT interact with any links, numbers, or instructions.",
                      "red"))
    elif risk_level == "Medium":
        print(colored("\n[!] WARNING: MEDIUM RISK DETECTED!", "yellow"))
        print(colored("This content may be suspicious. Proceed with caution and verify the source.", "yellow"))
    else:
        print(colored("\n[+] LOW RISK DETECTED.", "green"))
        print(colored("This content appears to be safe, but always stay vigilant.", "green"))

    print(colored("\nAnalysis complete.", "cyan"))
    print(colored("If you want to check another email or message, please re-run the program.", "yellow"))
    sys.exit(0)  # Exit the program


if __name__ == "__main__":
    main()