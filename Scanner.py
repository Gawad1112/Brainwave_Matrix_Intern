import re
import requests
from datetime import datetime, timezone
import tldextract
import json

# =============================================================================
# CONFIGURATION
# =============================================================================
# Replace this with your actual Google Safe Browsing API key
API_KEY = 'AIzaSyB-f-47s6IL9avQfwupBWZd5lNLQKDrI9c'
SAFE_BROWSING_API_URL = 'https://safebrowsing.googleapis.com/v4/threatMatches:find'

# List of suspicious TLDs often used in phishing
SUSPICIOUS_TLDS = {'xyz', 'top', 'icu', 'club', 'ru', 'info', 'tk', 'ml', 'ga', 'cf', 'pw', 'cc', 'bz', 'review', 'stream'}

# List of trusted/legitimate domains that might be targeted for cloning
TRUSTED_DOMAINS = {'paypal', 'google', 'microsoft', 'apple', 'amazon', 'netflix', 'facebook', 'instagram', 'twitter', 'linkedin', 'bankofamerica', 'wellsfargo', 'chase', 'citibank'}

# =============================================================================
# CORE SCANNING FUNCTIONS
# =============================================================================

def check_google_safe_browsing(url):
    """Checks the URL against Google's Safe Browsing database. Returns a list of threats or None."""
    if not API_KEY or API_KEY == 'AIzaSyB-f-47s6IL9avQfwupBWZd5lNLQKDrI9c':
        return ["Google Safe Browsing check skipped. API key not configured."]

    payload = {
        "client": {
            "clientId": "phishnet-scanner",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    params = {'key': API_KEY}
    try:
        response = requests.post(SAFE_BROWSING_API_URL, params=params, json=payload, timeout=10)
        response.raise_for_status()
        data = response.json()

        if 'matches' in data:
            threats = [f"{match['threatType']} (Platform: {match.get('platformType', 'ANY')})" for match in data['matches']]
            return threats
        else:
            return None
    except requests.exceptions.RequestException as e:
        return [f"Error querying Safe Browsing API: {e}"]
    except json.JSONDecodeError:
        return ["Error decoding API response."]

def check_domain_age(domain):
    """Checks the creation date of the domain. Returns age in days and a threat level."""
    try:
        # Try to import whois safely
        try:
            import whois
        except ImportError:
            return None, "UNKNOWN (python-whois library not installed)"
        
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date:
            now = datetime.now(timezone.utc)
            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(tzinfo=timezone.utc)
            age_days = (now - creation_date).days

            if age_days < 30:
                return age_days, "DANGEROUS"
            elif age_days < 365:
                return age_days, "SUSPICIOUS"
            else:
                return age_days, "SAFE"
        else:
            return None, "UNKNOWN (No WHOIS data)"
    except Exception as e:
        return None, f"UNKNOWN (WHOIS lookup failed: {str(e)})"

def analyze_url_heuristics(url):
    """Performs heuristic analysis on the URL string. Returns a list of findings."""
    findings = []
    extracted = tldextract.extract(url)
    domain = f"{extracted.domain}.{extracted.suffix}"
    full_domain = extracted.fqdn

    # Check for IP address in URL
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    if re.search(ip_pattern, url):
        findings.append("Uses an IP address instead of a domain name.")

    # Check for '@' symbol (userinfo)
    if '@' in url:
        findings.append("Contains '@' symbol, used to obscure the real domain.")

    # Count hyphens in domain
    hyphen_count = full_domain.count('-')
    if hyphen_count >= 3:
        findings.append(f"An unusually high number ({hyphen_count}) of hyphens in the domain.")
    elif hyphen_count > 0:
        findings.append(f"Contains hyphens in the domain ({hyphen_count}), which can be suspicious.")

    # Check URL length
    if len(url) > 75:
        findings.append(f"URL is very long ({len(url)} characters), a common phishing tactic.")

    # Check for suspicious TLDs
    if extracted.suffix in SUSPICIOUS_TLDS:
        findings.append(f"Uses a suspicious Top-Level Domain (TLD): '.{extracted.suffix}'.")

    # Check for subdomain spoofing
    subdomain_list = extracted.subdomain.split('.') if extracted.subdomain else []
    for part in subdomain_list:
        if part in TRUSTED_DOMAINS:
            findings.append(f"Uses a trusted brand name ('{part}') in a subdomain to mimic a legitimate site.")

    # Check for domain imitation
    for trusted_domain in TRUSTED_DOMAINS:
        if trusted_domain in domain and domain != trusted_domain:
            findings.append(f"Domain '{domain}' may be a misspelling or imitation of trusted domain '{trusted_domain}'.")

    return findings

def scan_url(target_url):
    """Orchestrates the entire scan of a single URL."""
    print(f"\n\033[1;34m[ SCANNING ]\033[0m {target_url}")
    report = {"url": target_url, "heuristics": [], "threats": [], "domain_age": None, "age_threat": "UNKNOWN"}

    # Layer 1: Heuristic Analysis
    heuristic_findings = analyze_url_heuristics(target_url)
    report["heuristics"] = heuristic_findings

    # Layer 2: Domain Age Check
    extracted = tldextract.extract(target_url)
    domain_to_check = f"{extracted.domain}.{extracted.suffix}"
    age_days, age_threat = check_domain_age(domain_to_check)
    report["domain_age"] = age_days
    report["age_threat"] = age_threat

    # Layer 3: Google Safe Browsing
    safe_browsing_result = check_google_safe_browsing(target_url)
    if safe_browsing_result:
        report["threats"].extend(safe_browsing_result)

    # Generate the final report
    generate_report(report)

def generate_report(report):
    """Generates a color-coded terminal report based on the scan results."""
    print("-" * 60)
    print(f"URL: {report['url']}")

    # Print Heuristics
    if report['heuristics']:
        print("\n\033[1;33mHEURISTIC ANALYSIS FINDINGS:\033[0m")
        for finding in report['heuristics']:
            print(f"  \033[0;33m•\033[0m {finding}")
    else:
        print("\n\033[1;32m✓ No suspicious heuristics detected.\033[0m")

    # Print Domain Age
    print(f"\n\033[1;36mDOMAIN AGE:\033[0m")
    if report['domain_age']:
        threat_color = "1;31" if "DANGEROUS" in report['age_threat'] else "1;33" if "SUSPICIOUS" in report['age_threat'] else "1;32"
        print(f"  Domain is approximately {report['domain_age']} days old. [\033[{threat_color}m{report['age_threat']}\033[0m]")
    else:
        print(f"  {report['age_threat']}")

    # Print Safe Browsing Results
    print(f"\n\033[1;35mGOOGLE SAFE BROWSING:\033[0m")
    if report['threats'] and not any("THREAT" in t for t in report['threats'] if isinstance(t, str)):
        print("  \033[1;32m✓ No known threats detected.\033[0m")
    elif report['threats']:
        for threat in report['threats']:
            if "error" in threat.lower() or "skipped" in threat.lower():
                print(f"  \033[1;33m• {threat}\033[0m")
            else:
                print(f"  \033[1;31m• THREAT DETECTED: {threat}\033[0m")

    # Final Verdict
    final_verdict = "SAFE"
    color_code = "1;32" # Green
    if any("THREAT DETECTED" in t for t in report['threats'] if isinstance(t, str)):
        final_verdict = "DANGEROUS - KNOWN MALICIOUS"
        color_code = "1;31" # Red
    elif report['heuristics'] or "SUSPICIOUS" in report['age_threat'] or "DANGEROUS" in report['age_threat']:
        final_verdict = "SUSPICIOUS"
        color_code = "1;33" # Yellow

    print(f"\n\033[1mFINAL VERDICT: \033[{color_code}m{final_verdict}\033[0m")
    print("-" * 60)

# =============================================================================
# MAIN EXECUTION - SIMPLE INPUT
# =============================================================================

print("\n" + "="*50)
print("PHISHNET SCANNER")
print("="*50)

# Get the URL from the user
url = input("\nEnter the URL to scan: ").strip()

# Add https:// if no protocol is specified
if not url.startswith(('http://', 'https://')):
    url = 'https://' + url
    print(f"Assuming HTTPS: {url}")

# Scan the provided URL
scan_url(url)