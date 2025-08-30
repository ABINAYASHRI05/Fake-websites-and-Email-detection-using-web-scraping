import requests
import socket
import ssl
import whois
from datetime import datetime
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import re

# Refined Suspicious keywords list with weight adjustment
high_risk_keywords = [
    "password", "login", "verify", "security", "credit card", "bank", "suspend", "account locked"
]
low_risk_keywords = [
    "win", "winner", "free", "urgent", "limited", "click", "exclusive", "guarantee",
    "instant", "access now", "deal", "earn", "urgent action", "act now", "offer expires"
]

# Helper function to check if input is an email
def is_email(input_str):
    return bool(re.match(r"[^@]+@[^@]+\.[^@]+", input_str))

# Email checker
def email_checker(email):
    domain = email.split('@')[1]
    try:
        socket.getaddrinfo(domain, 0, socket.AF_INET, socket.SOCK_STREAM)
        return True
    except socket.gaierror:
        return False

# Feature 1: Domain age
def get_domain_age(domain):
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if not creation_date:
            return -1
        return (datetime.now() - creation_date).days
    except Exception:
        return -1

# Feature 2: SSL certificate validity
def ssl_certificate_info(domain):
    try:
        context = ssl.create_default_context()
        with context.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(3)
            s.connect((domain, 443))
            cert = s.getpeercert()
        expiry_date = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
        valid = datetime.now() < expiry_date
        return {
            "ssl_present": True,
            "valid_until": expiry_date.strftime('%Y-%m-%d'),
            "is_valid": valid
        }
    except Exception:
        return {
            "ssl_present": False,
            "valid_until": None,
            "is_valid": False
        }

# Feature 3: URL structure
def url_structure(url):
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    return {
        "url_length": len(url),
        "has_ip": hostname.replace('.', '').isdigit(),
        "num_subdomains": max(len(hostname.split('.')) - 2, 0)
    }

# Feature 4: Internal vs External link ratio
def link_ratio(url):
    try:
        html = requests.get(url, timeout=5).text
        soup = BeautifulSoup(html, 'html.parser')
        domain = urlparse(url).netloc

        internal = external = 0
        for a in soup.find_all('a', href=True):
            href = a['href']
            if domain in href or href.startswith('/'):
                internal += 1
            else:
                external += 1
        total = internal + external
        return round(external / total, 3) if total else 0.0
    except:
        return -1.0

# Feature 5: Suspicious keyword frequency with weight
def keyword_check(url):
    try:
        text = requests.get(url, timeout=5).text.lower()
        high_risk_count = sum(text.count(word) for word in high_risk_keywords)
        low_risk_count = sum(text.count(word) for word in low_risk_keywords)
        return high_risk_count * 2 + low_risk_count
    except:
        return 0

# Feature 6: JavaScript redirection
def js_redirection(url):
    try:
        html = requests.get(url, timeout=5).text
        return 1 if "location.href" in html or "window.location" in html else 0
    except:
        return 0

# IP Address Fetching
def get_ip_address(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None

# Combine all features
def extract_all_features(url):
    if not url.startswith("http"):
        url = "https://" + url
    parsed = urlparse(url)
    domain = parsed.netloc.replace("www.", "").split(":")[0]

    return {
        "domain": domain,
        "domain_age_days": get_domain_age(domain),
        **ssl_certificate_info(domain),
        **url_structure(url),
        "link_ratio": link_ratio(url),
        "suspicious_keyword_count": keyword_check(url),
        "js_redirection": js_redirection(url),
        "ip_address": get_ip_address(domain)
    }

# Classification
def classify_website(features):
    score = 0

    if features["ssl_present"] and features["is_valid"]:
        score += 3
    if features["domain_age_days"] > 180:
        score += 3
    if features["link_ratio"] < 0.7:
        score += 1

    if features["suspicious_keyword_count"] > 50:
        score -= 3
    elif features["suspicious_keyword_count"] > 30:
        score -= 2
    elif features["suspicious_keyword_count"] > 15:
        score -= 1

    if features["js_redirection"] > 0:
        score -= 0.5
    if features["link_ratio"] > 0.85:
        score -= 1
    if features["ip_address"]:
        score -= 0.5
    if features["domain_age_days"] == -1:
        score -= 2

    verdict = "Legit" if score >= 2 else "Fake"
    reasons = []

    if features["ssl_present"]:
        reasons.append("✅ Uses HTTPS")
    else:
        reasons.append("❌ No SSL")

    if features["domain_age_days"] > 180:
        reasons.append("✅ Old domain")
    elif features["domain_age_days"] == -1:
        reasons.append("❌ WHOIS data unavailable")
    else:
        reasons.append("⚠️ Recently registered domain")

    if features["suspicious_keyword_count"] > 50:
        reasons.append("❌ Too many suspicious keywords")
    elif features["suspicious_keyword_count"] > 30:
        reasons.append("⚠️ Some suspicious keywords detected")

    if features["js_redirection"]:
        reasons.append("⚠️ JavaScript redirection found")

    if features["link_ratio"] > 0.85:
        reasons.append("⚠️ High external link ratio")

    if features["ip_address"]:
        reasons.append("⚠️ Uses IP address directly")

    return verdict, reasons

# Main logic
if __name__ == "__main__":
    while True:
        test_input = input("\nEnter a website URL or email address (or type 'exit' to quit): ")
        if test_input.lower() == "exit":
            print("Exiting real-time scanner.")
            break

        if is_email(test_input):
            print("\n[+] Validating email...\n")
            is_valid = email_checker(test_input)
            verdict = "Legit" if is_valid else "Fake"
            print(f"Email: {test_input}")
            print(f"Verdict: {verdict}")
        else:
            print("\n[+] Extracting website features in real-time...\n")
            features = extract_all_features(test_input)
            verdict, reasons = classify_website(features)

            print("========== Real-Time Website Analysis ==========")
            print(f"Domain:                {features['domain']}")
            print(f"Domain Age (days):     {features['domain_age_days']}")
            print(f"SSL Present:           {features['ssl_present']}")
            print(f"SSL Valid Until:       {features['valid_until']}")
            print(f"SSL Currently Valid:   {features['is_valid']}")
            print(f"URL Length:            {features['url_length']}")
            print(f"Has IP Address:        {features['ip_address']}")
            print(f"Subdomain Count:       {features['num_subdomains']}")
            print(f"External Link Ratio:   {features['link_ratio']}")
            print(f"Suspicious Keywords:   {features['suspicious_keyword_count']}")
            print(f"JS Redirection Found:  {features['js_redirection']}")
            print("------------------------------------------------")
            print(f"Verdict:               {'✅ Legit' if verdict == 'Legit' else '❌ Fake'}")
            print("Reasons:")
            for reason in reasons:
                print(f"- {reason}")
            print("================================================")
