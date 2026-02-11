import requests
from urllib.parse import urlparse

# Mock blocklist for demonstration
MALICIOUS_DOMAINS = {
    'malicious-test.com',
    'evtil-site.org',
    'phishing-example.net',
    'bad-actor.io'
}

SUSPICIOUS_KEYWORDS = [
    'login', 'verify', 'update', 'banking', 'secure', 'account', 'confirm'
]

def expand_url(url):
    """
    Expands a shortened URL to its final destination.
    """
    if not url.startswith('http'):
        url = 'http://' + url
        
    try:
        response = requests.head(url, allow_redirects=True, timeout=5)
        return response.url
    except requests.RequestException:
        return url

def get_snapshot_url(url):
    """
    Returns a URL that generates a snapshot of the target website.
    Using thum.io for this purpose as it is a public service.
    """
    # Simply prepend the thum.io prefix
    return f"https://image.thum.io/get/width/800/crop/800/{url}"

def check_malicious(url):
    """
    Checks if a URL is potentially malicious using heuristics and a mock blocklist.
    Returns: (is_malicious: bool, reason: str, confidence: str)
    """
    final_url = expand_url(url)
    parsed = urlparse(final_url)
    domain = parsed.netloc.lower()
    
    # Check blocklist
    if domain in MALICIOUS_DOMAINS:
        return True, "Domain found in blocklist", "High"
        
    # Check for suspicious keywords in domain (heuristic)
    # This is a very simple heuristic for demonstration
    if any(keyword in domain for keyword in SUSPICIOUS_KEYWORDS) and '-' in domain:
         return True, "Suspicious keywords found in hyphenated domain", "Medium"

    # Deep mock check for demonstration purposes
    if 'malware' in final_url or 'virus' in final_url:
        return True, "URL path contains suspicious terms", "Medium"

    return False, "No threats detected", "Safe"
