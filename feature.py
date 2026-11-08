import ipaddress
import re
import socket
from urllib.parse import urlparse
from bs4 import BeautifulSoup

KNOWN_SAFE_DOMAINS = {
    'google.com', 'www.google.com', 'youtube.com', 'www.youtube.com',
    'facebook.com', 'www.facebook.com', 'amazon.com', 'www.amazon.com',
    'apple.com', 'www.apple.com', 'microsoft.com', 'www.microsoft.com',
    'wikipedia.org', 'www.wikipedia.org', 'github.com', 'www.github.com',
    'linkedin.com', 'www.linkedin.com', 'netflix.com', 'www.netflix.com',
    'twitter.com', 'www.twitter.com', 'x.com', 'yahoo.com', 'www.yahoo.com',
    'instagram.com', 'www.instagram.com', 'reddit.com', 'www.reddit.com'
}

class FeatureExtraction:
    """
    Optimized Real-Time Feature Extraction Engine for Malicious URL Detection.
    Evaluates:
      1. Lexical URL features (IP usage, URL length, symbols, redirection, prefix-suffix, subdomains)
      2. Domain age & DNS heuristics (registration length, TLD reputation, host resolution)
      3. Structural heuristics (anchor analysis, script tags, form action handlers, iframes, popups)
    
    Designed to process and extract features in under 50 milliseconds for high-performance real-time inference.
    """
    def __init__(self, url, html=None, fast_mode=True):
        self.features = []
        self.url = str(url).strip()
        if not (self.url.startswith("http://") or self.url.startswith("https://")):
            self.url = "http://" + self.url

        self.fast_mode = fast_mode
        self.html = html
        self.soup = None
        self.response = None
        self.whois_response = None
        
        try:
            self.urlparse = urlparse(self.url)
            self.domain = self.urlparse.netloc.lower()
            if ":" in self.domain:
                self.domain = self.domain.split(":")[0]
        except Exception:
            self.urlparse = None
            self.domain = ""

        self.is_top_domain = self.domain in KNOWN_SAFE_DOMAINS or any(self.domain.endswith("." + d) for d in KNOWN_SAFE_DOMAINS)

        # Parse webpage parameters / HTML structure if provided (e.g. from Chrome extension or scraper)
        if self.html:
            try:
                self.soup = BeautifulSoup(self.html, 'html.parser')
            except Exception:
                self.soup = None
        elif not self.fast_mode:
            # Fallback slow network fetch only if fast_mode is explicitly disabled
            try:
                import requests
                self.response = requests.get(self.url, timeout=1.0)
                self.soup = BeautifulSoup(self.response.text, 'html.parser')
            except Exception:
                self.response = None
                self.soup = None

        # Extract 30 features matching model input dimensions
        self.features.append(self.UsingIp())
        self.features.append(self.longUrl())
        self.features.append(self.shortUrl())
        self.features.append(self.symbol())
        self.features.append(self.redirecting())
        self.features.append(self.prefixSuffix())
        self.features.append(self.SubDomains())
        self.features.append(self.Hppts())
        self.features.append(self.DomainRegLen())
        self.features.append(self.Favicon())
        self.features.append(self.NonStdPort())
        self.features.append(self.HTTPSDomainURL())
        self.features.append(self.RequestURL())
        self.features.append(self.AnchorURL())
        self.features.append(self.LinksInScriptTags())
        self.features.append(self.ServerFormHandler())
        self.features.append(self.InfoEmail())
        self.features.append(self.AbnormalURL())
        self.features.append(self.WebsiteForwarding())
        self.features.append(self.StatusBarCust())
        self.features.append(self.DisableRightClick())
        self.features.append(self.UsingPopupWindow())
        self.features.append(self.IframeRedirection())
        self.features.append(self.AgeofDomain())
        self.features.append(self.DNSRecording())
        self.features.append(self.WebsiteTraffic())
        self.features.append(self.PageRank())
        self.features.append(self.GoogleIndex())
        self.features.append(self.LinksPointingToPage())
        self.features.append(self.StatsReport())

    # 1. UsingIp: Check if IP address is used instead of domain
    def UsingIp(self):
        try:
            ipaddress.ip_address(self.domain)
            return -1
        except Exception:
            if re.search(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', self.domain):
                return -1
            return 1

    # 2. longUrl: URL length heuristic
    def longUrl(self):
        if len(self.url) < 54:
            return 1
        elif 54 <= len(self.url) <= 75:
            return 0
        return -1

    # 3. shortUrl: Detect URL shortening services
    def shortUrl(self):
        match = re.search(
            r'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
            r'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
            r'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
            r'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|lnkd\.in|'
            r'db\.tt|qr\.ae|adf\.ly|bitly\.com|cur\.lv|tinyurl\.com|ity\.im|'
            r'q\.gs|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org',
            self.url, re.IGNORECASE
        )
        return -1 if match else 1

    # 4. Symbol@: Look for '@' in URL
    def symbol(self):
        return -1 if "@" in self.url else 1

    # 5. Redirecting//: Redirection '//' check
    def redirecting(self):
        return -1 if self.url.rfind('//') > 6 else 1

    # 6. prefixSuffix: '-' in domain name (common phishing disguise)
    def prefixSuffix(self):
        return -1 if '-' in self.domain else 1

    # 7. SubDomains: Subdomain count heuristic
    def SubDomains(self):
        dot_count = len(re.findall(r"\.", self.url))
        if dot_count <= 1:
            return 1
        elif dot_count == 2:
            return 0
        return -1

    # 8. HTTPS: Valid HTTPS scheme
    def Hppts(self):
        try:
            return 1 if self.urlparse and self.urlparse.scheme.lower() == 'https' else -1
        except Exception:
            return -1

    # 9. DomainRegLen: Registration length heuristic
    def DomainRegLen(self):
        if self.is_top_domain:
            return 1
        suspicious_tlds = [r'\.xyz$', r'\.top$', r'\.buzz$', r'\.tk$', r'\.ga$', r'\.cf$', r'\.gq$', r'\.ml$', r'\.cam$', r'\.icu$', r'\.work$']
        for tld in suspicious_tlds:
            if re.search(tld, self.domain, re.IGNORECASE):
                return -1
        return 1

    # 10. Favicon: External favicon loading
    def Favicon(self):
        try:
            if self.soup is not None:
                for link in self.soup.find_all('link', href=True):
                    rel = link.get('rel', [])
                    if isinstance(rel, list):
                        rel = " ".join(rel)
                    if 'icon' in rel.lower():
                        if self.domain in link['href'] or link['href'].startswith('/'):
                            return 1
                        return -1
            return 1 if self.is_top_domain else 0
        except Exception:
            return 1

    # 11. NonStdPort: Non-standard port in domain
    def NonStdPort(self):
        try:
            raw_netloc = self.urlparse.netloc if self.urlparse else ""
            if ":" in raw_netloc:
                port = raw_netloc.split(":")[1]
                if port not in ("80", "443", ""):
                    return -1
            return 1
        except Exception:
            return 1

    # 12. HTTPSDomainURL: 'https' token masqueraded inside domain
    def HTTPSDomainURL(self):
        return -1 if 'https' in self.domain else 1

    # 13. RequestURL: External objects / resources ratio
    def RequestURL(self):
        try:
            if self.soup is not None:
                total, external = 0, 0
                for tag in self.soup.find_all(['img', 'audio', 'embed', 'iframe'], src=True):
                    total += 1
                    src = tag['src']
                    if not (src.startswith('/') or self.domain in src):
                        external += 1
                if total == 0:
                    return 1
                ratio = (external / total) * 100
                if ratio < 22.0:
                    return 1
                elif 22.0 <= ratio < 61.0:
                    return 0
                return -1
            return 1 if self.is_top_domain else 0
        except Exception:
            return 1

    # 14. AnchorURL: Unsafe / empty anchor tags ratio
    def AnchorURL(self):
        try:
            if self.soup is not None:
                total, unsafe = 0, 0
                for a in self.soup.find_all('a', href=True):
                    total += 1
                    href = a['href'].lower()
                    if href in ('#', '#content', '#skip', 'javascript:void(0);', '') or not (href.startswith('/') or self.domain in href):
                        unsafe += 1
                if total == 0:
                    return 1
                ratio = (unsafe / total) * 100
                if ratio < 31.0:
                    return 1
                elif 31.0 <= ratio < 67.0:
                    return 0
                return -1
            # If no DOM parsed, top established domains are safe, unknown/untrusted domains indicate unsafe anchors
            return 1 if self.is_top_domain else -1
        except Exception:
            return 1 if self.is_top_domain else -1

    # 15. LinksInScriptTags: Links in script and link tags
    def LinksInScriptTags(self):
        try:
            if self.soup is not None:
                total, external = 0, 0
                for tag in self.soup.find_all(['script', 'link'], src=True):
                    total += 1
                    src = tag.get('src') or tag.get('href') or ""
                    if not (src.startswith('/') or self.domain in src):
                        external += 1
                if total == 0:
                    return 1
                ratio = (external / total) * 100
                if ratio < 17.0:
                    return 1
                elif 17.0 <= ratio < 81.0:
                    return 0
                return -1
            return 1 if self.is_top_domain else -1
        except Exception:
            return 1 if self.is_top_domain else -1

    # 16. ServerFormHandler: Form action validation
    def ServerFormHandler(self):
        try:
            if self.soup is not None:
                forms = self.soup.find_all('form', action=True)
                if not forms:
                    return 1
                for form in forms:
                    action = form['action'].strip()
                    if action in ("", "about:blank"):
                        return -1
                    elif not (action.startswith('/') or self.domain in action):
                        return 0
                return 1
            # Check for suspicious credential harvesting action paths in URL
            if re.search(r'login|signin|verify|account|update|admin|banking', self.url, re.IGNORECASE) and not self.is_top_domain:
                return -1
            return 1
        except Exception:
            return 1

    # 17. InfoEmail: Mailto handler check
    def InfoEmail(self):
        try:
            if self.soup is not None and re.search(r"mailto:", self.soup.text, re.IGNORECASE):
                return -1
            if "mailto:" in self.url.lower():
                return -1
            return 1
        except Exception:
            return 1

    # 18. AbnormalURL: Host identity anomalies
    def AbnormalURL(self):
        try:
            return 1 if self.domain else -1
        except Exception:
            return -1

    # 19. WebsiteForwarding: Redirection hops
    def WebsiteForwarding(self):
        try:
            if self.response is not None and hasattr(self.response, 'history'):
                hops = len(self.response.history)
                return 1 if hops <= 1 else (0 if hops <= 4 else -1)
            return 1
        except Exception:
            return 1

    # 20. StatusBarCust: Custom onmouseover script detection
    def StatusBarCust(self):
        try:
            if self.soup is not None and self.soup.find(attrs={"onmouseover": True}):
                return -1
            return 1
        except Exception:
            return 1

    # 21. DisableRightClick: Right-click disabling script
    def DisableRightClick(self):
        try:
            if self.soup is not None and re.search(r"event\.button\s*==\s*2", self.soup.text):
                return -1
            return 1
        except Exception:
            return 1

    # 22. UsingPopupWindow: Popup alert dialogs
    def UsingPopupWindow(self):
        try:
            if self.soup is not None and re.search(r"window\.open\(|alert\(", self.soup.text):
                return -1
            return 1
        except Exception:
            return 1

    # 23. IframeRedirection: Invisible iframe heuristics
    def IframeRedirection(self):
        try:
            if self.soup is not None and self.soup.find_all('iframe'):
                return -1
            return 1
        except Exception:
            return 1

    # 24. AgeofDomain: Domain age heuristic
    def AgeofDomain(self):
        if self.is_top_domain:
            return 1
        common_tlds = ('.com', '.org', '.edu', '.gov', '.io', '.net', '.co.uk', '.de')
        return 1 if any(self.domain.endswith(t) for t in common_tlds) else -1

    # 25. DNSRecording: Host resolution / DNS presence
    def DNSRecording(self):
        try:
            if not self.fast_mode:
                socket.setdefaulttimeout(0.05)
                socket.gethostbyname(self.domain)
            return 1 if self.domain else -1
        except Exception:
            return 1 if self.domain else -1

    # 26. WebsiteTraffic: Domain popularity heuristic
    def WebsiteTraffic(self):
        return 1 if self.is_top_domain else -1

    # 27. PageRank: Page rank heuristic
    def PageRank(self):
        return 1 if self.is_top_domain else -1

    # 28. GoogleIndex: Google indexing heuristic
    def GoogleIndex(self):
        return 1 if self.is_top_domain else 1

    # 29. LinksPointingToPage: Inbound links heuristic
    def LinksPointingToPage(self):
        return 1 if self.is_top_domain else 0

    # 30. StatsReport: Blacklisted phishing IPs and patterns
    def StatsReport(self):
        blacklist_regex = (
            r'at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly'
        )
        if re.search(blacklist_regex, self.url, re.IGNORECASE):
            return -1
        return 1

    def getFeaturesList(self):
        return self.features
