"""
Advanced Security Scanner API — Production-Ready Version
Fixed: SSRF protection, rate limiting, proper error handling,
       non-destructive tests, connection pooling, logging.
"""

import os
import sys
import re
import ssl
import socket
import signal
import logging
import ipaddress
from datetime import datetime
from urllib.parse import urlparse
from functools import wraps

import requests
import dns.resolver
import concurrent.futures
from flask import Flask, request, jsonify, send_from_directory
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# =============================================================================
# CONFIGURATION
# =============================================================================

MAX_SCAN_TIME = int(os.environ.get('MAX_SCAN_TIME', '60'))  # seconds
MAX_URL_LENGTH = 2048

# =============================================================================
# LOGGING
# =============================================================================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger('security_scanner')

# =============================================================================
# FLASK APP SETUP
# =============================================================================

app = Flask(__name__, static_folder="frontend")
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["100 per day", "20 per hour"],
    storage_uri="memory://"  # Use Redis in production: "redis://localhost:6379"
)

# =============================================================================
# SECURITY UTILITIES
# =============================================================================

class ScanTimeout(Exception):
    """Raised when a scan exceeds the maximum allowed duration."""
    pass


def validate_target_url(url: str) -> tuple[bool, str]:
    """
    Validate that a URL is safe to scan.
    Returns (is_valid, error_message).
    """
    if not url or len(url) > MAX_URL_LENGTH:
        return False, f"URL must be between 1 and {MAX_URL_LENGTH} characters"

    # Ensure scheme
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    try:
        parsed = urlparse(url)
    except Exception:
        return False, "Invalid URL format"

    # Scheme check
    if parsed.scheme not in ('http', 'https'):
        return False, "Only HTTP and HTTPS URLs are supported"

    if not parsed.hostname:
        return False, "Invalid URL: no hostname found"

    # Block private/reserved IPs
    try:
        ip = ipaddress.ip_address(parsed.hostname)
        if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_multicast:
            return False, "Cannot scan private, loopback, or reserved IP addresses"
    except ValueError:
        pass  # It's a domain name, which is fine

    # Block known-dangerous hosts
    blocked_hosts = {
        '169.254.169.254',
        'metadata.google.internal',
        'metadata',
        'localhost',
        '0.0.0.0',
        '[::]',
        '[::1]'
    }
    if parsed.hostname.lower() in blocked_hosts:
        return False, "This hostname is blocked for security reasons"

    # Block URLs with embedded credentials
    if parsed.username or parsed.password:
        return False, "URLs with embedded credentials are not allowed"

    # Block non-standard ports in URL (optional — remove if you want to scan custom ports)
    if parsed.port and parsed.port not in (80, 443, 8080, 8443):
        return False, f"Non-standard port {parsed.port} is not allowed"

    return True, ""


def require_api_key(f):
    """Decorator to require a valid API key."""
    @wraps(f)
    def decorated(*args, **kwargs):
        provided = request.headers.get('X-API-Key') or request.args.get('api_key')
        if not provided or provided != API_KEY:
            logger.warning(f"Invalid API key attempt from {request.remote_addr}")
            return jsonify({'error': 'Invalid or missing API key'}), 401
        return f(*args, **kwargs)
    return decorated


def with_timeout(seconds: int):
    """Decorator to enforce a maximum execution time on a function."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            def handler(signum, frame):
                raise ScanTimeout(f"Scan exceeded {seconds} seconds")

            # Set alarm (Unix only; Windows will ignore signal-based timeout)
            old_handler = signal.signal(signal.SIGALRM, handler)
            signal.alarm(seconds)
            try:
                result = func(*args, **kwargs)
            finally:
                signal.alarm(0)
                signal.signal(signal.SIGALRM, old_handler)
            return result
        return wrapper
    return decorator


# =============================================================================
# SCANNER CLASS
# =============================================================================

class AdvancedSecurityScanner:
    """
    Production-grade security scanner with SSRF protection,
    connection pooling, and non-destructive tests.
    """

    # Common ports to scan (expanded from original)
    COMMON_PORTS = {
        21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
        80: 'HTTP', 110: 'POP3', 111: 'RPC', 135: 'MSRPC', 137: 'NetBIOS',
        139: 'NetBIOS-SSN', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
        465: 'SMTPS', 587: 'SMTP-Submission', 631: 'IPP', 636: 'LDAPS',
        993: 'IMAPS', 995: 'POP3S', 1080: 'SOCKS', 1194: 'OpenVPN',
        1433: 'MSSQL', 1723: 'PPTP', 1883: 'MQTT', 3306: 'MySQL',
        3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 5901: 'VNC-1',
        6379: 'Redis', 6667: 'IRC', 7474: 'Neo4j', 8000: 'HTTP-Alt',
        8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt', 8888: 'HTTP-Alt',
        9200: 'Elasticsearch', 9418: 'Git', 11211: 'Memcached',
        15672: 'RabbitMQ', 27017: 'MongoDB'
    }

    # Subdomains to enumerate
    SUBDOMAIN_LIST = [
        'www', 'api', 'admin', 'mail', 'dev', 'stage', 'test', 'cdn',
        'static', 'app', 'portal', 'secure', 'blog', 'shop', 'store',
        'support', 'docs', 'wiki', 'git', 'jenkins', 'grafana',
        'prometheus', 'kibana', 'elastic', 'db', 'database', 'mysql',
        'redis', 'mongo', 'postgres', 'backup', 'old', 'v1', 'v2',
        'staging', 'demo', 'sandbox', 'internal', 'intranet'
    ]

    # Sensitive files to check
    SENSITIVE_PATHS = [
        '/.env', '/.env.local', '/.env.production',
        '/.git/config', '/.git/HEAD', '/.svn/entries',
        '/.htaccess', '/.htpasswd', '/.DS_Store',
        '/package.json', '/composer.json', '/requirements.txt',
        '/Dockerfile', '/docker-compose.yml',
        '/web.config', '/config.php', '/config.json',
        '/admin', '/wp-admin', '/phpmyadmin',
        '/api/docs', '/swagger.json', '/openapi.json',
        '/.well-known/security.txt',
        '/robots.txt', '/sitemap.xml',
        '/backup.sql', '/dump.sql', '/database.sql',
        '/.aws/credentials', '/.kube/config'
    ]

    def __init__(self, target_url: str):
        self.target_url = target_url.rstrip('/')
        parsed = urlparse(self.target_url)
        self.domain = parsed.netloc.split(':')[0]
        self.scheme = parsed.scheme

        # Reusable HTTP session with connection pooling
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'SecurityScanner/3.0 (+https://your-site.com; Security Audit Tool)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'identity',
            'Connection': 'keep-alive',
        })
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=10,
            pool_maxsize=10,
            max_retries=1
        )
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)

    # -------------------------------------------------------------------------
    # MAIN SCAN
    # -------------------------------------------------------------------------

    def run_full_scan(self) -> dict:
        """Execute all security checks and return results."""
        return {
            'timestamp': datetime.now().isoformat(),
            'target': self.target_url,
            'domain': self.domain,
            'ports': self.scan_ports(),
            'ssl': self.analyze_ssl(),
            'cors': self.test_cors(),
            'headers': self.check_security_headers(),
            'rate_limiting': self.test_rate_limiting(),
            'dns': self.check_dns_security(),
            'subdomains': self.enumerate_subdomains(),
            'technologies': self.detect_technologies(),
            'exposed_files': self.check_exposed_files(),
            'cloud': self.detect_cloud_provider(),
            'vulnerabilities': self.check_known_vulnerabilities()
        }

    # -------------------------------------------------------------------------
    # PORT SCANNING
    # -------------------------------------------------------------------------

    def scan_ports(self) -> list:
        """Scan common ports with limited concurrency."""
        open_ports = []

        def check_port(port: int, service: str):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.6)
                result = sock.connect_ex((self.domain, port))
                sock.close()
                if result == 0:
                    severity = self._port_severity(port)
                    open_ports.append({
                        'port': port,
                        'service': service,
                        'severity': severity,
                        'status': 'OPEN'
                    })
            except (socket.error, OSError):
                pass

        # Use 10 workers max to avoid looking like a DDoS
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [
                executor.submit(check_port, port, svc)
                for port, svc in self.COMMON_PORTS.items()
            ]
            concurrent.futures.wait(futures, timeout=15)

        return sorted(open_ports, key=lambda x: x['port'])

    @staticmethod
    def _port_severity(port: int) -> str:
        critical = {22, 3306, 5432, 6379, 27017, 3389, 1433, 23}
        high = {21, 25, 445, 5900, 5901, 11211}
        if port in critical:
            return 'CRITICAL'
        if port in high:
            return 'HIGH'
        return 'INFO'

    # -------------------------------------------------------------------------
    # SSL / TLS
    # -------------------------------------------------------------------------

    def analyze_ssl(self) -> dict:
        """Analyze SSL/TLS certificate and configuration."""
        if self.scheme != 'https':
            return {'valid': False, 'error': 'Not an HTTPS target'}

        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.domain, 443), timeout=8) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()

                    not_after = cert.get('notAfter')
                    if not_after:
                        expire_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        days_left = (expire_date - datetime.now()).days
                    else:
                        days_left = -1

                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    subject = dict(x[0] for x in cert.get('subject', []))

                    # Check for weak protocols
                    weak_protocols = {'SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1'}
                    protocol_warning = version in weak_protocols

                    return {
                        'valid': True,
                        'days_left': days_left,
                        'protocol': version,
                        'protocol_warning': protocol_warning,
                        'cipher': cipher[0] if cipher else 'Unknown',
                        'cipher_bits': cipher[2] if cipher and len(cipher) > 2 else None,
                        'issuer': issuer.get('organizationName', 'Unknown'),
                        'subject': subject.get('commonName', 'Unknown'),
                        'sans': cert.get('subjectAltName', [])
                    }
        except ssl.SSLError as e:
            logger.warning(f"SSL error for {self.domain}: {e}")
            return {'valid': False, 'error': 'SSL certificate error'}
        except socket.error as e:
            logger.warning(f"Socket error for {self.domain}: {e}")
            return {'valid': False, 'error': 'Could not connect for SSL check'}
        except Exception as e:
            logger.error(f"Unexpected SSL error for {self.domain}: {e}")
            return {'valid': False, 'error': 'SSL analysis failed'}

    # -------------------------------------------------------------------------
    # CORS TESTING
    # -------------------------------------------------------------------------

    def test_cors(self) -> list:
        """Test CORS configuration non-destructively."""
        results = []
        test_origins = ['https://evil.com', 'null', 'https://attacker.example']
        test_paths = ['/', '/api', '/api/v1']  # Try common paths

        for path in test_paths:
            for origin in test_origins:
                try:
                    resp = self.session.get(
                        f"{self.target_url}{path}",
                        headers={'Origin': origin},
                        timeout=5,
                        allow_redirects=False
                    )
                    acao = resp.headers.get('Access-Control-Allow-Origin', '')
                    acac = resp.headers.get('Access-Control-Allow-Credentials', '').lower()

                    if acao == '*':
                        results.append({
                            'path': path,
                            'origin': origin,
                            'status': 'CRITICAL',
                            'finding': f'Wildcard CORS on {path} — any site can access this endpoint'
                        })
                    elif origin in acao:
                        creds_risk = 'with credentials' if acac == 'true' else ''
                        results.append({
                            'path': path,
                            'origin': origin,
                            'status': 'HIGH',
                            'finding': f'Reflects origin on {path} {creds_risk} — potential CSRF risk'
                        })
                except requests.RequestException:
                    continue

            # Stop early if we found issues on root path
            if path == '/' and results:
                break

        if not results:
            results.append({'status': 'GOOD', 'finding': 'No CORS misconfigurations detected'})

        return results

    # -------------------------------------------------------------------------
    # SECURITY HEADERS
    # -------------------------------------------------------------------------

    def check_security_headers(self) -> list:
        """Check for recommended security headers."""
        try:
            resp = self.session.get(self.target_url, timeout=8, allow_redirects=True)
            headers = resp.headers

            checks = [
                ('Strict-Transport-Security', 'Enforces HTTPS connections', 'HIGH'),
                ('X-Frame-Options', 'Prevents clickjacking attacks', 'MEDIUM'),
                ('X-Content-Type-Options', 'Prevents MIME type sniffing', 'MEDIUM'),
                ('Content-Security-Policy', 'Mitigates XSS and data injection', 'HIGH'),
                ('Referrer-Policy', 'Controls referrer information leakage', 'LOW'),
                ('Permissions-Policy', 'Restricts browser feature access', 'LOW'),
                ('X-XSS-Protection', 'Legacy XSS filter (deprecated but checked)', 'INFO'),
            ]

            results = []
            for header, description, severity in checks:
                value = headers.get(header)
                results.append({
                    'header': header,
                    'present': value is not None,
                    'value': value if value else 'MISSING',
                    'description': description,
                    'severity': severity
                })

            # Check for server header leakage
            server = headers.get('Server')
            if server:
                results.append({
                    'header': 'Server',
                    'present': True,
                    'value': server,
                    'description': 'Server software version exposed',
                    'severity': 'INFO'
                })

            return results
        except requests.RequestException as e:
            logger.warning(f"Header check failed for {self.domain}: {e}")
            return []

    # -------------------------------------------------------------------------
    # RATE LIMITING (NON-DESTRUCTIVE)
    # -------------------------------------------------------------------------

    def test_rate_limiting(self) -> dict:
        """Test rate limiting using lightweight HEAD requests."""
        endpoints = ['/', '/api', '/login', '/auth']

        for endpoint in endpoints:
            try:
                success = 0
                for _ in range(5):
                    try:
                        resp = self.session.head(
                            f"{self.target_url}{endpoint}",
                            timeout=3,
                            allow_redirects=False
                        )
                        if resp.status_code != 429:
                            success += 1
                    except requests.RequestException:
                        break

                if success == 5:
                    return {
                        'status': 'WARNING',
                        'finding': f'No rate limiting detected on {endpoint} — vulnerable to brute force'
                    }
                elif success < 5:
                    return {
                        'status': 'GOOD',
                        'finding': f'Rate limiting appears active on {endpoint}'
                    }
            except requests.RequestException:
                continue

        return {'status': 'INFO', 'finding': 'Could not conclusively test rate limiting'}

    # -------------------------------------------------------------------------
    # DNS SECURITY
    # -------------------------------------------------------------------------

    def check_dns_security(self) -> dict:
        """Check DNS security records."""
        dns_info = {'spf': None, 'dmarc': None, 'dnssec': False, 'mx': []}

        # SPF
        try:
            answers = dns.resolver.resolve(self.domain, 'TXT', lifetime=5)
            for rdata in answers:
                txt = str(rdata).strip('"')
                if txt.startswith('v=spf1'):
                    dns_info['spf'] = txt
                    break
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
            pass
        except Exception as e:
            logger.debug(f"SPF check error: {e}")

        # DMARC
        try:
            answers = dns.resolver.resolve(f'_dmarc.{self.domain}', 'TXT', lifetime=5)
            dns_info['dmarc'] = str(answers[0]).strip('"')
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
            pass
        except Exception as e:
            logger.debug(f"DMARC check error: {e}")

        # DNSSEC
        try:
            dns.resolver.resolve(self.domain, 'DNSKEY', lifetime=5)
            dns_info['dnssec'] = True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
            dns_info['dnssec'] = False
        except Exception as e:
            logger.debug(f"DNSSEC check error: {e}")
            dns_info['dnssec'] = False

        # MX records
        try:
            answers = dns.resolver.resolve(self.domain, 'MX', lifetime=5)
            dns_info['mx'] = [str(rdata.exchange).rstrip('.') for rdata in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
            pass
        except Exception as e:
            logger.debug(f"MX check error: {e}")

        return dns_info

    # -------------------------------------------------------------------------
    # SUBDOMAIN ENUMERATION
    # -------------------------------------------------------------------------

    def enumerate_subdomains(self) -> list:
        """Enumerate common subdomains."""
        found = []

        def check_subdomain(sub: str):
            subdomain = f"{sub}.{self.domain}"
            try:
                ip = socket.gethostbyname(subdomain)
                found.append({'subdomain': subdomain, 'ip': ip})
            except socket.gaierror:
                pass
            except Exception as e:
                logger.debug(f"Subdomain check error for {subdomain}: {e}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
            futures = [executor.submit(check_subdomain, sub) for sub in self.SUBDOMAIN_LIST]
            concurrent.futures.wait(futures, timeout=20)

        return found

    # -------------------------------------------------------------------------
    # TECHNOLOGY DETECTION
    # -------------------------------------------------------------------------

    def detect_technologies(self) -> list:
        """Detect technologies from headers and response content."""
        techs = []
        try:
            resp = self.session.get(self.target_url, timeout=8)
            html = resp.text.lower()
            headers = {k.lower(): v.lower() for k, v in resp.headers.items()}

            # Server header
            server = resp.headers.get('Server', '')
            powered = resp.headers.get('X-Powered-By', '')

            tech_map = {
                'next.js': ('Next.js', None),
                'react': ('React', None),
                'vue': ('Vue.js', None),
                'angular': ('Angular', None),
                'jquery': ('jQuery', None),
                'bootstrap': ('Bootstrap', None),
                'tailwind': ('Tailwind CSS', None),
                'wordpress': ('WordPress', None),
                'drupal': ('Drupal', None),
                'joomla': ('Joomla', None),
                'laravel': ('Laravel', None),
                'django': ('Django', None),
                'flask': ('Flask', None),
                'express': ('Express.js', None),
                'nginx': ('Nginx', server),
                'apache': ('Apache', server),
                'cloudflare': ('Cloudflare', None),
                'fastly': ('Fastly', None),
                'akamai': ('Akamai', None),
            }

            for keyword, (name, version_source) in tech_map.items():
                if keyword in html or keyword in headers.get('server', ''):
                    version = None
                    if version_source and keyword in version_source.lower():
                        # Try to extract version from Server header
                        pattern = keyword + r'[/\-]?([\d.]+)'
                        match = re.search(pattern, version_source, re.I)
                        if match:
                            version = match.group(1)
                    techs.append({'name': name, 'version': version})

            # Framework-specific indicators
            if 'wp-content' in html:
                techs.append({'name': 'WordPress', 'version': None})
            if '_next/static' in html:
                techs.append({'name': 'Next.js', 'version': None})
            if 'gatsby' in html:
                techs.append({'name': 'Gatsby', 'version': None})
            if 'astro' in html:
                techs.append({'name': 'Astro', 'version': None})

            # Deduplicate
            seen = set()
            unique = []
            for t in techs:
                key = t['name']
                if key not in seen:
                    seen.add(key)
                    unique.append(t)

            return unique
        except requests.RequestException as e:
            logger.warning(f"Technology detection failed: {e}")
            return []

    # -------------------------------------------------------------------------
    # EXPOSED FILES
    # -------------------------------------------------------------------------

    def check_exposed_files(self) -> list:
        """Check for exposed sensitive files."""
        exposed = []

        for path in self.SENSITIVE_PATHS:
            try:
                resp = self.session.get(
                    f"{self.target_url}{path}",
                    timeout=5,
                    allow_redirects=False
                )
                if resp.status_code == 200:
                    # Additional check: ensure it's not a generic 200 page
                    content_length = len(resp.content)
                    if content_length > 0 and content_length < 100000:
                        exposed.append({
                            'path': path,
                            'status': 'EXPOSED',
                            'severity': 'CRITICAL',
                            'size': content_length
                        })
                elif resp.status_code == 403:
                    exposed.append({
                        'path': path,
                        'status': 'BLOCKED',
                        'severity': 'INFO'
                    })
            except requests.RequestException:
                pass

        return exposed

    # -------------------------------------------------------------------------
    # CLOUD DETECTION
    # -------------------------------------------------------------------------

    def detect_cloud_provider(self) -> dict:
        """Detect cloud hosting provider."""
        try:
            resp = self.session.head(self.target_url, timeout=5, allow_redirects=False)
            headers = resp.headers

            # Check headers
            if 'x-vercel-id' in headers or 'vercel' in headers.get('server', '').lower():
                return {'provider': 'Vercel', 'detected': True}
            if 'x-netlify' in headers or 'netlify' in headers.get('server', '').lower():
                return {'provider': 'Netlify', 'detected': True}
            if 'cloudfront' in headers.get('via', '').lower():
                return {'provider': 'AWS CloudFront', 'detected': True}
            if 'x-amz-cf-id' in headers:
                return {'provider': 'AWS CloudFront', 'detected': True}
            if 'cf-ray' in headers:
                return {'provider': 'Cloudflare', 'detected': True}
            if 'x-fastly' in headers:
                return {'provider': 'Fastly', 'detected': True}
            if 'x-akamai' in headers or 'akamai' in headers.get('server', '').lower():
                return {'provider': 'Akamai', 'detected': True}
            if 'x-github-request-id' in headers:
                return {'provider': 'GitHub Pages', 'detected': True}
            if 'render' in headers.get('server', '').lower():
                return {'provider': 'Render', 'detected': True}

            # Check domain patterns
            if 'vercel.app' in self.target_url or 'now.sh' in self.target_url:
                return {'provider': 'Vercel', 'detected': True}
            if 'netlify.app' in self.target_url or 'netlify.com' in self.target_url:
                return {'provider': 'Netlify', 'detected': True}
            if 'github.io' in self.target_url:
                return {'provider': 'GitHub Pages', 'detected': True}
            if 'herokuapp.com' in self.target_url:
                return {'provider': 'Heroku', 'detected': True}
            if 'firebaseapp.com' in self.target_url or 'web.app' in self.target_url:
                return {'provider': 'Firebase', 'detected': True}
            if 'azurewebsites.net' in self.target_url:
                return {'provider': 'Azure', 'detected': True}
            if 'appspot.com' in self.target_url:
                return {'provider': 'Google App Engine', 'detected': True}
            if 'cloud.google' in self.target_url:
                return {'provider': 'Google Cloud', 'detected': True}
            if 'amazonaws.com' in self.target_url:
                return {'provider': 'AWS', 'detected': True}

            return {'provider': 'Unknown / Traditional Hosting', 'detected': False}
        except requests.RequestException:
            return {'provider': 'Unknown', 'detected': False}

    # -------------------------------------------------------------------------
    # KNOWN VULNERABILITIES
    # -------------------------------------------------------------------------

    def check_known_vulnerabilities(self) -> list:
        """Check for common misconfigurations."""
        vulns = []
        try:
            resp = self.session.get(self.target_url, timeout=8)
            headers = resp.headers

            if not headers.get('X-Frame-Options') and not headers.get('Content-Security-Policy'):
                vulns.append({
                    'issue': 'Clickjacking Protection Missing',
                    'severity': 'MEDIUM',
                    'remediation': 'Add X-Frame-Options: DENY or SAMEORIGIN, or use CSP frame-ancestors'
                })

            if not headers.get('X-Content-Type-Options'):
                vulns.append({
                    'issue': 'MIME Sniffing Protection Missing',
                    'severity': 'MEDIUM',
                    'remediation': 'Add X-Content-Type-Options: nosniff'
                })

            if not headers.get('Strict-Transport-Security') and self.scheme == 'https':
                vulns.append({
                    'issue': 'HSTS Missing',
                    'severity': 'HIGH',
                    'remediation': 'Add Strict-Transport-Security header with max-age'
                })

            if headers.get('Server') and len(headers.get('Server', '')) > 3:
                vulns.append({
                    'issue': 'Server Header Leaks Version Info',
                    'severity': 'LOW',
                    'remediation': 'Configure server to suppress or genericize Server header'
                })

            # Check for debug endpoints
            debug_paths = ['/debug', '/phpinfo.php', '/.env', '/adminer.php']
            for path in debug_paths:
                try:
                    r = self.session.head(f"{self.target_url}{path}", timeout=3, allow_redirects=False)
                    if r.status_code == 200:
                        vulns.append({
                            'issue': f'Potentially exposed debug endpoint: {path}',
                            'severity': 'HIGH',
                            'remediation': f'Remove or protect {path}'
                        })
                except requests.RequestException:
                    pass

            return vulns
        except requests.RequestException:
            return []

    # -------------------------------------------------------------------------
    # SCORING
    # -------------------------------------------------------------------------

    @staticmethod
    def calculate_score(results: dict) -> int:
        """Calculate a 0-100 security score."""
        score = 100

        # Deduct for open critical ports
        if results.get('ports'):
            critical = sum(1 for p in results['ports'] if p.get('severity') == 'CRITICAL')
            high = sum(1 for p in results['ports'] if p.get('severity') == 'HIGH')
            score -= critical * 15
            score -= high * 8

        # Deduct for CORS issues
        if results.get('cors'):
            critical_cors = sum(1 for c in results['cors'] if c.get('status') == 'CRITICAL')
            high_cors = sum(1 for c in results['cors'] if c.get('status') == 'HIGH')
            score -= critical_cors * 20
            score -= high_cors * 10

        # Deduct for exposed files
        if results.get('exposed_files'):
            exposed = sum(1 for f in results['exposed_files'] if f.get('status') == 'EXPOSED')
            score -= exposed * 15

        # Deduct for missing headers
        if results.get('headers'):
            high_missing = sum(1 for h in results['headers'] if not h.get('present') and h.get('severity') == 'HIGH')
            med_missing = sum(1 for h in results['headers'] if not h.get('present') and h.get('severity') == 'MEDIUM')
            score -= high_missing * 8
            score -= med_missing * 4

        # Deduct for invalid SSL
        if results.get('ssl') and not results['ssl'].get('valid'):
            score -= 25
        elif results.get('ssl') and results['ssl'].get('protocol_warning'):
            score -= 10

        # Deduct for known vulnerabilities
        if results.get('vulnerabilities'):
            high_vulns = sum(1 for v in results['vulnerabilities'] if v.get('severity') == 'HIGH')
            med_vulns = sum(1 for v in results['vulnerabilities'] if v.get('severity') == 'MEDIUM')
            score -= high_vulns * 10
            score -= med_vulns * 5

        return max(0, min(100, score))


# =============================================================================
# FLASK ROUTES — API + FRONTEND (Combined Server)
# =============================================================================

@app.route('/')
def serve_index():
    """Serve the main frontend page."""
    return send_from_directory('frontend', 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    """Serve frontend static files."""
    return send_from_directory('frontend', path)

@app.route('/api/health')
def health():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/info')
def info():
    """API info endpoint."""
    return jsonify({
        'name': 'Advanced Security Scanner API',
        'version': '3.1',
        'status': 'online',
        'features': [
            'Port Scanning', 'SSL Analysis', 'CORS Testing',
            'Security Headers', 'Rate Limiting', 'DNS Security',
            'Subdomain Enumeration', 'Technology Detection',
            'Exposed Files', 'Vulnerability Checks', 'Cloud Detection'
        ]
    })

@app.route('/api/scan')
@limiter.limit("5 per minute")
@with_timeout(MAX_SCAN_TIME)
def scan():
    """
    Public scan endpoint — no API key needed since it's same-server.
    SSRF protection and rate limiting are the security layers.
    """
    url = request.args.get('url')
    if not url:
        return jsonify({'error': 'Missing url parameter'}), 400

    # Validate URL (blocks private IPs, metadata endpoints, etc.)
    is_valid, error_msg = validate_target_url(url)
    if not is_valid:
        logger.warning(f"Blocked scan attempt: {url} — {error_msg}")
        return jsonify({'error': error_msg}), 400

    # Normalize URL
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    logger.info(f"Scan started for {url} from {request.remote_addr}")

    try:
        scanner = AdvancedSecurityScanner(url)
        results = scanner.run_full_scan()
        results['score'] = scanner.calculate_score(results)

        logger.info(f"Scan completed for {url} — Score: {results['score']}")
        return jsonify(results)

    except ScanTimeout:
        logger.warning(f"Scan timed out for {url}")
        return jsonify({'error': 'Scan exceeded maximum time limit'}), 504

    except Exception as e:
        logger.error(f"Unexpected error scanning {url}: {e}")
        return jsonify({'error': 'An unexpected error occurred during scanning'}), 500


@app.errorhandler(429)
def ratelimit_handler(e):
    """Handle rate limit exceeded."""
    return jsonify({
        'error': 'Rate limit exceeded. Maximum 5 scans per minute.',
        'retry_after': e.description
    }), 429


# =============================================================================
# MAIN
# =============================================================================

if __name__ == '__main__':
    # NEVER run with debug=True in production
    app.run(host='0.0.0.0', port=10000, debug=False)
