"""
Detector de problemas de SSL y análisis SEO básico
"""
import re
import ssl
import socket
from datetime import datetime, timezone
from typing import Dict
from bs4 import BeautifulSoup
from urllib.parse import urlparse

class SSLSEODetector:
    """Detecta problemas de SSL y realiza análisis SEO básico"""
    
    def _verify_certificate(self, hostname: str) -> Dict:
        """
        Verifica el certificado SSL real del servidor.
        
        Returns:
            Dict con info del certificado o error
        """
        cert_info = {
            "valid": False,
            "issuer": None,
            "subject": None,
            "expires": None,
            "days_remaining": None,
            "error": None,
        }
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Certificado válido (si llegamos aquí no hubo error SSL)
                    cert_info["valid"] = True
                    
                    # Emisor
                    issuer_parts = []
                    for rdn in cert.get("issuer", ()):
                        for attr_type, attr_value in rdn:
                            if attr_type in ("organizationName", "commonName"):
                                issuer_parts.append(attr_value)
                    cert_info["issuer"] = " - ".join(issuer_parts) if issuer_parts else "Unknown"
                    
                    # Sujeto (dominio)
                    subject_parts = []
                    for rdn in cert.get("subject", ()):
                        for attr_type, attr_value in rdn:
                            if attr_type == "commonName":
                                subject_parts.append(attr_value)
                    cert_info["subject"] = ", ".join(subject_parts) if subject_parts else hostname
                    
                    # Fecha de expiración
                    not_after = cert.get("notAfter")
                    if not_after:
                        # Formato: 'Mar  4 12:00:00 2026 GMT'
                        exp_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        exp_date = exp_date.replace(tzinfo=timezone.utc)
                        cert_info["expires"] = exp_date.strftime("%Y-%m-%d")
                        days_left = (exp_date - datetime.now(timezone.utc)).days
                        cert_info["days_remaining"] = days_left
                        
        except ssl.SSLCertVerificationError as e:
            cert_info["error"] = f"Invalid certificate: {str(e)[:150]}"
        except ssl.SSLError as e:
            cert_info["error"] = f"SSL error: {str(e)[:150]}"
        except socket.timeout:
            cert_info["error"] = "Connection timeout verifying certificate"
        except OSError as e:
            cert_info["error"] = f"Connection error: {str(e)[:150]}"
        except Exception as e:
            cert_info["error"] = f"Error checking certificate: {str(e)[:150]}"
        
        return cert_info
    
    def detect_ssl_issues(self, url: str, response_headers: Dict = None) -> Dict:
        """
        Detecta problemas de SSL verificando el certificado real del servidor.
        
        Args:
            url: URL del sitio (final URL después de redirects)
            response_headers: Headers de la respuesta HTTP
            
        Returns:
            Dict con problemas de SSL encontrados
        """
        results = {
            "has_https": False,
            "has_valid_certificate": False,
            "certificate": {},
            "has_mixed_content": False,
            "missing_headers": [],
            "issues": [],
            "severity": "none"
        }
        
        parsed = urlparse(url)
        
        # Verificar si la URL final usa HTTPS
        if parsed.scheme == "https":
            results["has_https"] = True
            
            # Verificar certificado SSL real
            cert_info = self._verify_certificate(parsed.hostname)
            results["certificate"] = cert_info
            
            if cert_info["valid"]:
                results["has_valid_certificate"] = True
                
                # Avisar si el certificado expira pronto (< 30 días)
                if cert_info["days_remaining"] is not None and cert_info["days_remaining"] < 30:
                    if cert_info["days_remaining"] < 0:
                        results["issues"].append(
                            f"SSL certificate EXPIRED ({abs(cert_info['days_remaining'])} days ago)"
                        )
                    else:
                        results["issues"].append(
                            f"SSL certificate expires soon ({cert_info['days_remaining']} days remaining)"
                        )
            else:
                results["issues"].append(
                    f"SSL certificate problem: {cert_info.get('error', 'Unknown error')}"
                )
        else:
            results["issues"].append("Site not using HTTPS")
        
        # Verificar headers de seguridad (informativos, no problemas reales)
        if response_headers:
            security_headers = {
                "Strict-Transport-Security": "Missing HSTS header",
                "X-Content-Type-Options": "Missing X-Content-Type-Options header",
                "X-Frame-Options": "Missing X-Frame-Options header",
            }
            
            for header, message in security_headers.items():
                if header not in response_headers:
                    results["missing_headers"].append(message)
        
        # Determinar severidad basada en problemas reales
        if results["issues"]:
            # Check for critical issues
            if any("EXPIRED" in i or "not using HTTPS" in i for i in results["issues"]):
                results["severity"] = "high"
            elif any("expires soon" in i for i in results["issues"]):
                results["severity"] = "medium"
            else:
                results["severity"] = "medium"
        elif results["missing_headers"] and results["severity"] == "none":
            results["severity"] = "low"
        
        return results
    
    def detect_mixed_content(self, html_content: str, url: str) -> bool:
        """Detecta contenido mixto (HTTP en página HTTPS)"""
        if not url.startswith("https://"):
            return False
        
        # Buscar recursos HTTP en página HTTPS
        http_resources = re.findall(r'(?:src|href)=["\']http://[^"\']+', html_content, re.IGNORECASE)
        return len(http_resources) > 0
    
    def analyze_seo(self, html_content: str, url: str) -> Dict:
        """
        Análisis SEO básico
        
        Args:
            html_content: Contenido HTML
            url: URL de la página
            
        Returns:
            Dict con análisis SEO
        """
        results = {
            "has_title": False,
            "title_length": 0,
            "title_text": "",
            "has_meta_description": False,
            "meta_description_length": 0,
            "meta_description_text": "",
            "has_h1": False,
            "h1_count": 0,
            "h1_texts": [],
            "has_canonical": False,
            "canonical_url": "",
            "images_without_alt": 0,
            "total_images": 0,
            "has_open_graph": False,
            "issues": [],
            "severity": "none"
        }
        
        try:
            soup = BeautifulSoup(html_content, 'lxml')
            
            # Analizar título
            title_tag = soup.find('title')
            if title_tag:
                results["has_title"] = True
                results["title_text"] = title_tag.get_text().strip()
                results["title_length"] = len(results["title_text"])
                
                if results["title_length"] == 0:
                    results["issues"].append("Title tag is empty")
                elif results["title_length"] < 10:
                    results["issues"].append(f"Title too short ({results['title_length']} chars)")
                elif results["title_length"] > 60:
                    results["issues"].append(f"Title too long ({results['title_length']} chars, recommended: max 60)")
                
                # Títulos genéricos
                generic_titles = ['untitled', 'home', 'welcome', 'new page', 'index']
                if results["title_text"].lower() in generic_titles:
                    results["issues"].append(f"Generic title: {results['title_text']}")
            else:
                results["issues"].append("Missing title tag")
            
            # Analizar meta description
            meta_desc = soup.find('meta', attrs={'name': re.compile('^description$', re.I)})
            if meta_desc and meta_desc.get('content'):
                results["has_meta_description"] = True
                results["meta_description_text"] = meta_desc.get('content', '').strip()
                results["meta_description_length"] = len(results["meta_description_text"])
                
                if results["meta_description_length"] < 50:
                    results["issues"].append(f"Meta description too short ({results['meta_description_length']} chars)")
                elif results["meta_description_length"] > 160:
                    results["issues"].append(f"Meta description too long ({results['meta_description_length']} chars)")
            else:
                results["issues"].append("Missing meta description")
            
            # Analizar H1
            h1_tags = soup.find_all('h1')
            results["h1_count"] = len(h1_tags)
            results["has_h1"] = results["h1_count"] > 0
            
            if results["h1_count"] == 0:
                results["issues"].append("Missing H1 tag")
            elif results["h1_count"] > 1:
                results["issues"].append(f"Multiple H1 tags found ({results['h1_count']})")
            
            for h1 in h1_tags[:3]:
                text = h1.get_text().strip()
                if text:
                    results["h1_texts"].append(text[:100])
            
            # Analizar canonical
            canonical = soup.find('link', attrs={'rel': 'canonical'})
            if canonical and canonical.get('href'):
                results["has_canonical"] = True
                results["canonical_url"] = canonical.get('href', '')
            
            # Analizar imágenes sin alt
            images = soup.find_all('img')
            results["total_images"] = len(images)
            results["images_without_alt"] = sum(1 for img in images if not img.get('alt'))
            
            if results["images_without_alt"] > 0:
                percentage = (results["images_without_alt"] / results["total_images"]) * 100 if results["total_images"] > 0 else 0
                results["issues"].append(f"{results['images_without_alt']}/{results['total_images']} images missing alt text ({percentage:.0f}%)")
            
            # Analizar Open Graph
            og_tags = soup.find_all('meta', attrs={'property': re.compile('^og:')})
            results["has_open_graph"] = len(og_tags) > 0
            
            # Determinar severidad
            critical_seo_issues = ['Missing title tag', 'Title tag is empty']
            medium_seo_issues = ['Missing H1 tag', 'Missing meta description']
            if any(issue in results["issues"] for issue in critical_seo_issues):
                results["severity"] = "high"
            elif any(issue in results["issues"] for issue in medium_seo_issues):
                results["severity"] = "medium"
            elif len(results["issues"]) >= 3:
                results["severity"] = "medium"
            elif len(results["issues"]) > 0:
                results["severity"] = "low"
                
        except Exception as e:
            results["issues"].append(f"Error parsing HTML: {str(e)[:100]}")
            results["severity"] = "medium"
        
        return results


def test_ssl_seo_detector():
    """Test del detector de SSL y SEO"""
    print("🧪 Testing SSL & SEO Detector...")
    
    detector = SSLSEODetector()
    
    # Test 1: SSL - sitio sin HTTPS
    print("\n✓ Test 1 - SSL Issues (http):")
    result1 = detector.detect_ssl_issues("http://example.com")
    print(f"  Has HTTPS: {result1['has_https']}")
    print(f"  Valid cert: {result1['has_valid_certificate']}")
    print(f"  Issues: {result1['issues']}")
    print(f"  Severity: {result1['severity']}")
    
    # Test 2: SSL - sitio con HTTPS (real cert check)
    print("\n✓ Test 2 - SSL Secure (https://example.com):")
    result2 = detector.detect_ssl_issues("https://example.com")
    print(f"  Has HTTPS: {result2['has_https']}")
    print(f"  Valid cert: {result2['has_valid_certificate']}")
    cert = result2.get('certificate', {})
    if cert.get('valid'):
        print(f"  Issuer: {cert.get('issuer')}")
        print(f"  Expires: {cert.get('expires')} ({cert.get('days_remaining')} days)")
    else:
        print(f"  Cert error: {cert.get('error')}")
    print(f"  Severity: {result2['severity']}")
    
    # Test 3: SEO - sitio con problemas
    html_bad_seo = """
    <html>
    <head>
        <title>Home</title>
    </head>
    <body>
        <h1>Title 1</h1>
        <h1>Title 2</h1>
        <img src="image1.jpg">
        <img src="image2.jpg" alt="Image 2">
    </body>
    </html>
    """
    
    print("\n✓ Test 3 - SEO with Issues:")
    result3 = detector.analyze_seo(html_bad_seo, "https://example.com")
    print(f"  Has title: {result3['has_title']}")
    print(f"  Title: '{result3['title_text']}'")
    print(f"  Has meta description: {result3['has_meta_description']}")
    print(f"  H1 count: {result3['h1_count']}")
    print(f"  Images without alt: {result3['images_without_alt']}/{result3['total_images']}")
    print(f"  Issues found: {len(result3['issues'])}")
    for issue in result3['issues']:
        print(f"    - {issue}")
    print(f"  Severity: {result3['severity']}")
    
    # Test 4: SEO - sitio bien optimizado
    html_good_seo = """
    <html>
    <head>
        <title>Professional Web Development Services - Best Agency 2026</title>
        <meta name="description" content="Expert web development services with 10+ years experience. Custom solutions for businesses of all sizes.">
        <link rel="canonical" href="https://example.com/">
        <meta property="og:title" content="Web Development Services">
    </head>
    <body>
        <h1>Welcome to Our Agency</h1>
        <img src="image1.jpg" alt="Team photo">
        <img src="image2.jpg" alt="Office">
    </body>
    </html>
    """
    
    print("\n✓ Test 4 - SEO Optimized:")
    result4 = detector.analyze_seo(html_good_seo, "https://example.com")
    print(f"  Has title: {result4['has_title']} ({result4['title_length']} chars)")
    print(f"  Has meta description: {result4['has_meta_description']} ({result4['meta_description_length']} chars)")
    print(f"  H1 count: {result4['h1_count']}")
    print(f"  Has canonical: {result4['has_canonical']}")
    print(f"  Has Open Graph: {result4['has_open_graph']}")
    print(f"  Images without alt: {result4['images_without_alt']}/{result4['total_images']}")
    print(f"  Issues found: {len(result4['issues'])}")
    print(f"  Severity: {result4['severity']}")
    
    print("\n✅ SSL & SEO Detector tests completed!")
    return True


if __name__ == "__main__":
    test_ssl_seo_detector()
