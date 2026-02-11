"""
Detector de problemas de SSL y análisis SEO básico
"""
import re
from typing import Dict
from bs4 import BeautifulSoup
from urllib.parse import urlparse

class SSLSEODetector:
    """Detecta problemas de SSL y realiza análisis SEO básico"""
    
    def detect_ssl_issues(self, url: str, response_headers: Dict = None) -> Dict:
        """
        Detecta problemas de SSL
        
        Args:
            url: URL del sitio
            response_headers: Headers de la respuesta HTTP
            
        Returns:
            Dict con problemas de SSL encontrados
        """
        results = {
            "has_https": False,
            "has_mixed_content": False,
            "issues": [],
            "severity": "none"
        }
        
        parsed = urlparse(url)
        
        # Verificar si usa HTTPS
        if parsed.scheme == "https":
            results["has_https"] = True
        else:
            results["issues"].append("Site not using HTTPS")
            results["severity"] = "high"
        
        # Verificar headers de seguridad (si están disponibles)
        if response_headers:
            security_headers = {
                "Strict-Transport-Security": "Missing HSTS header",
                "X-Content-Type-Options": "Missing X-Content-Type-Options header",
                "X-Frame-Options": "Missing X-Frame-Options header",
            }
            
            for header, message in security_headers.items():
                if header not in response_headers:
                    results["issues"].append(message)
        
        if results["issues"] and results["severity"] == "none":
            results["severity"] = "medium"
        
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
                elif results["title_length"] < 30:
                    results["issues"].append(f"Title too short ({results['title_length']} chars)")
                elif results["title_length"] > 60:
                    results["issues"].append(f"Title too long ({results['title_length']} chars)")
                
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
            critical_issues = ['Missing title tag', 'Title tag is empty', 'Missing H1 tag']
            if any(issue in results["issues"] for issue in critical_issues):
                results["severity"] = "high"
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
    print("\n✓ Test 1 - SSL Issues:")
    result1 = detector.detect_ssl_issues("http://example.com")
    print(f"  Has HTTPS: {result1['has_https']}")
    print(f"  Issues: {result1['issues']}")
    print(f"  Severity: {result1['severity']}")
    
    # Test 2: SSL - sitio con HTTPS
    print("\n✓ Test 2 - SSL Secure:")
    result2 = detector.detect_ssl_issues("https://example.com")
    print(f"  Has HTTPS: {result2['has_https']}")
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
