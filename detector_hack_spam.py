"""
Detector de sitios hackeados y spam SEO injection
"""
import re
from typing import List, Dict
from bs4 import BeautifulSoup

class HackDetector:
    """Detecta sitios hackeados y spam SEO injection"""
    
    # Patrones de hackeo evidente
    HACK_PATTERNS = [
        r"hacked by\s+[\w\s]+",
        r"defaced by\s+[\w\s]+",
        r"injected by\s+[\w\s]+",
        r"pwned by\s+[\w\s]+",
        r"owned by.*?(?:team|cyber|army)",
        r"site\s+(?:has been\s+)?hacked",
        r"this site has been (?:hacked|compromised)",
        r"cyber army",
        r"(?:was|has been) hacked",
    ]
    
    # Patrones de spam SEO
    SPAM_SEO_PATTERNS = [
        (r"(?:casino|poker|slots).*?online", "casino spam"),
        (r"(?:viagra|cialis|levitra|pharmacy)", "pharma spam"),
        (r"payday\s+loans?", "payday loan spam"),
        (r"(?:buy|cheap).*?(?:viagra|cialis)", "pharma spam"),
        (r"online\s+(?:gambling|betting)", "gambling spam"),
    ]
    
    # Patrones sospechosos en WordPress
    WP_SUSPICIOUS_PATTERNS = [
        r"wp-content/.*?(?:casino|poker|viagra|cialis)",
        r"wp-includes/.*?\.php\?\w+=",
    ]
    
    # Patrones de código malicioso
    MALWARE_PATTERNS = [
        r"eval\(base64_decode\(",
        r"eval\(gzinflate\(",
        r"assert\(base64_decode\(",
        r"eval\(str_rot13\(",
        r"base64_decode.*?eval",
    ]
    
    # Patrones de API keys y tokens hardcodeados (NUEVO - Fase 1)
    API_KEY_PATTERNS = [
        (r'api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{20,})["\']', 'API Key'),
        (r'apikey["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{20,})["\']', 'API Key'),
        (r'secret[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{20,})["\']', 'Secret Key'),
        (r'access[_-]?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{20,})["\']', 'Access Token'),
        (r'auth[_-]?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{20,})["\']', 'Auth Token'),
        (r'sk_live_[a-zA-Z0-9]{20,}', 'Stripe Live Key'),
        (r'sk_test_[a-zA-Z0-9]{20,}', 'Stripe Test Key'),
        (r'pk_live_[a-zA-Z0-9]{20,}', 'Stripe Publishable Key'),
        (r'AIza[0-9A-Za-z_-]{35}', 'Google API Key'),
        (r'AKIA[0-9A-Z]{16}', 'AWS Access Key'),
        (r'ghp_[a-zA-Z0-9]{36}', 'GitHub Personal Token'),
        (r'gho_[a-zA-Z0-9]{36}', 'GitHub OAuth Token'),
    ]
    
    # Comentarios sospechosos en HTML (NUEVO - Fase 1)
    SUSPICIOUS_COMMENTS = [
        r'<!--.*?(?:password|passwd|pwd).*?-->',
        r'<!--.*?(?:TODO|FIXME|HACK).*?(?:remove|delete|fix).*?-->',
        r'<!--.*?(?:debug|test).*?(?:mode|enabled).*?-->',
        r'<!--.*?(?:admin|root).*?-->',
    ]
    
    def __init__(self):
        self.hack_regex = [re.compile(pattern, re.IGNORECASE) for pattern in self.HACK_PATTERNS]
        self.spam_regex = [(re.compile(pattern, re.IGNORECASE), label) for pattern, label in self.SPAM_SEO_PATTERNS]
        self.wp_regex = [re.compile(pattern, re.IGNORECASE) for pattern in self.WP_SUSPICIOUS_PATTERNS]
        self.malware_regex = [re.compile(pattern, re.IGNORECASE) for pattern in self.MALWARE_PATTERNS]
        self.api_key_regex = [(re.compile(pattern, re.IGNORECASE), label) if isinstance(pattern, str) else (re.compile(pattern[0], re.IGNORECASE), pattern[1]) for pattern, label in self.API_KEY_PATTERNS]
        self.comment_regex = [re.compile(pattern, re.IGNORECASE | re.DOTALL) for pattern in self.SUSPICIOUS_COMMENTS]
    
    def detect(self, html_content: str, url: str) -> Dict:
        """
        Detecta hackeos, spam SEO y malware
        
        Args:
            html_content: Contenido HTML de la página
            url: URL de la página
            
        Returns:
            Dict con los problemas encontrados
        """
        results = {
            "is_hacked": False,
            "has_spam_seo": False,
            "has_malware": False,
            "has_exposed_keys": False,
            "has_suspicious_comments": False,
            "hack_indicators": [],
            "spam_indicators": [],
            "malware_indicators": [],
            "hidden_content": [],
            "exposed_keys": [],
            "suspicious_comments": [],
            "severity": "none"
        }
        
        # Detectar hackeos evidentes
        for regex in self.hack_regex:
            matches = regex.findall(html_content)
            if matches:
                results["is_hacked"] = True
                for match in matches[:3]:
                    if match not in results["hack_indicators"]:
                        results["hack_indicators"].append(match[:150])
        
        # Detectar spam SEO
        for regex, label in self.spam_regex:
            matches = regex.findall(html_content)
            if matches:
                results["has_spam_seo"] = True
                spam_entry = f"{label}: {matches[0][:100]}"
                if spam_entry not in results["spam_indicators"]:
                    results["spam_indicators"].append(spam_entry)
        
        # Detectar spam en WordPress específicamente
        for regex in self.wp_regex:
            matches = regex.findall(html_content)
            if matches:
                results["has_spam_seo"] = True
                for match in matches[:2]:
                    indicator = f"WP suspicious: {match[:100]}"
                    if indicator not in results["spam_indicators"]:
                        results["spam_indicators"].append(indicator)
        
        # Detectar malware
        for regex in self.malware_regex:
            matches = regex.findall(html_content)
            if matches:
                results["has_malware"] = True
                for match in matches[:2]:
                    if match[:100] not in results["malware_indicators"]:
                        results["malware_indicators"].append(match[:100])
        
        # Detectar API keys y tokens expuestos (NUEVO - Fase 1)
        for regex, key_type in self.api_key_regex:
            matches = regex.findall(html_content)
            if matches:
                results["has_exposed_keys"] = True
                for match in matches[:3]:  # Limitar a 3 ejemplos
                    # Obtener solo los primeros y últimos 4 chars para no exponer la key completa
                    if isinstance(match, tuple):
                        key_value = match[0] if match[0] else match[1]
                    else:
                        key_value = match
                    
                    if len(key_value) > 8:
                        masked = f"{key_value[:4]}...{key_value[-4:]}"
                    else:
                        masked = "***"
                    
                    key_info = f"{key_type}: {masked}"
                    if key_info not in results["exposed_keys"]:
                        results["exposed_keys"].append(key_info)
        
        # Detectar comentarios HTML sospechosos (NUEVO - Fase 1)
        for regex in self.comment_regex:
            matches = regex.findall(html_content)
            if matches:
                results["has_suspicious_comments"] = True
                for match in matches[:3]:
                    comment = match[:100].strip()
                    if comment not in results["suspicious_comments"]:
                        results["suspicious_comments"].append(comment)
        
        # Detectar contenido oculto (usando BeautifulSoup)
        try:
            soup = BeautifulSoup(html_content, 'lxml')
            
            # Buscar elementos con display:none que contengan spam keywords
            spam_keywords = ['casino', 'poker', 'viagra', 'cialis', 'payday', 'loan']
            hidden_elements = soup.find_all(style=re.compile(r'display\s*:\s*none', re.IGNORECASE))
            
            for element in hidden_elements[:5]:
                text = element.get_text().lower()
                if any(keyword in text for keyword in spam_keywords):
                    results["hidden_content"].append(f"Hidden spam: {text[:100]}")
                    results["has_spam_seo"] = True
        except Exception as e:
            pass  # Si falla el parsing, continuamos
        
        # Determinar severidad
        if results["is_hacked"]:
            results["severity"] = "critical"
        elif results["has_malware"]:
            results["severity"] = "critical"
        elif results["has_exposed_keys"]:
            results["severity"] = "critical"  # API keys expuestas son críticas
        elif results["has_spam_seo"]:
            results["severity"] = "high"
        elif results["has_suspicious_comments"]:
            results["severity"] = "medium"
        
        return results


def test_hack_detector():
    """Test del detector de hackeos"""
    print("🧪 Testing Hack & Spam Detector...")
    
    detector = HackDetector()
    
    # Test 1: Sitio hackeado evidente
    html_hacked = """
    <html>
    <body>
        <h1>HACKED BY CYBER TEAM</h1>
        <p>This site has been hacked by Anonymous</p>
    </body>
    </html>
    """
    
    result1 = detector.detect(html_hacked, "http://example.com")
    print(f"\n✓ Test 1 - Hacked Site:")
    print(f"  Is hacked: {result1['is_hacked']}")
    print(f"  Severity: {result1['severity']}")
    print(f"  Indicators: {result1['hack_indicators']}")
    
    # Test 2: Spam SEO
    html_spam = """
    <html>
    <body>
        <h1>Normal Site</h1>
        <div style="display:none">
            Buy cheap viagra online casino poker best deals
        </div>
        <a href="/wp-content/plugins/casino-online-slots">Hidden link</a>
    </body>
    </html>
    """
    
    result2 = detector.detect(html_spam, "http://example.com")
    print(f"\n✓ Test 2 - SEO Spam:")
    print(f"  Has spam: {result2['has_spam_seo']}")
    print(f"  Severity: {result2['severity']}")
    print(f"  Spam indicators: {len(result2['spam_indicators'])}")
    print(f"  Hidden content: {len(result2['hidden_content'])}")
    
    # Test 3: Malware
    html_malware = """
    <script>
    eval(base64_decode('malicious code here'));
    </script>
    """
    
    result3 = detector.detect(html_malware, "http://example.com")
    print(f"\n✓ Test 3 - Malware:")
    print(f"  Has malware: {result3['has_malware']}")
    print(f"  Severity: {result3['severity']}")
    print(f"  Malware indicators: {len(result3['malware_indicators'])}")
    
    # Test 4: Sitio limpio
    html_clean = "<html><body><h1>Normal Website</h1><p>Regular content</p></body></html>"
    result4 = detector.detect(html_clean, "http://example.com")
    print(f"\n✓ Test 4 - Clean Site:")
    print(f"  Is hacked: {result4['is_hacked']}")
    print(f"  Has spam: {result4['has_spam_seo']}")
    print(f"  Has malware: {result4['has_malware']}")
    print(f"  Severity: {result4['severity']}")
    
    print("\n✅ Hack & Spam Detector tests completed!")
    return True


if __name__ == "__main__":
    test_hack_detector()
