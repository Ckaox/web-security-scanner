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
        (r"\b(?:casino|poker|slots)\b.*?\bonline\b", "casino spam"),
        (r"\b(?:viagra|cialis|levitra)\b", "pharma spam"),
        (r"\bpharmacy\b(?!.*?(?:farmacia|botica|apoteca))", "pharma spam"),
        (r"\bpayday\s+loans?\b", "payday loan spam"),
        (r"\b(?:buy|cheap)\b.*?\b(?:viagra|cialis)\b", "pharma spam"),
        (r"\bonline\s+(?:gambling|betting)\b", "gambling spam"),
    ]
    
    # Patrones sospechosos en WordPress
    WP_SUSPICIOUS_PATTERNS = [
        r"wp-content/[^\"'<>\s]{0,100}\b(?:casino|poker|viagra|cialis)\b",
        r"wp-includes/[^\"'<>\s]{0,100}\.php\?\w+=",
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
    # Nota: Google Maps API keys (AIza...) son públicas por diseño - se reportan como info, no crítico
    API_KEY_PATTERNS = [
        (r'api[_-]?key["\']?\s*[:=]\s*["\']((?!AIza)[a-zA-Z0-9_-]{20,})["\']', 'API Key'),
        (r'apikey["\']?\s*[:=]\s*["\']((?!AIza)[a-zA-Z0-9_-]{20,})["\']', 'API Key'),
        (r'secret[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{20,})["\']', 'Secret Key'),
        (r'access[_-]?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{20,})["\']', 'Access Token'),
        (r'auth[_-]?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{20,})["\']', 'Auth Token'),
        (r'sk_live_[a-zA-Z0-9]{20,}', 'Stripe Live Key'),
        (r'sk_test_[a-zA-Z0-9]{20,}', 'Stripe Test Key'),
        (r'AKIA[0-9A-Z]{16}', 'AWS Access Key'),
        (r'ghp_[a-zA-Z0-9]{36}', 'GitHub Personal Token'),
        (r'gho_[a-zA-Z0-9]{36}', 'GitHub OAuth Token'),
    ]
    
    # Patrones de API keys públicas (reportar como info, no crítico)
    PUBLIC_KEY_PATTERNS = [
        (r'AIza[0-9A-Za-z_-]{35}', 'Google Maps API Key (public)'),
        (r'pk_live_[a-zA-Z0-9]{20,}', 'Stripe Publishable Key (public)'),
        (r'pk_test_[a-zA-Z0-9]{20,}', 'Stripe Test Publishable Key (public)'),
    ]
    
    # Comentarios sospechosos en HTML (NUEVO - Fase 1)
    # Excluir comentarios condicionales de IE <!--[if...]>
    SUSPICIOUS_COMMENTS = [
        r'<!--(?!\[if).*?(?:password|passwd|pwd)\s*[:=].*?-->',
        r'<!--(?!\[if).*?(?:TODO|FIXME|HACK).*?(?:remove|delete|fix).*?-->',
        r'<!--(?!\[if).*?(?:debug|test)\s*(?:mode|enabled)\s*[:=].*?-->',
    ]
    
    def __init__(self):
        self.hack_regex = [re.compile(pattern, re.IGNORECASE) for pattern in self.HACK_PATTERNS]
        self.spam_regex = [(re.compile(pattern, re.IGNORECASE), label) for pattern, label in self.SPAM_SEO_PATTERNS]
        self.wp_regex = [re.compile(pattern, re.IGNORECASE) for pattern in self.WP_SUSPICIOUS_PATTERNS]
        self.malware_regex = [re.compile(pattern, re.IGNORECASE) for pattern in self.MALWARE_PATTERNS]
        self.api_key_regex = [(re.compile(pattern, re.IGNORECASE), label) for pattern, label in self.API_KEY_PATTERNS]
        self.public_key_regex = [(re.compile(pattern, re.IGNORECASE), label) for pattern, label in self.PUBLIC_KEY_PATTERNS]
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
            "has_public_keys": False,
            "has_suspicious_comments": False,
            "hack_indicators": [],
            "spam_indicators": [],
            "malware_indicators": [],
            "hidden_content": [],
            "exposed_keys": [],
            "public_keys": [],
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
                        key_value = match[0] if match[0] else (match[1] if len(match) > 1 else '')
                    else:
                        key_value = match
                    
                    if len(key_value) > 8:
                        masked = f"{key_value[:4]}...{key_value[-4:]}"
                    else:
                        masked = "***"
                    
                    key_info = f"{key_type}: {masked}"
                    if key_info not in results["exposed_keys"]:
                        results["exposed_keys"].append(key_info)
        
        # Detectar API keys públicas (info, no crítico - ej: Google Maps, Stripe Publishable)
        for regex, key_type in self.public_key_regex:
            matches = regex.findall(html_content)
            if matches:
                results["has_public_keys"] = True
                for match in matches[:3]:
                    key_value = match if isinstance(match, str) else match[0]
                    if len(key_value) > 8:
                        masked = f"{key_value[:4]}...{key_value[-4:]}"
                    else:
                        masked = "***"
                    key_info = f"{key_type}: {masked}"
                    if key_info not in results["public_keys"]:
                        results["public_keys"].append(key_info)
        
        # Detectar comentarios HTML sospechosos (NUEVO - Fase 1)
        # Primero extraer cada comentario individualmente, luego analizarlos
        comment_extractor = re.compile(r'<!--(.*?)-->', re.DOTALL)
        html_comments = comment_extractor.findall(html_content)
        
        # Patrones sospechosos dentro de comentarios individuales
        suspicious_in_comment = [
            re.compile(r'(?:password|passwd|pwd)\s*[:=]\s*\S+', re.IGNORECASE),
            re.compile(r'(?:TODO|FIXME|HACK).*?(?:remove|delete|fix)', re.IGNORECASE | re.DOTALL),
            re.compile(r'(?:debug|test)\s*(?:mode|enabled)\s*[:=]\s*(?:true|1|on)', re.IGNORECASE),
        ]
        
        for comment_text in html_comments[:50]:  # Limitar a 50 comentarios
            comment_text = comment_text.strip()
            if not comment_text or comment_text.startswith('[if'):
                continue  # Saltar comentarios condicionales de IE
            for pattern in suspicious_in_comment:
                if pattern.search(comment_text):
                    results["has_suspicious_comments"] = True
                    short_comment = f"<!--{comment_text[:80]}-->"
                    if short_comment not in results["suspicious_comments"]:
                        results["suspicious_comments"].append(short_comment)
                    break
        
        # Detectar contenido oculto (usando BeautifulSoup)
        try:
            soup = BeautifulSoup(html_content, 'lxml')
            
            # Buscar elementos con display:none que contengan spam keywords (con word boundaries)
            spam_keywords_regex = re.compile(r'\b(?:casino|poker|viagra|cialis|payday|loan)\b', re.IGNORECASE)
            hidden_elements = soup.find_all(style=re.compile(r'display\s*:\s*none', re.IGNORECASE))
            
            for element in hidden_elements[:5]:
                text = element.get_text()
                if spam_keywords_regex.search(text):
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
