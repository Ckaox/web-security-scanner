"""
Detector de CMS desactualizado y contenido placeholder
"""
import re
from typing import Dict
from bs4 import BeautifulSoup
from datetime import datetime

class CMSPlaceholderDetector:
    """Detecta CMS desactualizados y contenido placeholder"""
    
    # Patrones de detección de WordPress
    WP_VERSION_PATTERNS = [
        (r'<meta name="generator" content="WordPress ([\d.]+)"', 'meta_generator'),
        (r'wp-includes/js/.*?ver=([\d.]+)', 'script_version'),
        (r'/wp-content/themes/.*?/style\.css\?ver=([\d.]+)', 'theme_version'),
    ]
    
    # Patrones para detectar otros CMS
    CMS_PATTERNS = {
        'Joomla': r'<meta name="generator" content="Joomla! ([\d.]+)',
        'Drupal': r'<meta name="generator" content="Drupal ([\d.]+)',
        'Shopify': r'Shopify\.theme|shopify-section',
        'Wix': r'wix\.com|wixstatic\.com',
        'Squarespace': r'squarespace',
    }
    
    # Librerías JavaScript comunes
    JS_LIBRARIES = {
        'jQuery': r'jquery[.-]([\d.]+)(?:\.min)?\.js',
        'Bootstrap': r'bootstrap[.-]([\d.]+)(?:\.min)?\.(?:js|css)',
        'Font Awesome': r'font-awesome[/-]([\d.]+)',
    }
    
    # Patrones de contenido placeholder
    PLACEHOLDER_PATTERNS = [
        r'lorem\s+ipsum',
        r'dolor\s+sit\s+amet',
        r'consectetur\s+adipiscing',
        r'coming\s+soon',
        r'under\s+construction',
        r'website\s+under\s+construction',
        r'site\s+under\s+maintenance',
        r'placeholder\s+(?:text|image|content)',
        r'this\s+is\s+(?:a\s+)?(?:test|sample|demo)',
        r'default\s+(?:page|content|text)',
        r'example\.(?:com|jpg|png)',
    ]
    
    # URLs placeholder comunes
    PLACEHOLDER_URLS = [
        'placeholder.com',
        'via.placeholder.com',
        'placehold.it',
        'dummyimage.com',
        'lorempixel.com',
        'unsplash.it',
    ]
    
    def __init__(self):
        self.placeholder_regex = [re.compile(pattern, re.IGNORECASE) for pattern in self.PLACEHOLDER_PATTERNS]
    
    def detect_wordpress(self, html_content: str, url: str) -> Dict:
        """Detecta WordPress y su versión"""
        result = {
            "is_wordpress": False,
            "version": None,
            "detection_method": None,
            "is_outdated": False,
            "plugins_detected": [],
            "theme_detected": None
        }
        
        # Buscar indicadores de WordPress
        wp_indicators = [
            '/wp-content/',
            '/wp-includes/',
            'wordpress',
            '/wp-json/',
        ]
        
        for indicator in wp_indicators:
            if indicator in html_content.lower():
                result["is_wordpress"] = True
                break
        
        if not result["is_wordpress"]:
            return result
        
        # Detectar versión
        for pattern, method in self.WP_VERSION_PATTERNS:
            match = re.search(pattern, html_content, re.IGNORECASE)
            if match:
                result["version"] = match.group(1)
                result["detection_method"] = method
                break
        
        # Detectar plugins (buscar en wp-content/plugins/)
        plugin_matches = re.findall(r'/wp-content/plugins/([^/\'"?]+)', html_content, re.IGNORECASE)
        result["plugins_detected"] = list(set(plugin_matches))[:10]  # Limitar a 10
        
        # Detectar tema
        theme_match = re.search(r'/wp-content/themes/([^/\'"?]+)', html_content, re.IGNORECASE)
        if theme_match:
            result["theme_detected"] = theme_match.group(1)
        
        # Verificar si está desactualizado (versión < 6.0 es antigua en 2026)
        if result["version"]:
            try:
                major_version = float('.'.join(result["version"].split('.')[:2]))
                if major_version < 6.0:
                    result["is_outdated"] = True
            except:
                pass
        
        return result
    
    def detect_cms(self, html_content: str, url: str) -> Dict:
        """Detecta otros CMS"""
        result = {
            "cms_detected": None,
            "version": None,
            "confidence": "none"  # none, low, medium, high
        }
        
        for cms_name, pattern in self.CMS_PATTERNS.items():
            match = re.search(pattern, html_content, re.IGNORECASE)
            if match:
                result["cms_detected"] = cms_name
                result["confidence"] = "high"
                # Intentar extraer versión si está en el grupo 1
                try:
                    result["version"] = match.group(1)
                except:
                    pass
                break
        
        return result
    
    def detect_js_libraries(self, html_content: str) -> Dict:
        """Detecta librerías JavaScript y sus versiones"""
        result = {
            "libraries": {},
            "outdated_libraries": []
        }
        
        for lib_name, pattern in self.JS_LIBRARIES.items():
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            if matches:
                # Tomar la primera versión encontrada
                version = matches[0]
                result["libraries"][lib_name] = version
                
                # Verificar si está desactualizado
                if lib_name == "jQuery":
                    try:
                        major_version = float('.'.join(version.split('.')[:2]))
                        if major_version < 3.0:
                            result["outdated_libraries"].append(f"{lib_name} {version} (current: 3.x)")
                    except:
                        pass
        
        return result
    
    def detect_placeholder_content(self, html_content: str, url: str) -> Dict:
        """Detecta contenido placeholder"""
        result = {
            "has_placeholder": False,
            "placeholder_texts": [],
            "placeholder_images": [],
            "copyright_year": None,
            "is_copyright_outdated": False,
            "severity": "none"
        }
        
        try:
            # Buscar texto placeholder
            for regex in self.placeholder_regex:
                matches = regex.findall(html_content)
                if matches:
                    result["has_placeholder"] = True
                    for match in matches[:3]:
                        if len(match) > 10 and match not in result["placeholder_texts"]:
                            result["placeholder_texts"].append(match[:100])
            
            # Buscar imágenes placeholder
            soup = BeautifulSoup(html_content, 'lxml')
            images = soup.find_all('img')
            
            for img in images:
                src = img.get('src', '') + img.get('data-src', '')
                if any(placeholder in src.lower() for placeholder in self.PLACEHOLDER_URLS):
                    result["has_placeholder"] = True
                    result["placeholder_images"].append(src[:100])
            
            # Detectar copyright desactualizado
            copyright_pattern = r'©?\s*(?:copyright\s+)?(?:©\s*)?(\d{4})(?:\s*-\s*(\d{4}))?'
            copyright_matches = re.findall(copyright_pattern, html_content, re.IGNORECASE)
            
            current_year = datetime.now().year
            
            for match in copyright_matches:
                year = match[1] if match[1] else match[0]  # Usar el año final si hay rango
                try:
                    year_int = int(year)
                    if year_int > 2000 and year_int <= current_year:
                        result["copyright_year"] = year_int
                        if year_int < current_year - 1:  # Más de 1 año desactualizado
                            result["is_copyright_outdated"] = True
                        break
                except:
                    pass
            
            # Determinar severidad
            if result["has_placeholder"]:
                if len(result["placeholder_texts"]) > 3 or len(result["placeholder_images"]) > 2:
                    result["severity"] = "high"
                else:
                    result["severity"] = "medium"
            elif result["is_copyright_outdated"]:
                result["severity"] = "low"
                
        except Exception as e:
            pass
        
        return result
    
    def detect_all(self, html_content: str, url: str) -> Dict:
        """Ejecuta todas las detecciones"""
        return {
            "wordpress": self.detect_wordpress(html_content, url),
            "other_cms": self.detect_cms(html_content, url),
            "js_libraries": self.detect_js_libraries(html_content),
            "placeholder": self.detect_placeholder_content(html_content, url),
        }


def test_cms_placeholder_detector():
    """Test del detector de CMS y placeholder"""
    print("🧪 Testing CMS & Placeholder Detector...")
    
    detector = CMSPlaceholderDetector()
    
    # Test 1: WordPress detectado
    html_wp = """
    <html>
    <head>
        <meta name="generator" content="WordPress 5.8.1" />
        <link rel='stylesheet' href='/wp-content/themes/twentytwenty/style.css?ver=1.0' />
        <script src='/wp-includes/js/jquery/jquery.min.js?ver=3.5.1'></script>
    </head>
    <body>
        <div class="wp-content">Content here</div>
    </body>
    </html>
    """
    
    print("\n✓ Test 1 - WordPress Detection:")
    result1 = detector.detect_wordpress(html_wp, "https://example.com")
    print(f"  Is WordPress: {result1['is_wordpress']}")
    print(f"  Version: {result1['version']}")
    print(f"  Is outdated: {result1['is_outdated']}")
    print(f"  Detection method: {result1['detection_method']}")
    print(f"  Theme: {result1['theme_detected']}")
    
    # Test 2: Librerías JS
    print("\n✓ Test 2 - JS Libraries:")
    result2 = detector.detect_js_libraries(html_wp)
    print(f"  Libraries found: {result2['libraries']}")
    print(f"  Outdated: {result2['outdated_libraries']}")
    
    # Test 3: Contenido placeholder
    html_placeholder = """
    <html>
    <head><title>Coming Soon</title></head>
    <body>
        <h1>Website Under Construction</h1>
        <p>Lorem ipsum dolor sit amet, consectetur adipiscing elit.</p>
        <img src="https://via.placeholder.com/300">
        <img src="https://placehold.it/400x300">
        <footer>© Copyright 2022 Example Inc</footer>
    </body>
    </html>
    """
    
    print("\n✓ Test 3 - Placeholder Content:")
    result3 = detector.detect_placeholder_content(html_placeholder, "https://example.com")
    print(f"  Has placeholder: {result3['has_placeholder']}")
    print(f"  Placeholder texts: {len(result3['placeholder_texts'])}")
    print(f"  Placeholder images: {len(result3['placeholder_images'])}")
    print(f"  Copyright year: {result3['copyright_year']}")
    print(f"  Copyright outdated: {result3['is_copyright_outdated']}")
    print(f"  Severity: {result3['severity']}")
    
    # Test 4: Sitio limpio
    html_clean = """
    <html>
    <head>
        <title>Professional Website</title>
        <script src="https://cdn.example.com/app-bundle.js"></script>
    </head>
    <body>
        <h1>Welcome to Our Company</h1>
        <p>We provide professional services.</p>
        <footer>© 2026 Our Company</footer>
    </body>
    </html>
    """
    
    print("\n✓ Test 4 - Clean Site:")
    result4 = detector.detect_placeholder_content(html_clean, "https://example.com")
    print(f"  Has placeholder: {result4['has_placeholder']}")
    print(f"  Copyright year: {result4['copyright_year']}")
    print(f"  Copyright outdated: {result4['is_copyright_outdated']}")
    print(f"  Severity: {result4['severity']}")
    
    # Test 5: Detección completa
    print("\n✓ Test 5 - Complete Detection:")
    result5 = detector.detect_all(html_wp, "https://example.com")
    print(f"  WordPress detected: {result5['wordpress']['is_wordpress']}")
    print(f"  Libraries: {list(result5['js_libraries']['libraries'].keys())}")
    
    print("\n✅ CMS & Placeholder Detector tests completed!")
    return True


if __name__ == "__main__":
    test_cms_placeholder_detector()
