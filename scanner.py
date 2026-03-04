"""
Scanner principal que combina todos los detectores
"""
import requests
from typing import Dict
import time
from urllib.parse import urlparse
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
# Suprimir warnings de SSL
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

# Importar todos los detectores
from detector_php_errors import PHPErrorDetector
from detector_hack_spam import HackDetector
from detector_ssl_seo import SSLSEODetector
from detector_cms_placeholder import CMSPlaceholderDetector
from detector_sensitive_info import SensitiveInfoDetector


class WebScanner:
    """Scanner principal que ejecuta todas las verificaciones"""
    
    def __init__(self, timeout=10, user_agent=None, enable_phase2=True):
        """
        Args:
            timeout: Timeout para requests HTTP (segundos)
            user_agent: User agent personalizado
            enable_phase2: Habilitar escaneos de Fase 2 (más intensivo)
        """
        self.timeout = timeout
        self.user_agent = user_agent or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        self.enable_phase2 = enable_phase2
        
        # Inicializar detectores
        self.php_detector = PHPErrorDetector()
        self.hack_detector = HackDetector()
        self.ssl_seo_detector = SSLSEODetector()
        self.cms_detector = CMSPlaceholderDetector()
        self.sensitive_detector = SensitiveInfoDetector(timeout=5, user_agent=self.user_agent)
    
    def _detect_maintenance_mode(self, status_code: int, html_content: str) -> Dict:
        """
        Detecta si el sitio está en modo mantenimiento
        
        Args:
            status_code: Código HTTP de la respuesta
            html_content: Contenido HTML de la página
            
        Returns:
            Dict con información de modo mantenimiento
        """
        import re
        result = {
            "is_maintenance": False,
            "indicators": [],
            "severity": "none"
        }
        
        # Verificar por código HTTP
        if status_code in [503, 502]:
            result["is_maintenance"] = True
            result["indicators"].append(f"HTTP {status_code} - Service Unavailable")
        
        # Verificar por contenido HTML (tanto en español como en inglés)
        html_lower = html_content.lower() if html_content else ""
        
        maintenance_patterns = [
            (r'\bcoming\s+soon\b', 'Coming soon page'),
            (r'\bunder\s+construction\b', 'Under construction'),
            (r'\bunder\s+maintenance\b', 'Under maintenance'),
            (r'\btemporarily\s+unavailable\b', 'Temporarily unavailable'),
            (r'\bmaintenance\s+mode\b', 'Maintenance mode active'),
            (r'\ben\s+(?:modo\s+)?mantenimiento\b', 'En mantenimiento'),
            (r'\ben\s+construcci[oó]n\b', 'En construcción'),
            (r'\bpr[oó]ximamente\b', 'Próximamente'),
            (r'\bsitio\s+en\s+(?:mantenimiento|construcci[oó]n)\b', 'Sitio en mantenimiento'),
            (r'\bwe(?:\x27|&#39;)?re\s+(?:currently\s+)?(?:updating|redesigning|working)\b', 'Site being updated'),
            (r'\bsite\s+is\s+(?:currently\s+)?(?:down|offline|unavailable)\b', 'Site offline'),
            (r'\bvolver[eá]\s+pronto\b', 'Volverá pronto'),
            (r'\bwp-maintenance-mode\b', 'WordPress maintenance mode plugin'),
        ]
        
        for pattern, description in maintenance_patterns:
            if re.search(pattern, html_lower):
                result["is_maintenance"] = True
                if description not in result["indicators"]:
                    result["indicators"].append(description)
        
        if result["is_maintenance"]:
            result["severity"] = "high"
        
        return result
    
    def fetch_url(self, url: str) -> Dict:
        """
        Hace request a la URL y obtiene el contenido
        
        Returns:
            Dict con status, headers, content, etc.
        """
        result = {
            "success": False,
            "status_code": None,
            "content": "",
            "headers": {},
            "response_time": 0,
            "error": None,
            "final_url": url,
        }
        
        try:
            # Asegurar que la URL tenga esquema
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            headers = {'User-Agent': self.user_agent}
            
            start_time = time.time()
            response = requests.get(
                url, 
                headers=headers, 
                timeout=self.timeout,
                allow_redirects=True,
                verify=False  # Permitir SSL inválido para detectar problemas
            )
            result["response_time"] = time.time() - start_time
            
            result["success"] = True
            result["status_code"] = response.status_code
            result["content"] = response.text
            result["headers"] = dict(response.headers)
            result["final_url"] = response.url
            
        except requests.exceptions.Timeout:
            result["error"] = "Request timeout"
        except requests.exceptions.ConnectionError:
            result["error"] = "Connection error"
        except requests.exceptions.RequestException as e:
            result["error"] = f"Request error: {str(e)[:100]}"
        except Exception as e:
            result["error"] = f"Unexpected error: {str(e)[:100]}"
        
        return result
    
    def scan(self, url: str) -> Dict:
        """
        Escanea una URL completa con todos los detectores
        
        Args:
            url: URL a escanear
            
        Returns:
            Dict con todos los resultados del escaneo
        """
        scan_result = {
            "url": url,
            "scan_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "scan_duration": 0,
            "fetch_info": {},
            "overall_severity": "none",  # none, low, medium, high, critical
            "issues_summary": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "total": 0
            },
            "results": {
                "php_errors": {},
                "security": {},
                "ssl": {},
                "sensitive_info": {},  # Fase 2
                "seo": {},
                "cms": {},
                "placeholder": {},
                "maintenance_mode": {},
            }
        }
        
        start_time = time.time()
        
        # 1. Fetch URL
        print(f"🔍 Fetching {url}...")
        fetch_result = self.fetch_url(url)
        scan_result["fetch_info"] = {
            "success": fetch_result["success"],
            "status_code": fetch_result["status_code"],
            "response_time": round(fetch_result["response_time"], 2),
            "error": fetch_result["error"],
            "final_url": fetch_result["final_url"]
        }
        
        if not fetch_result["success"]:
            scan_result["scan_duration"] = round(time.time() - start_time, 2)
            scan_result["overall_severity"] = "critical"
            scan_result["issues_summary"]["critical"] = 1
            scan_result["issues_summary"]["total"] = 1
            return scan_result
        
        html_content = fetch_result["content"]
        final_url = fetch_result["final_url"]
        
        # 1b. Detectar modo mantenimiento
        print("  ✓ Checking maintenance mode...")
        scan_result["results"]["maintenance_mode"] = self._detect_maintenance_mode(
            fetch_result["status_code"], html_content
        )
        
        # 2. Detectar errores PHP
        print("  ✓ Checking PHP errors...")
        scan_result["results"]["php_errors"] = self.php_detector.detect(html_content, final_url)
        
        # 3. Detectar hackeos y spam
        print("  ✓ Checking security threats...")
        scan_result["results"]["security"] = self.hack_detector.detect(html_content, final_url)
        
        # 4. Verificar SSL
        print("  ✓ Checking SSL...")
        scan_result["results"]["ssl"] = self.ssl_seo_detector.detect_ssl_issues(
            final_url, 
            fetch_result["headers"]
        )
        
        # 4b. Verificar contenido mixto
        if self.ssl_seo_detector.detect_mixed_content(html_content, final_url):
            scan_result["results"]["ssl"]["has_mixed_content"] = True
            scan_result["results"]["ssl"]["issues"].append("Mixed content detected (HTTP resources on HTTPS page)")
            if scan_result["results"]["ssl"]["severity"] == "none":
                scan_result["results"]["ssl"]["severity"] = "medium"
        
        # 5. Análisis SEO
        print("  ✓ Analyzing SEO...")
        scan_result["results"]["seo"] = self.ssl_seo_detector.analyze_seo(html_content, final_url)
        
        # 6. Detectar CMS
        print("  ✓ Detecting CMS...")
        cms_results = self.cms_detector.detect_all(html_content, final_url)
        scan_result["results"]["cms"] = cms_results["wordpress"]
        scan_result["results"]["cms"]["other_cms"] = cms_results["other_cms"]
        scan_result["results"]["cms"]["js_libraries"] = cms_results["js_libraries"]
        scan_result["results"]["placeholder"] = cms_results["placeholder"]
        
        # 7. FASE 2 - Detectar información sensible (opcional, más intensivo)
        if self.enable_phase2:
            print("  ✓ Scanning for sensitive files (Phase 2)...")
            sensitive_results = self.sensitive_detector.detect_all(final_url)
            scan_result["results"]["sensitive_info"] = sensitive_results
        
        # 8. Calcular resumen de severidad
        severities = {
            "php_errors": scan_result["results"]["php_errors"].get("severity", "none"),
            "security": scan_result["results"]["security"].get("severity", "none"),
            "ssl": scan_result["results"]["ssl"].get("severity", "none"),
            "seo": scan_result["results"]["seo"].get("severity", "none"),
            "placeholder": scan_result["results"]["placeholder"].get("severity", "none"),
            "maintenance_mode": scan_result["results"]["maintenance_mode"].get("severity", "none"),
        }
        
        # Agregar severidades de Fase 2 si está habilitada
        if self.enable_phase2 and scan_result["results"]["sensitive_info"]:
            sensitive_info = scan_result["results"]["sensitive_info"]
            if "sensitive_files" in sensitive_info:
                severities["sensitive_files"] = sensitive_info["sensitive_files"].get("severity", "none")
            if "directory_listing" in sensitive_info:
                severities["directory_listing"] = sensitive_info["directory_listing"].get("severity", "none")
            if "install_files" in sensitive_info:
                severities["install_files"] = sensitive_info["install_files"].get("severity", "none")
            if "admin_panels" in sensitive_info:
                severities["admin_panels"] = sensitive_info["admin_panels"].get("severity", "none")
            if "log_files" in sensitive_info:
                severities["log_files"] = sensitive_info["log_files"].get("severity", "none")
            if "robots_analysis" in sensitive_info:
                severities["robots_analysis"] = sensitive_info["robots_analysis"].get("severity", "none")
        
        # Contar issues por severidad
        severity_priority = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}
        
        for severity in severities.values():
            if severity != "none":
                scan_result["issues_summary"][severity] += 1
                scan_result["issues_summary"]["total"] += 1
        
        # Determinar severidad general (la más alta encontrada)
        max_severity = "none"
        max_priority = 0
        for severity in severities.values():
            if severity_priority.get(severity, 0) > max_priority:
                max_priority = severity_priority[severity]
                max_severity = severity
        
        scan_result["overall_severity"] = max_severity
        scan_result["scan_duration"] = round(time.time() - start_time, 2)
        
        return scan_result
    
    def print_summary(self, scan_result: Dict):
        """Imprime un resumen legible de los resultados"""
        print("\n" + "="*70)
        print(f"📊 SCAN SUMMARY: {scan_result['url']}")
        print("="*70)
        
        # Estado general
        severity_emoji = {
            "none": "✅",
            "low": "⚠️",
            "medium": "⚠️",
            "high": "🔴",
            "critical": "🚨"
        }
        
        emoji = severity_emoji.get(scan_result["overall_severity"], "❓")
        print(f"\n{emoji} Overall Severity: {scan_result['overall_severity'].upper()}")
        print(f"⏱️  Scan Duration: {scan_result['scan_duration']}s")
        print(f"📈 Response Time: {scan_result['fetch_info']['response_time']}s")
        print(f"🔢 HTTP Status: {scan_result['fetch_info']['status_code']}")
        
        # Resumen de issues
        summary = scan_result["issues_summary"]
        if summary["total"] > 0:
            print(f"\n🔍 Issues Found: {summary['total']}")
            if summary["critical"] > 0:
                print(f"   🚨 Critical: {summary['critical']}")
            if summary["high"] > 0:
                print(f"   🔴 High: {summary['high']}")
            if summary["medium"] > 0:
                print(f"   ⚠️  Medium: {summary['medium']}")
            if summary["low"] > 0:
                print(f"   ℹ️  Low: {summary['low']}")
        else:
            print("\n✅ No critical issues found")
        
        # Detalles por categoría
        results = scan_result["results"]
        
        # Maintenance Mode
        if results.get("maintenance_mode", {}).get("is_maintenance"):
            print(f"\n\U0001f6a7 MAINTENANCE MODE DETECTED:")
            for indicator in results["maintenance_mode"]["indicators"]:
                print(f"   - {indicator}")
            print(f"   ⚠️  Results may be incomplete - site is not serving normal content")
        
        # PHP Errors
        if results["php_errors"]["has_errors"]:
            print(f"\n🔴 PHP/DATABASE ERRORS:")
            if results["php_errors"]["php_errors"]:
                print(f"   - PHP errors found: {len(results['php_errors']['php_errors'])}")
                for error in results["php_errors"]["php_errors"][:2]:
                    print(f"     • {error[:80]}...")
            if results["php_errors"]["db_errors"]:
                print(f"   - Database errors found: {len(results['php_errors']['db_errors'])}")
        
        # Security
        if results["security"]["is_hacked"] or results["security"]["has_spam_seo"] or results["security"]["has_malware"]:
            print(f"\n🚨 SECURITY ISSUES:")
            if results["security"]["is_hacked"]:
                print(f"   🚨 SITE APPEARS TO BE HACKED!")
                for indicator in results["security"]["hack_indicators"][:2]:
                    print(f"     • {indicator}")
            if results["security"]["has_malware"]:
                print(f"   ⚠️  Malware code detected")
            if results["security"]["has_spam_seo"]:
                print(f"   ⚠️  Spam SEO injection detected: {len(results['security']['spam_indicators'])} indicators")
        
        # API Keys expuestas (NUEVO - Fase 1)
        if results["security"].get("has_exposed_keys"):
            print(f"\n🚨 API KEYS / TOKENS EXPOSED IN CODE (CRITICAL):")
            for key_info in results["security"]["exposed_keys"][:5]:
                print(f"   🚨 {key_info}")
                # API Keys públicas (informativo)
        if results["security"].get("has_public_keys"):
            print(f"\n\u2139\ufe0f  PUBLIC API KEYS IN CODE (informational):")
            for key_info in results["security"]["public_keys"][:5]:
                print(f"   - {key_info}")
                # Comentarios sospechosos (NUEVO - Fase 1)
        if results["security"].get("has_suspicious_comments"):
            print(f"\n⚠️  SUSPICIOUS COMMENTS IN HTML:")
            for comment in results["security"]["suspicious_comments"][:3]:
                print(f"   - {comment}")
        
        # SSL / Certificate
        ssl_data = results["ssl"]
        if ssl_data.get("has_https") and ssl_data.get("has_valid_certificate"):
            cert = ssl_data.get("certificate", {})
            print(f"\n\U0001f512 SSL CERTIFICATE: \u2705 Valid")
            if cert.get("issuer"):
                print(f"   Issuer: {cert['issuer']}")
            if cert.get("expires"):
                days = cert.get('days_remaining', '?')
                print(f"   Expires: {cert['expires']} ({days} days remaining)")
        elif ssl_data.get("has_https"):
            print(f"\n\U0001f512 SSL CERTIFICATE: \u26a0\ufe0f  Problem detected")
        else:
            print(f"\n\U0001f512 SSL CERTIFICATE: \U0001f534 Site not using HTTPS")
        
        if ssl_data["issues"]:
            for issue in ssl_data["issues"][:3]:
                print(f"   \U0001f534 {issue}")
        
        if ssl_data.get("missing_headers"):
            print(f"\n\U0001f6e1\ufe0f  SECURITY HEADERS (informational):")
            for header in ssl_data["missing_headers"][:3]:
                print(f"   - {header}")
        
        # SEO
        if results["seo"]["issues"]:
            print(f"\n📈 SEO ISSUES ({len(results['seo']['issues'])}):")
            for issue in results["seo"]["issues"][:5]:
                print(f"   - {issue}")
        
        # CMS
        if results["cms"]["is_wordpress"]:
            print(f"\n🔧 CMS DETECTED:")
            print(f"   - WordPress {results['cms']['version'] or 'version unknown'}")
            if results["cms"]["is_outdated"]:
                print(f"   ⚠️  WordPress version is OUTDATED")
            if results["cms"]["plugins_detected"]:
                print(f"   - Plugins detected: {len(results['cms']['plugins_detected'])}")
        
        # Información sensible (Fase 2)
        if results.get("sensitive_info"):
            sensitive = results["sensitive_info"]
            
            if "sensitive_files" in sensitive and sensitive["sensitive_files"]["accessible_files"]:
                print(f"\n🚨 SENSITIVE FILES EXPOSED (Phase 2):")
                for file_info in sensitive["sensitive_files"]["sensitive_files"]:
                    print(f"   🚨 {file_info['file']} ({file_info['size']} bytes)")
                if sensitive["sensitive_files"]["accessible_files"]:
                    other_files = [f for f in sensitive["sensitive_files"]["accessible_files"] 
                                   if not any(f == sf["file"] for sf in sensitive["sensitive_files"]["sensitive_files"])]
                    if other_files:
                        print(f"   ⚠️  Other accessible files: {', '.join(other_files[:3])}")
            
            if "directory_listing" in sensitive and sensitive["directory_listing"]["exposed_directories"]:
                print(f"\n⚠️  DIRECTORY LISTING ENABLED:")
                for dir_info in sensitive["directory_listing"]["exposed_directories"]:
                    print(f"   - /{dir_info['directory']}/ ({dir_info['file_count']} files)")
            
            if "install_files" in sensitive and sensitive["install_files"]["install_files_found"]:
                print(f"\n🚨 INSTALLATION FILES FOUND (CRITICAL):")
                for install in sensitive["install_files"]["install_files_found"]:
                    print(f"   🚨 {install['file']} - Allows site reinstallation!")
            
            if "admin_panels" in sensitive and sensitive["admin_panels"]["accessible_panels"]:
                print(f"\n⚠️  ADMIN PANELS ACCESSIBLE:")
                for panel in sensitive["admin_panels"]["accessible_panels"][:5]:
                    print(f"   - {panel['panel']} (HTTP {panel['status']})")
            
            if "log_files" in sensitive and sensitive["log_files"]["exposed_logs"]:
                print(f"\n🚨 LOG FILES EXPOSED:")
                for log in sensitive["log_files"]["exposed_logs"]:
                    print(f"   🚨 {log['file']} ({log['size']} bytes) - May contain sensitive info")
            
            if "robots_analysis" in sensitive and sensitive["robots_analysis"]["accessible_disallowed"]:
                print(f"\n⚠️  ROBOTS.TXT ANALYSIS:")
                print(f"   Disallowed paths found: {len(sensitive['robots_analysis']['disallowed_paths'])}")
                print(f"   ⚠️  Accessible disallowed paths: {len(sensitive['robots_analysis']['accessible_disallowed'])}")
                for path_info in sensitive["robots_analysis"]["accessible_disallowed"][:3]:
                    print(f"     - {path_info['path']}")
        
        # Placeholder
        if results["placeholder"]["has_placeholder"]:
            print(f"\n📝 PLACEHOLDER CONTENT:")
            print(f"   - Placeholder texts: {len(results['placeholder']['placeholder_texts'])}")
            print(f"   - Placeholder images: {len(results['placeholder']['placeholder_images'])}")
        
        if results["placeholder"]["is_copyright_outdated"]:
            print(f"   - Outdated copyright: {results['placeholder']['copyright_year']}")
        
        print("\n" + "="*70)


def test_real_url():
    """Test con una URL real"""
    print("🧪 Testing with real URLs...\n")
    
    scanner = WebScanner(timeout=15)
    
    # URLs de prueba (podemos usar ejemplo.com o test.com)
    test_urls = [
        "httpbin.org/html",  # URL de prueba que responde con HTML
    ]
    
    for url in test_urls:
        print(f"\n{'='*70}")
        print(f"Testing: {url}")
        print('='*70)
        
        result = scanner.scan(url)
        scanner.print_summary(result)
        
        print("\n")


if __name__ == "__main__":
    test_real_url()
