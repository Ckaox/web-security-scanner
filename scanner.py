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
            scan_result["suggestions"] = self.generate_suggestions(scan_result)
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
        
        # 9. Generar sugerencias accionables
        scan_result["suggestions"] = self.generate_suggestions(scan_result)
        
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
        
        # Si el fetch falló, los dicts estarán vacíos - salir temprano
        if not scan_result["fetch_info"].get("success"):
            error_msg = scan_result["fetch_info"].get("error", "Unknown error")
            print(f"\n🚨 FETCH FAILED: {error_msg}")
            print(f"   Cannot analyze site - connection failed.")
            
            suggestions = scan_result.get("suggestions", [])
            if suggestions:
                print(f"\n{'─'*70}")
                print(f"💡 RECOMMENDATIONS ({len(suggestions)}):")
                print(f"{'─'*70}")
                for sug in suggestions:
                    icon = {"critical": "🚨", "high": "🔴", "medium": "⚠️", "low": "ℹ️"}.get(sug.get("priority", ""), "•")
                    print(f"   {icon} {sug['text']}")
            
            print("\n" + "="*70)
            return
        
        # Maintenance Mode
        if results.get("maintenance_mode", {}).get("is_maintenance"):
            print(f"\n\U0001f6a7 MAINTENANCE MODE DETECTED:")
            for indicator in results["maintenance_mode"]["indicators"]:
                print(f"   - {indicator}")
            print(f"   ⚠️  Results may be incomplete - site is not serving normal content")
        
        # PHP Errors
        php = results.get("php_errors", {})
        if php.get("has_errors"):
            print(f"\n🔴 PHP/DATABASE ERRORS:")
            if php.get("php_errors"):
                print(f"   - PHP errors found: {len(php['php_errors'])}")
                for error in php["php_errors"][:2]:
                    print(f"     • {error[:80]}...")
            if php.get("db_errors"):
                print(f"   - Database errors found: {len(php['db_errors'])}")
        
        # Security
        sec = results.get("security", {})
        if sec.get("is_hacked") or sec.get("has_spam_seo") or sec.get("has_malware"):
            print(f"\n🚨 SECURITY ISSUES:")
            if sec.get("is_hacked"):
                print(f"   🚨 SITE APPEARS TO BE HACKED!")
                for indicator in sec.get("hack_indicators", [])[:2]:
                    print(f"     • {indicator}")
            if sec.get("has_malware"):
                print(f"   ⚠️  Malware code detected")
            if sec.get("has_spam_seo"):
                print(f"   ⚠️  Spam SEO injection detected: {len(sec.get('spam_indicators', []))} indicators")
        
        # API Keys expuestas
        if sec.get("has_exposed_keys"):
            print(f"\n🚨 API KEYS / TOKENS EXPOSED IN CODE (CRITICAL):")
            for key_info in sec.get("exposed_keys", [])[:5]:
                print(f"   🚨 {key_info}")
        # API Keys públicas (informativo)
        if sec.get("has_public_keys"):
            print(f"\n\u2139\ufe0f  PUBLIC API KEYS IN CODE (informational):")
            for key_info in sec.get("public_keys", [])[:5]:
                print(f"   - {key_info}")
        # Comentarios sospechosos
        if sec.get("has_suspicious_comments"):
            print(f"\n⚠️  SUSPICIOUS COMMENTS IN HTML:")
            for comment in sec.get("suspicious_comments", [])[:3]:
                print(f"   - {comment}")
        
        # SSL / Certificate
        ssl_data = results.get("ssl", {})
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
        elif ssl_data:
            print(f"\n\U0001f512 SSL CERTIFICATE: \U0001f534 Site not using HTTPS")
        
        if ssl_data.get("issues"):
            for issue in ssl_data["issues"][:3]:
                print(f"   \U0001f534 {issue}")
        
        if ssl_data.get("missing_headers"):
            print(f"\n\U0001f6e1\ufe0f  SECURITY HEADERS (informational):")
            for header in ssl_data["missing_headers"][:3]:
                print(f"   - {header}")
        
        # SEO
        seo = results.get("seo", {})
        if seo.get("issues"):
            print(f"\n📈 SEO ISSUES ({len(seo['issues'])}):")
            for issue in seo["issues"][:5]:
                print(f"   - {issue}")
        
        # CMS
        cms = results.get("cms", {})
        if cms.get("is_wordpress"):
            print(f"\n🔧 CMS DETECTED:")
            print(f"   - WordPress {cms.get('version') or 'version unknown'}")
            if cms.get("is_outdated"):
                print(f"   ⚠️  WordPress version is OUTDATED")
            if cms.get("plugins_detected"):
                print(f"   - Plugins detected: {len(cms['plugins_detected'])}")
        
        # Información sensible (Fase 2)
        if results.get("sensitive_info"):
            sensitive = results["sensitive_info"]
            
            sf = sensitive.get("sensitive_files", {})
            if sf.get("accessible_files"):
                print(f"\n🚨 SENSITIVE FILES EXPOSED (Phase 2):")
                for file_info in sf.get("sensitive_files", []):
                    print(f"   🚨 {file_info['file']} ({file_info['size']} bytes)")
                other_files = [f for f in sf["accessible_files"] 
                               if not any(f == sfi["file"] for sfi in sf.get("sensitive_files", []))]
                if other_files:
                    print(f"   ⚠️  Other accessible files: {', '.join(other_files[:3])}")
            
            dl = sensitive.get("directory_listing", {})
            if dl.get("exposed_directories"):
                print(f"\n⚠️  DIRECTORY LISTING ENABLED:")
                for dir_info in dl["exposed_directories"]:
                    print(f"   - /{dir_info['directory']}/ ({dir_info['file_count']} files)")
            
            inst = sensitive.get("install_files", {})
            if inst.get("install_files_found"):
                print(f"\n🚨 INSTALLATION FILES FOUND (CRITICAL):")
                for install in inst["install_files_found"]:
                    print(f"   🚨 {install['file']} - Allows site reinstallation!")
            
            ap = sensitive.get("admin_panels", {})
            if ap.get("accessible_panels"):
                print(f"\n⚠️  ADMIN PANELS ACCESSIBLE:")
                for panel in ap["accessible_panels"][:5]:
                    print(f"   - {panel['panel']} (HTTP {panel['status']})")
            
            lf = sensitive.get("log_files", {})
            if lf.get("exposed_logs"):
                print(f"\n🚨 LOG FILES EXPOSED:")
                for log in lf["exposed_logs"]:
                    print(f"   🚨 {log['file']} ({log['size']} bytes) - May contain sensitive info")
            
            ra = sensitive.get("robots_analysis", {})
            if ra.get("accessible_disallowed"):
                print(f"\n⚠️  ROBOTS.TXT ANALYSIS:")
                print(f"   Disallowed paths found: {len(ra.get('disallowed_paths', []))}")
                print(f"   ⚠️  Accessible disallowed paths: {len(ra['accessible_disallowed'])}")
                for path_info in ra["accessible_disallowed"][:3]:
                    print(f"     - {path_info['path']}")
        
        # Placeholder
        placeholder = results.get("placeholder", {})
        if placeholder.get("has_placeholder"):
            print(f"\n📝 PLACEHOLDER CONTENT:")
            print(f"   - Placeholder texts: {len(placeholder.get('placeholder_texts', []))}")
            print(f"   - Placeholder images: {len(placeholder.get('placeholder_images', []))}")
        
        if placeholder.get("is_copyright_outdated"):
            print(f"   - Outdated copyright: {placeholder.get('copyright_year')}")
        
        # SUGGESTIONS
        suggestions = scan_result.get("suggestions", [])
        if suggestions:
            print(f"\n{'─'*70}")
            print(f"💡 RECOMMENDATIONS ({len(suggestions)}):")
            print(f"{'─'*70}")
            for i, sug in enumerate(suggestions, 1):
                priority = sug.get("priority", "")
                icon = {"critical": "🚨", "high": "🔴", "medium": "⚠️", "low": "ℹ️"}.get(priority, "•")
                print(f"   {icon} {sug['text']}")
        else:
            print(f"\n💡 No recommendations — site looks good!")
        
        print("\n" + "="*70)
    
    def generate_suggestions(self, scan_result: Dict) -> list:
        """
        Genera sugerencias accionables priorizadas a partir de todos los resultados.
        Cada sugerencia es un dict: {priority, category, text}
        Priority: critical > high > medium > low
        Máximo ~10 sugerencias, las más importantes primero.
        """
        suggestions = []
        results = scan_result.get("results", {})
        
        if not scan_result.get("fetch_info", {}).get("success"):
            suggestions.append({
                "priority": "critical",
                "category": "connectivity",
                "text": "The website is unreachable. Verify the domain is correct, the server is online, and DNS is properly configured."
            })
            return suggestions
        
        # ── MAINTENANCE MODE ──
        maint = results.get("maintenance_mode", {})
        if maint.get("is_maintenance"):
            suggestions.append({
                "priority": "high",
                "category": "maintenance",
                "text": "Site is in maintenance mode — visitors cannot access content. Disable maintenance mode or set an estimated return time."
            })
        
        # ── SECURITY: HACKED / MALWARE / SPAM ──
        sec = results.get("security", {})
        if sec.get("is_hacked"):
            suggestions.append({
                "priority": "critical",
                "category": "security",
                "text": "Site shows signs of being hacked. Immediately: restore from a clean backup, change all passwords, update all software, and audit server access logs."
            })
        if sec.get("has_malware"):
            suggestions.append({
                "priority": "critical",
                "category": "security",
                "text": "Malware code detected in the page source. Scan the server with a security tool (e.g. Wordfence, Sucuri) and remove all malicious scripts."
            })
        if sec.get("has_spam_seo"):
            suggestions.append({
                "priority": "critical",
                "category": "security",
                "text": "SEO spam injected into the site (pharma/casino links). Clean the database and templates, then check for unauthorized admin users."
            })
        if sec.get("has_exposed_keys"):
            suggestions.append({
                "priority": "critical",
                "category": "security",
                "text": "Private API keys or tokens are exposed in the HTML source. Revoke them immediately, generate new ones, and move them to server-side environment variables."
            })
        if sec.get("has_suspicious_comments"):
            suggestions.append({
                "priority": "medium",
                "category": "security",
                "text": "Suspicious HTML comments found (possible debug info or backdoor markers). Review and remove any unnecessary comments from production code."
            })
        
        # ── PHP / DB ERRORS ──
        php = results.get("php_errors", {})
        if php.get("has_errors"):
            php_list = php.get("php_errors", [])
            db_list = php.get("db_errors", [])
            if db_list:
                suggestions.append({
                    "priority": "critical",
                    "category": "errors",
                    "text": "Database errors are visible to visitors. Check the DB connection credentials, ensure the database server is running, and set display_errors = Off in php.ini."
                })
            if php_list:
                suggestions.append({
                    "priority": "high",
                    "category": "errors",
                    "text": f"PHP errors are exposed to visitors ({len(php_list)} found). Set display_errors = Off in production and review the error log to fix the underlying issues."
                })
        
        # ── SSL / HTTPS ──
        ssl_data = results.get("ssl", {})
        if not ssl_data.get("has_https"):
            suggestions.append({
                "priority": "high",
                "category": "ssl",
                "text": "Site is not using HTTPS. Install an SSL certificate (free via Let's Encrypt) and redirect all HTTP traffic to HTTPS."
            })
        elif not ssl_data.get("has_valid_certificate"):
            suggestions.append({
                "priority": "high",
                "category": "ssl",
                "text": "SSL certificate has a problem (invalid, self-signed, or hostname mismatch). Renew or replace the certificate."
            })
        else:
            cert = ssl_data.get("certificate", {})
            days = cert.get("days_remaining")
            if days is not None and days < 0:
                suggestions.append({
                    "priority": "critical",
                    "category": "ssl",
                    "text": f"SSL certificate EXPIRED {abs(days)} days ago. Renew it immediately — browsers are showing security warnings to all visitors."
                })
            elif days is not None and days < 30:
                suggestions.append({
                    "priority": "medium",
                    "category": "ssl",
                    "text": f"SSL certificate expires in {days} days ({cert.get('expires')}). Renew soon or enable auto-renewal to avoid downtime."
                })
        
        if ssl_data.get("has_mixed_content"):
            suggestions.append({
                "priority": "medium",
                "category": "ssl",
                "text": "Mixed content detected: some resources load over HTTP on an HTTPS page. Update all asset URLs to use HTTPS or protocol-relative paths."
            })
        
        missing_hdrs = ssl_data.get("missing_headers", [])
        if missing_hdrs:
            header_names = ", ".join(h.replace("Missing ", "").replace(" header", "") for h in missing_hdrs)
            suggestions.append({
                "priority": "low",
                "category": "headers",
                "text": f"Missing security headers: {header_names}. Configure them in your web server to improve defense against clickjacking and MIME sniffing."
            })
        
        # ── SENSITIVE FILES (Phase 2) ──
        sensitive = results.get("sensitive_info", {})
        
        inst = sensitive.get("install_files", {})
        if inst.get("install_files_found"):
            files = ", ".join(f["file"] for f in inst["install_files_found"][:3])
            suggestions.append({
                "priority": "critical",
                "category": "sensitive",
                "text": f"Installation files found and accessible ({files}). Delete them immediately — they can be used to reinstall/reset your site."
            })
        
        sf = sensitive.get("sensitive_files", {})
        if sf.get("sensitive_files"):
            files = ", ".join(f["file"] for f in sf["sensitive_files"][:3])
            suggestions.append({
                "priority": "critical",
                "category": "sensitive",
                "text": f"Sensitive files exposed ({files}). Block public access via .htaccess or server config — they may contain passwords or config data."
            })
        
        lf = sensitive.get("log_files", {})
        if lf.get("exposed_logs"):
            suggestions.append({
                "priority": "high",
                "category": "sensitive",
                "text": "Log files are publicly accessible. Move them outside the web root or block access — they can reveal server paths, errors, and user data."
            })
        
        dl = sensitive.get("directory_listing", {})
        if dl.get("exposed_directories"):
            count = len(dl["exposed_directories"])
            suggestions.append({
                "priority": "high",
                "category": "sensitive",
                "text": f"Directory listing is enabled on {count} folder(s). Disable it with 'Options -Indexes' in .htaccess to prevent exposing your file structure."
            })
        
        ap = sensitive.get("admin_panels", {})
        panels = ap.get("accessible_panels", [])
        if panels:
            panel_names = ", ".join(p["panel"] for p in panels[:3])
            suggestions.append({
                "priority": "medium",
                "category": "sensitive",
                "text": f"Admin panel(s) accessible ({panel_names}). Restrict access by IP, add 2FA, or move to a custom URL to reduce brute-force risk."
            })
        
        # ── CMS ──
        cms = results.get("cms", {})
        if cms.get("is_wordpress"):
            if cms.get("is_outdated"):
                suggestions.append({
                    "priority": "high",
                    "category": "cms",
                    "text": f"WordPress version {cms.get('version', '?')} is outdated. Update to the latest version to patch known security vulnerabilities."
                })
            outdated_plugins = [p for p in cms.get("plugins_detected", []) if isinstance(p, dict) and p.get("outdated")]
            plugin_count = len(cms.get("plugins_detected", []))
            if plugin_count > 15:
                suggestions.append({
                    "priority": "medium",
                    "category": "cms",
                    "text": f"{plugin_count} plugins detected. Review and deactivate unused plugins to reduce attack surface and improve performance."
                })
        
        # ── SEO ──
        seo = results.get("seo", {})
        seo_issues = seo.get("issues", [])
        if seo_issues:
            # Group & prioritize SEO suggestions
            if any("Missing title" in i or "Title tag is empty" in i for i in seo_issues):
                suggestions.append({
                    "priority": "high",
                    "category": "seo",
                    "text": "The page is missing a <title> tag. Add a descriptive, keyword-rich title (50-60 characters) — this is critical for search engine ranking."
                })
            if any("Missing meta description" in i for i in seo_issues):
                suggestions.append({
                    "priority": "medium",
                    "category": "seo",
                    "text": "Missing meta description. Add a compelling description (120-160 characters) that summarizes the page content for search results."
                })
            if any("Missing H1" in i for i in seo_issues):
                suggestions.append({
                    "priority": "medium",
                    "category": "seo",
                    "text": "No H1 heading found. Add a single, descriptive H1 tag — search engines use it to understand the main topic of the page."
                })
            if any("Multiple H1" in i for i in seo_issues):
                suggestions.append({
                    "priority": "low",
                    "category": "seo",
                    "text": "Multiple H1 tags detected. Use a single H1 for the main heading and H2-H6 for subheadings to improve content hierarchy."
                })
            alt_issue = next((i for i in seo_issues if "images missing alt" in i), None)
            if alt_issue:
                suggestions.append({
                    "priority": "low",
                    "category": "seo",
                    "text": f"Images without alt text: {alt_issue.split(')')[0].split('(')[-1] if '(' in alt_issue else 'some'}. Add descriptive alt attributes for accessibility and SEO."
                })
        
        # ── PLACEHOLDER / COPYRIGHT ──
        placeholder = results.get("placeholder", {})
        if placeholder.get("has_placeholder"):
            suggestions.append({
                "priority": "medium",
                "category": "content",
                "text": "Placeholder/dummy content detected. Replace it with real content before it affects your professional image and SEO."
            })
        if placeholder.get("is_copyright_outdated"):
            year = placeholder.get("copyright_year", "?")
            suggestions.append({
                "priority": "low",
                "category": "content",
                "text": f"Copyright year is outdated ({year}). Update it to the current year to show the site is actively maintained."
            })
        
        # ── PUBLIC API KEYS (informational) ──
        if sec.get("has_public_keys"):
            suggestions.append({
                "priority": "low",
                "category": "security",
                "text": "Public API keys found in source (e.g. Google Maps). While not secret, consider restricting them by referrer/IP in the provider's console."
            })
        
        # ── RESPONSE TIME ──
        resp_time = scan_result.get("fetch_info", {}).get("response_time", 0)
        if resp_time > 5:
            suggestions.append({
                "priority": "medium",
                "category": "performance",
                "text": f"Response time is slow ({resp_time}s). Investigate server performance, enable caching, optimize images, and consider a CDN."
            })
        elif resp_time > 3:
            suggestions.append({
                "priority": "low",
                "category": "performance",
                "text": f"Response time is {resp_time}s. Consider enabling server-side caching and image optimization to improve loading speed."
            })
        
        # Sort by priority (critical first)
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        suggestions.sort(key=lambda s: priority_order.get(s["priority"], 99))
        
        # Limit to top 10 most important
        return suggestions[:10]


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
