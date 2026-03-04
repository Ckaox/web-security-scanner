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
        print(f"  Conectando a {url}...")
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
        print("  > Verificando modo mantenimiento...")
        scan_result["results"]["maintenance_mode"] = self._detect_maintenance_mode(
            fetch_result["status_code"], html_content
        )
        
        # 2. Detectar errores PHP
        print("  > Verificando errores PHP...")
        scan_result["results"]["php_errors"] = self.php_detector.detect(html_content, final_url)
        
        # 3. Detectar hackeos y spam
        print("  > Verificando amenazas de seguridad...")
        scan_result["results"]["security"] = self.hack_detector.detect(html_content, final_url)
        
        # 4. Verificar SSL
        print("  > Verificando SSL...")
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
        print("  > Analizando SEO...")
        scan_result["results"]["seo"] = self.ssl_seo_detector.analyze_seo(html_content, final_url)
        
        # 6. Detectar CMS
        print("  > Detectando CMS...")
        cms_results = self.cms_detector.detect_all(html_content, final_url)
        scan_result["results"]["cms"] = cms_results["wordpress"]
        scan_result["results"]["cms"]["other_cms"] = cms_results["other_cms"]
        scan_result["results"]["cms"]["js_libraries"] = cms_results["js_libraries"]
        scan_result["results"]["placeholder"] = cms_results["placeholder"]
        
        # 7. FASE 2 - Detectar información sensible (opcional, más intensivo)
        if self.enable_phase2:
            print("  > Escaneando archivos sensibles (Fase 2)...")
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
        print(f"  RESUMEN DEL ESCANEO: {scan_result['url']}")
        print("="*70)
        
        # Estado general
        severity_label = {
            "none": "[OK]",
            "low": "[BAJO]",
            "medium": "[MEDIO]",
            "high": "[ALTO]",
            "critical": "[CRITICO]"
        }
        
        label = severity_label.get(scan_result["overall_severity"], "[?]")
        print(f"\n  Severidad general: {label}")
        print(f"  Duracion del escaneo: {scan_result['scan_duration']}s")
        print(f"  Tiempo de respuesta: {scan_result['fetch_info']['response_time']}s")
        print(f"  Estado HTTP: {scan_result['fetch_info']['status_code']}")
        
        # Resumen de issues
        summary = scan_result["issues_summary"]
        if summary["total"] > 0:
            print(f"\n  Problemas encontrados: {summary['total']}")
            if summary["critical"] > 0:
                print(f"   [CRITICO] {summary['critical']}")
            if summary["high"] > 0:
                print(f"   [ALTO]    {summary['high']}")
            if summary["medium"] > 0:
                print(f"   [MEDIO]   {summary['medium']}")
            if summary["low"] > 0:
                print(f"   [BAJO]    {summary['low']}")
        else:
            print("\n  No se encontraron problemas criticos.")
        
        # Detalles por categoría
        results = scan_result["results"]
        
        # Si el fetch falló, los dicts estarán vacíos - salir temprano
        if not scan_result["fetch_info"].get("success"):
            error_msg = scan_result["fetch_info"].get("error", "Error desconocido")
            print(f"\n  [CRITICO] CONEXION FALLIDA: {error_msg}")
            print(f"   No se puede analizar el sitio - la conexion ha fallado.")
            
            suggestions = scan_result.get("suggestions", [])
            if suggestions:
                print(f"\n{'─'*70}")
                print(f"  RECOMENDACIONES ({len(suggestions)}):")
                print(f"{'─'*70}")
                for sug in suggestions:
                    p = sug.get("priority", "")
                    tag = {"critical": "[CRITICO]", "high": "[ALTO]", "medium": "[MEDIO]", "low": "[BAJO]"}.get(p, "-")
                    print(f"   {tag} {sug['text']}")
            
            print("\n" + "="*70)
            return
        
        # Maintenance Mode
        if results.get("maintenance_mode", {}).get("is_maintenance"):
            print(f"\n  MODO MANTENIMIENTO DETECTADO:")
            for indicator in results["maintenance_mode"]["indicators"]:
                print(f"   - {indicator}")
            print(f"   Los resultados pueden ser incompletos - el sitio no sirve contenido normal.")
        
        # PHP Errors
        php = results.get("php_errors", {})
        if php.get("has_errors"):
            print(f"\n  ERRORES PHP/BASE DE DATOS:")
            if php.get("php_errors"):
                print(f"   - Errores PHP encontrados: {len(php['php_errors'])}")
                for error in php["php_errors"][:2]:
                    print(f"     > {error[:80]}...")
            if php.get("db_errors"):
                print(f"   - Errores de base de datos: {len(php['db_errors'])}")
        
        # Security
        sec = results.get("security", {})
        if sec.get("is_hacked") or sec.get("has_spam_seo") or sec.get("has_malware"):
            print(f"\n  PROBLEMAS DE SEGURIDAD:")
            if sec.get("is_hacked"):
                print(f"   [CRITICO] El sitio parece estar hackeado.")
                for indicator in sec.get("hack_indicators", [])[:2]:
                    print(f"     > {indicator}")
            if sec.get("has_malware"):
                print(f"   [ALTO] Codigo malware detectado.")
            if sec.get("has_spam_seo"):
                print(f"   [ALTO] Inyeccion de spam SEO detectada: {len(sec.get('spam_indicators', []))} indicadores")
        
        # API Keys expuestas
        if sec.get("has_exposed_keys"):
            print(f"\n  API KEYS / TOKENS EXPUESTOS EN CODIGO (CRITICO):")
            for key_info in sec.get("exposed_keys", [])[:5]:
                print(f"   [CRITICO] {key_info}")
        # API Keys públicas (informativo)
        if sec.get("has_public_keys"):
            print(f"\n  API KEYS PUBLICAS EN CODIGO (informativo):")
            for key_info in sec.get("public_keys", [])[:5]:
                print(f"   - {key_info}")
        # Comentarios sospechosos
        if sec.get("has_suspicious_comments"):
            print(f"\n  COMENTARIOS SOSPECHOSOS EN HTML:")
            for comment in sec.get("suspicious_comments", [])[:3]:
                print(f"   - {comment}")
        
        # SSL / Certificate
        ssl_data = results.get("ssl", {})
        if ssl_data.get("has_https") and ssl_data.get("has_valid_certificate"):
            cert = ssl_data.get("certificate", {})
            print(f"\n  CERTIFICADO SSL: Valido")
            if cert.get("issuer"):
                print(f"   Emisor: {cert['issuer']}")
            if cert.get("expires"):
                days = cert.get('days_remaining', '?')
                print(f"   Expira: {cert['expires']} ({days} dias restantes)")
        elif ssl_data.get("has_https"):
            print(f"\n  CERTIFICADO SSL: Problema detectado")
        elif ssl_data:
            print(f"\n  CERTIFICADO SSL: El sitio no usa HTTPS")
        
        if ssl_data.get("issues"):
            for issue in ssl_data["issues"][:3]:
                print(f"   [!] {issue}")
        
        if ssl_data.get("missing_headers"):
            print(f"\n  CABECERAS DE SEGURIDAD (informativo):")
            for header in ssl_data["missing_headers"][:3]:
                print(f"   - {header}")
        
        # SEO
        seo = results.get("seo", {})
        if seo.get("issues"):
            print(f"\n  PROBLEMAS SEO ({len(seo['issues'])}):")
            for issue in seo["issues"][:5]:
                print(f"   - {issue}")
        
        # CMS
        cms = results.get("cms", {})
        if cms.get("is_wordpress"):
            print(f"\n  CMS DETECTADO:")
            print(f"   - WordPress {cms.get('version') or 'version desconocida'}")
            if cms.get("is_outdated"):
                print(f"   [ALTO] La version de WordPress esta DESACTUALIZADA")
            if cms.get("plugins_detected"):
                print(f"   - Plugins detectados: {len(cms['plugins_detected'])}")
        
        # Información sensible (Fase 2)
        if results.get("sensitive_info"):
            sensitive = results["sensitive_info"]
            
            sf = sensitive.get("sensitive_files", {})
            if sf.get("accessible_files"):
                print(f"\n  ARCHIVOS SENSIBLES EXPUESTOS (Fase 2):")
                for file_info in sf.get("sensitive_files", []):
                    print(f"   [CRITICO] {file_info['file']} ({file_info['size']} bytes)")
                other_files = [f for f in sf["accessible_files"] 
                               if not any(f == sfi["file"] for sfi in sf.get("sensitive_files", []))]
                if other_files:
                    print(f"   Otros archivos accesibles: {', '.join(other_files[:3])}")
            
            dl = sensitive.get("directory_listing", {})
            if dl.get("exposed_directories"):
                print(f"\n  LISTADO DE DIRECTORIOS HABILITADO:")
                for dir_info in dl["exposed_directories"]:
                    print(f"   - /{dir_info['directory']}/ ({dir_info['file_count']} archivos)")
            
            inst = sensitive.get("install_files", {})
            if inst.get("install_files_found"):
                print(f"\n  ARCHIVOS DE INSTALACION ENCONTRADOS (CRITICO):")
                for install in inst["install_files_found"]:
                    print(f"   [CRITICO] {install['file']} - Permite reinstalar el sitio")
            
            ap = sensitive.get("admin_panels", {})
            if ap.get("accessible_panels"):
                print(f"\n  PANELES DE ADMINISTRACION ACCESIBLES:")
                for panel in ap["accessible_panels"][:5]:
                    print(f"   - {panel['panel']} (HTTP {panel['status']})")
            
            lf = sensitive.get("log_files", {})
            if lf.get("exposed_logs"):
                print(f"\n  ARCHIVOS DE LOG EXPUESTOS:")
                for log in lf["exposed_logs"]:
                    print(f"   [CRITICO] {log['file']} ({log['size']} bytes) - Puede contener info sensible")
            
            ra = sensitive.get("robots_analysis", {})
            if ra.get("accessible_disallowed"):
                print(f"\n  ANALISIS ROBOTS.TXT:")
                print(f"   Rutas bloqueadas encontradas: {len(ra.get('disallowed_paths', []))}")
                print(f"   Rutas bloqueadas pero accesibles: {len(ra['accessible_disallowed'])}")
                for path_info in ra["accessible_disallowed"][:3]:
                    print(f"     - {path_info['path']}")
        
        # Placeholder
        placeholder = results.get("placeholder", {})
        if placeholder.get("has_placeholder"):
            print(f"\n  CONTENIDO PLACEHOLDER:")
            print(f"   - Textos placeholder: {len(placeholder.get('placeholder_texts', []))}")
            print(f"   - Imagenes placeholder: {len(placeholder.get('placeholder_images', []))}")
        
        if placeholder.get("is_copyright_outdated"):
            print(f"   - Copyright desactualizado: {placeholder.get('copyright_year')}")
        
        # SUGERENCIAS
        suggestions = scan_result.get("suggestions", [])
        if suggestions:
            print(f"\n{'─'*70}")
            print(f"  RECOMENDACIONES ({len(suggestions)}):")
            print(f"{'─'*70}")
            for sug in suggestions:
                p = sug.get("priority", "")
                tag = {"critical": "[CRITICO]", "high": "[ALTO]", "medium": "[MEDIO]", "low": "[BAJO]"}.get(p, "-")
                print(f"   {tag} {sug['text']}")
        else:
            print(f"\n  Sin recomendaciones - el sitio se ve bien.")
        
        print("\n" + "="*70)
    
    def generate_suggestions(self, scan_result: Dict) -> list:
        """
        Genera sugerencias accionables priorizadas a partir de todos los resultados.
        Cada sugerencia es un dict: {priority, category, text}
        Priority: critical > high > medium > low
        Maximo ~10 sugerencias, las mas importantes primero.
        """
        suggestions = []
        results = scan_result.get("results", {})
        
        if not scan_result.get("fetch_info", {}).get("success"):
            suggestions.append({
                "priority": "critical",
                "category": "connectivity",
                "text": "El sitio web no es accesible. Verifica que el dominio sea correcto, que el servidor este en linea y que el DNS este bien configurado."
            })
            return suggestions
        
        # ── MODO MANTENIMIENTO ──
        maint = results.get("maintenance_mode", {})
        if maint.get("is_maintenance"):
            suggestions.append({
                "priority": "high",
                "category": "maintenance",
                "text": "El sitio esta en modo mantenimiento, los visitantes no pueden acceder al contenido. Desactiva el modo mantenimiento o indica una fecha estimada de retorno."
            })
        
        # ── SEGURIDAD: HACKEO / MALWARE / SPAM ──
        sec = results.get("security", {})
        if sec.get("is_hacked"):
            suggestions.append({
                "priority": "critical",
                "category": "security",
                "text": "El sitio muestra signos de estar hackeado. Accion inmediata: restaurar desde un backup limpio, cambiar todas las contrasenas, actualizar todo el software y revisar los logs de acceso."
            })
        if sec.get("has_malware"):
            suggestions.append({
                "priority": "critical",
                "category": "security",
                "text": "Se detecto codigo malware en el codigo fuente. Escanea el servidor con una herramienta de seguridad (ej. Wordfence, Sucuri) y elimina todos los scripts maliciosos."
            })
        if sec.get("has_spam_seo"):
            suggestions.append({
                "priority": "critical",
                "category": "security",
                "text": "Se detecto spam SEO inyectado en el sitio (enlaces de farmacia/casino). Limpia la base de datos y las plantillas, y verifica que no haya usuarios admin no autorizados."
            })
        if sec.get("has_exposed_keys"):
            suggestions.append({
                "priority": "critical",
                "category": "security",
                "text": "Claves API o tokens privados estan expuestos en el HTML. Revocalos inmediatamente, genera nuevos y muevalos a variables de entorno del servidor."
            })
        if sec.get("has_suspicious_comments"):
            suggestions.append({
                "priority": "medium",
                "category": "security",
                "text": "Se encontraron comentarios HTML sospechosos (posible info de debug o marcadores de backdoor). Revisa y elimina comentarios innecesarios del codigo en produccion."
            })
        
        # ── ERRORES PHP / DB ──
        php = results.get("php_errors", {})
        if php.get("has_errors"):
            php_list = php.get("php_errors", [])
            db_list = php.get("db_errors", [])
            if db_list:
                suggestions.append({
                    "priority": "critical",
                    "category": "errors",
                    "text": "Errores de base de datos visibles para los visitantes. Verifica las credenciales de conexion, asegurate de que el servidor DB este activo y configura display_errors = Off en php.ini."
                })
            if php_list:
                suggestions.append({
                    "priority": "high",
                    "category": "errors",
                    "text": f"Errores PHP expuestos a visitantes ({len(php_list)} encontrados). Configura display_errors = Off en produccion y revisa el log de errores para corregir las causas."
                })
        
        # ── SSL / HTTPS ──
        ssl_data = results.get("ssl", {})
        if not ssl_data.get("has_https"):
            suggestions.append({
                "priority": "high",
                "category": "ssl",
                "text": "El sitio no usa HTTPS. Instala un certificado SSL (gratuito con Let's Encrypt) y redirige todo el trafico HTTP a HTTPS."
            })
        elif not ssl_data.get("has_valid_certificate"):
            suggestions.append({
                "priority": "high",
                "category": "ssl",
                "text": "El certificado SSL tiene un problema (invalido, autofirmado o no coincide con el dominio). Renueva o reemplaza el certificado."
            })
        else:
            cert = ssl_data.get("certificate", {})
            days = cert.get("days_remaining")
            if days is not None and days < 0:
                suggestions.append({
                    "priority": "critical",
                    "category": "ssl",
                    "text": f"El certificado SSL EXPIRO hace {abs(days)} dias. Renovalo inmediatamente, los navegadores estan mostrando advertencias de seguridad a todos los visitantes."
                })
            elif days is not None and days < 30:
                suggestions.append({
                    "priority": "medium",
                    "category": "ssl",
                    "text": f"El certificado SSL expira en {days} dias ({cert.get('expires')}). Renuevalo pronto o activa la renovacion automatica para evitar caidas."
                })
        
        if ssl_data.get("has_mixed_content"):
            suggestions.append({
                "priority": "medium",
                "category": "ssl",
                "text": "Contenido mixto detectado: algunos recursos se cargan por HTTP en una pagina HTTPS. Actualiza todas las URLs de recursos para usar HTTPS."
            })
        
        missing_hdrs = ssl_data.get("missing_headers", [])
        if missing_hdrs:
            header_names = ", ".join(h.replace("Missing ", "").replace(" header", "") for h in missing_hdrs)
            suggestions.append({
                "priority": "low",
                "category": "headers",
                "text": f"Faltan cabeceras de seguridad: {header_names}. Configuralas en tu servidor web para mejorar la proteccion contra clickjacking y MIME sniffing."
            })
        
        # ── ARCHIVOS SENSIBLES (Fase 2) ──
        sensitive = results.get("sensitive_info", {})
        
        inst = sensitive.get("install_files", {})
        if inst.get("install_files_found"):
            files = ", ".join(f["file"] for f in inst["install_files_found"][:3])
            suggestions.append({
                "priority": "critical",
                "category": "sensitive",
                "text": f"Archivos de instalacion encontrados y accesibles ({files}). Eliminalos inmediatamente, pueden usarse para reinstalar/resetear tu sitio."
            })
        
        sf = sensitive.get("sensitive_files", {})
        if sf.get("sensitive_files"):
            files = ", ".join(f["file"] for f in sf["sensitive_files"][:3])
            suggestions.append({
                "priority": "critical",
                "category": "sensitive",
                "text": f"Archivos sensibles expuestos ({files}). Bloquea el acceso publico via .htaccess o configuracion del servidor, pueden contener contrasenas o datos de configuracion."
            })
        
        lf = sensitive.get("log_files", {})
        if lf.get("exposed_logs"):
            suggestions.append({
                "priority": "high",
                "category": "sensitive",
                "text": "Archivos de log accesibles publicamente. Muevalos fuera del directorio web o bloquea el acceso, pueden revelar rutas del servidor, errores y datos de usuarios."
            })
        
        dl = sensitive.get("directory_listing", {})
        if dl.get("exposed_directories"):
            count = len(dl["exposed_directories"])
            suggestions.append({
                "priority": "high",
                "category": "sensitive",
                "text": f"Listado de directorios habilitado en {count} carpeta(s). Desactivalo con 'Options -Indexes' en .htaccess para no exponer la estructura de archivos."
            })
        
        ap = sensitive.get("admin_panels", {})
        panels = ap.get("accessible_panels", [])
        if panels:
            panel_names = ", ".join(p["panel"] for p in panels[:3])
            suggestions.append({
                "priority": "medium",
                "category": "sensitive",
                "text": f"Panel(es) de admin accesible(s) ({panel_names}). Restringe el acceso por IP, agrega 2FA o cambia la URL para reducir ataques de fuerza bruta."
            })
        
        # ── CMS ──
        cms = results.get("cms", {})
        if cms.get("is_wordpress"):
            if cms.get("is_outdated"):
                suggestions.append({
                    "priority": "high",
                    "category": "cms",
                    "text": f"WordPress version {cms.get('version', '?')} esta desactualizada. Actualiza a la ultima version para corregir vulnerabilidades de seguridad conocidas."
                })
            plugin_count = len(cms.get("plugins_detected", []))
            if plugin_count > 15:
                suggestions.append({
                    "priority": "medium",
                    "category": "cms",
                    "text": f"{plugin_count} plugins detectados. Revisa y desactiva los plugins que no uses para reducir la superficie de ataque y mejorar el rendimiento."
                })
        
        # ── SEO ──
        seo = results.get("seo", {})
        seo_issues = seo.get("issues", [])
        if seo_issues:
            if any("Missing title" in i or "Title tag is empty" in i for i in seo_issues):
                suggestions.append({
                    "priority": "high",
                    "category": "seo",
                    "text": "La pagina no tiene etiqueta <title>. Agrega un titulo descriptivo con palabras clave (50-60 caracteres), es critico para el posicionamiento en buscadores."
                })
            if any("Missing meta description" in i for i in seo_issues):
                suggestions.append({
                    "priority": "medium",
                    "category": "seo",
                    "text": "Falta la meta description. Agrega una descripcion atractiva (120-160 caracteres) que resuma el contenido de la pagina para los resultados de busqueda."
                })
            if any("Missing H1" in i for i in seo_issues):
                suggestions.append({
                    "priority": "medium",
                    "category": "seo",
                    "text": "No se encontro encabezado H1. Agrega un unico H1 descriptivo, los buscadores lo usan para entender el tema principal de la pagina."
                })
            if any("Multiple H1" in i for i in seo_issues):
                suggestions.append({
                    "priority": "low",
                    "category": "seo",
                    "text": "Se detectaron multiples etiquetas H1. Usa un solo H1 para el titulo principal y H2-H6 para subtitulos, mejora la jerarquia del contenido."
                })
            alt_issue = next((i for i in seo_issues if "images missing alt" in i), None)
            if alt_issue:
                pct = alt_issue.split(')')[0].split('(')[-1] if '(' in alt_issue else 'algunas'
                suggestions.append({
                    "priority": "low",
                    "category": "seo",
                    "text": f"Imagenes sin texto alt: {pct}. Agrega atributos alt descriptivos para mejorar la accesibilidad y el SEO."
                })
        
        # ── PLACEHOLDER / COPYRIGHT ──
        placeholder = results.get("placeholder", {})
        if placeholder.get("has_placeholder"):
            suggestions.append({
                "priority": "medium",
                "category": "content",
                "text": "Se detecto contenido placeholder/de ejemplo. Reemplazalo con contenido real antes de que afecte tu imagen profesional y tu SEO."
            })
        if placeholder.get("is_copyright_outdated"):
            year = placeholder.get("copyright_year", "?")
            suggestions.append({
                "priority": "low",
                "category": "content",
                "text": f"El ano del copyright esta desactualizado ({year}). Actualizalo al ano actual para mostrar que el sitio se mantiene activo."
            })
        
        # ── API KEYS PUBLICAS (informativo) ──
        if sec.get("has_public_keys"):
            suggestions.append({
                "priority": "low",
                "category": "security",
                "text": "Se encontraron API keys publicas en el codigo (ej. Google Maps). Aunque no son secretas, considera restringirlas por referrer/IP en la consola del proveedor."
            })
        
        # ── TIEMPO DE RESPUESTA ──
        resp_time = scan_result.get("fetch_info", {}).get("response_time", 0)
        if resp_time > 5:
            suggestions.append({
                "priority": "medium",
                "category": "performance",
                "text": f"El tiempo de respuesta es lento ({resp_time}s). Investiga el rendimiento del servidor, activa cache, optimiza imagenes y considera usar un CDN."
            })
        elif resp_time > 3:
            suggestions.append({
                "priority": "low",
                "category": "performance",
                "text": f"El tiempo de respuesta es de {resp_time}s. Considera activar cache del servidor y optimizar imagenes para mejorar la velocidad de carga."
            })
        
        # Ordenar por prioridad (critico primero)
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        suggestions.sort(key=lambda s: priority_order.get(s["priority"], 99))
        
        # Limitar a las 10 mas importantes
        return suggestions[:10]


def test_real_url():
    """Test con una URL real"""
    print("Probando con URLs reales...\n")
    
    scanner = WebScanner(timeout=15)
    
    test_urls = [
        "httpbin.org/html",
    ]
    
    for url in test_urls:
        print(f"\n{'='*70}")
        print(f"Escaneando: {url}")
        print('='*70)
        
        result = scanner.scan(url)
        scanner.print_summary(result)
        
        print("\n")


if __name__ == "__main__":
    test_real_url()
