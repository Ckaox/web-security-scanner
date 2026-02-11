"""
Detector de información sensible expuesta y archivos peligrosos (Fase 2)
"""
import re
import requests
from typing import Dict, List
from urllib.parse import urljoin, urlparse
import warnings

warnings.filterwarnings('ignore', message='Unverified HTTPS request')


class SensitiveInfoDetector:
    """Detecta información sensible expuesta y configuraciones inseguras"""
    
    # Archivos sensibles comunes
    SENSITIVE_FILES = [
        '.env',
        '.env.backup',
        '.env.old',
        '.env.local',
        '.git/config',
        '.git/HEAD',
        'phpinfo.php',
        'info.php',
        'test.php',
        'backup.sql',
        'database.sql',
        'dump.sql',
        'backup.zip',
        'backup.tar.gz',
        'site-backup.zip',
        'wp-config.php.bak',
        'wp-config.php~',
        'config.php.bak',
        'config.php',
        'configuration.php',
        'settings.php',
        'database.yml',
        '.htaccess',
        '.htaccess.bak',
        'web.config',
        'readme.html',  # WordPress expone versión
        'license.txt',
    ]
    
    # Archivos de instalación (CRÍTICO - permiten reinstalar/hackear)
    INSTALL_FILES = [
        'install.php',
        'setup.php',
        'install/',
        'installer/',
        'installation/',
        'wp-admin/install.php',
        'wp-admin/setup-config.php',
        'install/index.php',
    ]
    
    # Paneles de administración
    ADMIN_PANELS = [
        'wp-admin/',
        'wp-login.php',
        'administrator/',  # Joomla
        'admin/',
        'admin/login',
        'admin.php',
        'phpmyadmin/',
        'pma/',
        'mysql/',
        'cpanel/',
        'plesk/',
        'webmail/',
    ]
    
    # Archivos de logs (pueden contener info sensible)
    LOG_FILES = [
        'error_log',
        'error.log',
        'debug.log',
        'access.log',
        'application.log',
        'php_errors.log',
        'logs/error.log',
        'logs/access.log',
        'storage/logs/laravel.log',
    ]
    
    # Directorios comunes
    COMMON_DIRECTORIES = [
        'admin',
        'administrator',
        'backup',
        'backups',
        'old',
        'test',
        'temp',
        'tmp',
        'private',
        'uploads',
        '.git',
    ]
    
    # Patrones de contenido sensible en HTML
    SENSITIVE_PATTERNS = {
        'api_keys': [
            r'api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{20,})',
            r'apikey["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{20,})',
        ],
        'tokens': [
            r'token["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{20,})',
            r'auth[_-]?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{20,})',
        ],
        'credentials': [
            r'password["\']?\s*[:=]\s*["\']([^"\']{3,})',
            r'passwd["\']?\s*[:=]\s*["\']([^"\']{3,})',
        ],
        'internal_ips': [
            r'(?:192\.168\.\d{1,3}\.\d{1,3})',
            r'(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3})',
            r'(?:172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})',
        ],
        'paths': [
            r'(?:[C-Z]:\\[\w\\]+)',  # Windows paths
            r'(?:/home/[\w/]+)',  # Linux paths
            r'(?:/var/www/[\w/]+)',
        ]
    }
    
    def __init__(self, timeout=5, user_agent=None):
        self.timeout = timeout
        self.user_agent = user_agent or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    
    def check_file_exists(self, base_url: str, file_path: str) -> Dict:
        """
        Verifica si un archivo sensible es accesible
        
        Returns:
            Dict con información de accesibilidad
        """
        result = {
            "file": file_path,
            "accessible": False,
            "status_code": None,
            "size": 0,
            "contains_sensitive": False
        }
        
        try:
            full_url = urljoin(base_url, file_path)
            headers = {'User-Agent': self.user_agent}
            
            response = requests.get(
                full_url,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=False,
                verify=False
            )
            
            result["status_code"] = response.status_code
            
            # Considerar accesible si es 200
            if response.status_code == 200:
                result["accessible"] = True
                result["size"] = len(response.content)
                
                # Verificar si contiene contenido sensible (para archivos pequeños)
                if result["size"] < 100000:  # Solo analizar si es < 100KB
                    content_lower = response.text.lower()
                    sensitive_keywords = ['password', 'secret', 'api_key', 'token', 'database', 'mysql']
                    result["contains_sensitive"] = any(keyword in content_lower for keyword in sensitive_keywords)
        
        except:
            pass
        
        return result
    
    def check_directory_listing(self, base_url: str, directory: str) -> Dict:
        """
        Verifica si un directorio tiene directory listing habilitado
        
        Returns:
            Dict con información del directorio
        """
        result = {
            "directory": directory,
            "has_listing": False,
            "status_code": None,
            "file_count_estimate": 0
        }
        
        try:
            full_url = urljoin(base_url, directory + '/')
            headers = {'User-Agent': self.user_agent}
            
            response = requests.get(
                full_url,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=False,
                verify=False
            )
            
            result["status_code"] = response.status_code
            
            if response.status_code == 200:
                content = response.text.lower()
                
                # Indicadores de directory listing
                listing_indicators = [
                    'index of /',
                    'parent directory',
                    '<pre>',  # Común en Apache
                    'directory listing',
                ]
                
                if any(indicator in content for indicator in listing_indicators):
                    result["has_listing"] = True
                    # Estimar cantidad de archivos (contar <a href> aproximadamente)
                    result["file_count_estimate"] = content.count('<a href') - 1  # -1 para parent dir
        
        except:
            pass
        
        return result
    
    def scan_sensitive_files(self, base_url: str, max_checks: int = 15) -> Dict:
        """
        Escanea archivos sensibles en el sitio
        
        Args:
            base_url: URL base del sitio
            max_checks: Máximo número de archivos a verificar
            
        Returns:
            Dict con archivos sensibles encontrados
        """
        result = {
            "files_checked": 0,
            "accessible_files": [],
            "sensitive_files": [],
            "severity": "none"
        }
        
        print(f"  🔍 Scanning for sensitive files (max {max_checks})...")
        
        for file_path in self.SENSITIVE_FILES[:max_checks]:
            result["files_checked"] += 1
            
            check_result = self.check_file_exists(base_url, file_path)
            
            if check_result["accessible"]:
                result["accessible_files"].append(file_path)
                
                if check_result["contains_sensitive"]:
                    result["sensitive_files"].append({
                        "file": file_path,
                        "size": check_result["size"]
                    })
                    print(f"    🚨 Found: {file_path} ({check_result['size']} bytes)")
        
        # Determinar severidad
        if result["sensitive_files"]:
            result["severity"] = "critical"
        elif len(result["accessible_files"]) >= 2:
            result["severity"] = "high"
        elif result["accessible_files"]:
            result["severity"] = "medium"
        
        return result
    
    def scan_install_files(self, base_url: str) -> Dict:
        """
        Escanea archivos de instalación que deberían estar eliminados
        
        Args:
            base_url: URL base del sitio
            
        Returns:
            Dict con archivos de instalación encontrados
        """
        result = {
            "files_checked": 0,
            "install_files_found": [],
            "severity": "none"
        }
        
        print(f"  🔍 Checking for installation files...")
        
        for file_path in self.INSTALL_FILES:
            result["files_checked"] += 1
            
            check_result = self.check_file_exists(base_url, file_path)
            
            if check_result["accessible"]:
                result["install_files_found"].append({
                    "file": file_path,
                    "status": check_result["status_code"],
                    "size": check_result["size"]
                })
                print(f"    🚨 Installation file found: {file_path}")
        
        # Cualquier archivo de instalación accesible es CRÍTICO
        if result["install_files_found"]:
            result["severity"] = "critical"
        
        return result
    
    def scan_admin_panels(self, base_url: str) -> Dict:
        """
        Escanea paneles de administración accesibles
        
        Args:
            base_url: URL base del sitio
            
        Returns:
            Dict con paneles encontrados
        """
        result = {
            "panels_checked": 0,
            "accessible_panels": [],
            "severity": "none"
        }
        
        print(f"  🔍 Checking admin panels...")
        
        for panel_path in self.ADMIN_PANELS:
            result["panels_checked"] += 1
            
            check_result = self.check_file_exists(base_url, panel_path)
            
            # Paneles suelen devolver 200 o 302 (redirect a login)
            if check_result["status_code"] in [200, 302, 301]:
                result["accessible_panels"].append({
                    "panel": panel_path,
                    "status": check_result["status_code"]
                })
                print(f"    ⚠️  Admin panel accessible: {panel_path} ({check_result['status_code']})")
        
        # Determinar severidad
        if len(result["accessible_panels"]) >= 3:
            result["severity"] = "high"
        elif len(result["accessible_panels"]) > 0:
            result["severity"] = "medium"
        
        return result
    
    def scan_log_files(self, base_url: str) -> Dict:
        """
        Escanea archivos de logs expuestos públicamente
        
        Args:
            base_url: URL base del sitio
            
        Returns:
            Dict con logs encontrados
        """
        result = {
            "logs_checked": 0,
            "exposed_logs": [],
            "severity": "none"
        }
        
        print(f"  🔍 Checking for exposed log files...")
        
        for log_path in self.LOG_FILES:
            result["logs_checked"] += 1
            
            check_result = self.check_file_exists(base_url, log_path)
            
            if check_result["accessible"] and check_result["size"] > 0:
                result["exposed_logs"].append({
                    "file": log_path,
                    "size": check_result["size"]
                })
                print(f"    🚨 Log file exposed: {log_path} ({check_result['size']} bytes)")
        
        # Determinar severidad
        if result["exposed_logs"]:
            result["severity"] = "high"
        
        return result
    
    def scan_robots_txt(self, base_url: str) -> Dict:
        """
        Analiza robots.txt para encontrar directorios 'prohibidos' y verifica si son accesibles
        
        Args:
            base_url: URL base del sitio
            
        Returns:
            Dict con análisis de robots.txt
        """
        result = {
            "has_robots": False,
            "disallowed_paths": [],
            "accessible_disallowed": [],
            "severity": "none"
        }
        
        print(f"  🔍 Analyzing robots.txt...")
        
        try:
            # Obtener robots.txt
            full_url = urljoin(base_url, 'robots.txt')
            headers = {'User-Agent': self.user_agent}
            
            response = requests.get(
                full_url,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=False,
                verify=False
            )
            
            if response.status_code == 200:
                result["has_robots"] = True
                content = response.text
                
                # Parsear líneas Disallow
                disallow_pattern = re.compile(r'^Disallow:\s*(.+)$', re.MULTILINE | re.IGNORECASE)
                disallows = disallow_pattern.findall(content)
                
                # Limpiar y filtrar paths
                for path in disallows:
                    path = path.strip()
                    if path and path != '/' and not path.startswith('*'):
                        result["disallowed_paths"].append(path)
                
                # Verificar si los primeros 5 paths prohibidos son accesibles
                for path in result["disallowed_paths"][:5]:
                    check_result = self.check_file_exists(base_url, path.lstrip('/'))
                    
                    # Si devuelve 200, el path prohibido es accesible
                    if check_result["status_code"] == 200:
                        result["accessible_disallowed"].append({
                            "path": path,
                            "status": check_result["status_code"]
                        })
                        print(f"    ⚠️  Disallowed path accessible: {path}")
                
                # Determinar severidad
                if len(result["accessible_disallowed"]) >= 2:
                    result["severity"] = "medium"
                elif result["accessible_disallowed"]:
                    result["severity"] = "low"
                    
        except Exception as e:
            # robots.txt no disponible o error - no mostrar en producción
            pass
        
        return result
    
    def scan_directory_listing(self, base_url: str, max_checks: int = 5) -> Dict:
        """
        Escanea directorios en busca de directory listing
        
        Args:
            base_url: URL base del sitio
            max_checks: Máximo número de directorios a verificar
            
        Returns:
            Dict con directorios expuestos
        """
        result = {
            "directories_checked": 0,
            "exposed_directories": [],
            "severity": "none"
        }
        
        print(f"  🔍 Checking directory listings (max {max_checks})...")
        
        for directory in self.COMMON_DIRECTORIES[:max_checks]:
            result["directories_checked"] += 1
            
            check_result = self.check_directory_listing(base_url, directory)
            
            if check_result["has_listing"]:
                result["exposed_directories"].append({
                    "directory": directory,
                    "file_count": check_result["file_count_estimate"]
                })
                print(f"    ⚠️  Directory listing: /{directory}/ ({check_result['file_count_estimate']} files)")
        
        # Determinar severidad
        if len(result["exposed_directories"]) >= 2:
            result["severity"] = "high"
        elif result["exposed_directories"]:
            result["severity"] = "medium"
        
        return result
    
    def detect_all(self, base_url: str) -> Dict:
        """
        Ejecuta todas las verificaciones de información sensible
        
        Args:
            base_url: URL base del sitio
            
        Returns:
            Dict con todos los resultados
        """
        return {
            "sensitive_files": self.scan_sensitive_files(base_url, max_checks=15),
            "directory_listing": self.scan_directory_listing(base_url, max_checks=5),
            "install_files": self.scan_install_files(base_url),
            "admin_panels": self.scan_admin_panels(base_url),
            "log_files": self.scan_log_files(base_url),
            "robots_analysis": self.scan_robots_txt(base_url),
        }


def test_sensitive_info_detector():
    """Test del detector de información sensible"""
    print("🧪 Testing Sensitive Info Detector...")
    
    detector = SensitiveInfoDetector(timeout=5)
    
    # Test con un sitio de prueba
    # Nota: Usaremos httpbin.org que responde con 200 a ciertos paths
    test_url = "https://httpbin.org/"
    
    print(f"\n✓ Testing with: {test_url}")
    
    # Test 1: Verificar un archivo específico
    print("\n  Test 1 - Check single file:")
    result1 = detector.check_file_exists(test_url, "status/200")
    print(f"    Status: {result1['status_code']}")
    print(f"    Accessible: {result1['accessible']}")
    
    # Test 2: Verificar archivo 404
    print("\n  Test 2 - Check non-existent file:")
    result2 = detector.check_file_exists(test_url, "this-file-does-not-exist.php")
    print(f"    Status: {result2['status_code']}")
    print(f"    Accessible: {result2['accessible']}")
    
    print("\n✅ Sensitive Info Detector tests completed!")
    print("\n⚠️  Note: Full scan skipped to avoid excessive requests")
    print("   Run with real targets using scanner.py")
    
    return True


if __name__ == "__main__":
    test_sensitive_info_detector()
