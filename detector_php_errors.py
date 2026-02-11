"""
Detector de errores PHP y de código visible en sitios web
"""
import re
from typing import List, Dict

class PHPErrorDetector:
    """Detecta errores PHP y de código visibles en el HTML"""
    
    # Patrones de errores PHP
    PHP_ERROR_PATTERNS = [
        r"Fatal error:.*?on line \d+",
        r"Parse error:.*?syntax error",
        r"Warning:.*?(?:require|include)",
        r"Uncaught Error",
        r"Deprecated:.*?function",
        r"Notice: Undefined",
        r"Call to undefined function",
        r"Failed to open stream",
    ]
    
    # Patrones de errores de base de datos
    DB_ERROR_PATTERNS = [
        r"mysql_connect\(\).*?error",
        r"PDOException",
        r"SQL syntax.*?error",
        r"Access denied for user",
        r"Too many connections",
        r"Table.*?doesn't exist",
        r"mysqli?_.*?error",
        r"Database connection failed",
    ]
    
    def __init__(self):
        self.php_regex = [re.compile(pattern, re.IGNORECASE) for pattern in self.PHP_ERROR_PATTERNS]
        self.db_regex = [re.compile(pattern, re.IGNORECASE) for pattern in self.DB_ERROR_PATTERNS]
    
    def detect(self, html_content: str, url: str) -> Dict:
        """
        Detecta errores PHP y de base de datos en el contenido HTML
        
        Args:
            html_content: Contenido HTML de la página
            url: URL de la página
            
        Returns:
            Dict con los errores encontrados
        """
        results = {
            "has_errors": False,
            "php_errors": [],
            "db_errors": [],
            "severity": "none"  # none, low, medium, high, critical
        }
        
        # Buscar errores PHP
        for regex in self.php_regex:
            matches = regex.findall(html_content)
            if matches:
                for match in matches[:3]:  # Limitar a 3 ejemplos
                    if match not in results["php_errors"]:
                        results["php_errors"].append(match[:200])  # Limitar longitud
        
        # Buscar errores de base de datos
        for regex in self.db_regex:
            matches = regex.findall(html_content)
            if matches:
                for match in matches[:3]:
                    if match not in results["db_errors"]:
                        results["db_errors"].append(match[:200])
        
        # Determinar severidad
        if results["php_errors"] or results["db_errors"]:
            results["has_errors"] = True
            # Errores de DB son más críticos
            if results["db_errors"]:
                results["severity"] = "critical"
            else:
                results["severity"] = "high"
        
        return results


def test_php_error_detector():
    """Test del detector de errores PHP"""
    print("🧪 Testing PHP Error Detector...")
    
    detector = PHPErrorDetector()
    
    # Test 1: HTML con error fatal de PHP
    html_with_fatal = """
    <html>
    <body>
        <br /><b>Fatal error:</b> Call to undefined function my_function() in 
        <b>/var/www/html/index.php</b> on line <b>42</b><br />
    </body>
    </html>
    """
    
    result1 = detector.detect(html_with_fatal, "http://example.com")
    print(f"\n✓ Test 1 - Fatal Error:")
    print(f"  Has errors: {result1['has_errors']}")
    print(f"  Severity: {result1['severity']}")
    print(f"  PHP Errors found: {len(result1['php_errors'])}")
    if result1['php_errors']:
        print(f"  Example: {result1['php_errors'][0][:100]}...")
    
    # Test 2: HTML con error de base de datos
    html_with_db_error = """
    <html><body>
        PDOException: SQLSTATE[HY000] [2002] Connection refused in database.php:15
    </body></html>
    """
    
    result2 = detector.detect(html_with_db_error, "http://example.com")
    print(f"\n✓ Test 2 - Database Error:")
    print(f"  Has errors: {result2['has_errors']}")
    print(f"  Severity: {result2['severity']}")
    print(f"  DB Errors found: {len(result2['db_errors'])}")
    
    # Test 3: HTML sin errores
    html_clean = "<html><body><h1>Welcome</h1><p>Normal content</p></body></html>"
    result3 = detector.detect(html_clean, "http://example.com")
    print(f"\n✓ Test 3 - Clean HTML:")
    print(f"  Has errors: {result3['has_errors']}")
    print(f"  Severity: {result3['severity']}")
    
    print("\n✅ PHP Error Detector tests completed!")
    return True


if __name__ == "__main__":
    test_php_error_detector()
