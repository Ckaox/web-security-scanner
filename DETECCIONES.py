"""
Resumen de todas las detecciones implementadas
"""

DETECCIONES_FASE_1 = {
    "Errores de Código": {
        "description": "Detecta errores PHP, JavaScript y de código visibles",
        "patterns": [
            "Fatal error:",
            "Parse error:",
            "Warning: require/include",
            "Uncaught Error",
            "Notice: Undefined",
            "Call to undefined function"
        ],
        "severity": "high/critical",
        "implementation": "detector_php_errors.py"
    },
    
    "Errores de Base de Datos": {
        "description": "Detecta errores de conexión y SQL expuestos",
        "patterns": [
            "PDOException",
            "SQL syntax error",
            "Access denied for user",
            "Too many connections",
            "Table doesn't exist"
        ],
        "severity": "critical",
        "implementation": "detector_php_errors.py"
    },
    
    "Sitios Hackeados": {
        "description": "Detecta indicadores evidentes de hackeo",
        "patterns": [
            "hacked by",
            "defaced by",
            "injected by",
            "pwned by",
            "site has been hacked"
        ],
        "severity": "critical",
        "implementation": "detector_hack_spam.py"
    },
    
    "Spam SEO Injection": {
        "description": "Detecta inyección de spam en el sitio",
        "patterns": [
            "casino online",
            "viagra/cialis/pharmacy",
            "payday loans",
            "gambling keywords",
            "Contenido oculto con spam"
        ],
        "severity": "high",
        "implementation": "detector_hack_spam.py"
    },
    
    "Malware": {
        "description": "Detecta código malicioso común",
        "patterns": [
            "eval(base64_decode(",
            "eval(gzinflate(",
            "assert(base64_decode(",
            "eval(str_rot13("
        ],
        "severity": "critical",
        "implementation": "detector_hack_spam.py"
    },
    
    "SSL y Seguridad": {
        "description": "Verifica HTTPS y headers de seguridad",
        "checks": [
            "Uso de HTTPS",
            "HSTS header",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Mixed content"
        ],
        "severity": "high",
        "implementation": "detector_ssl_seo.py"
    },
    
    "SEO Básico": {
        "description": "Análisis SEO fundamental",
        "checks": [
            "Title tag (existencia, longitud, contenido)",
            "Meta description",
            "H1 tags (cantidad, contenido)",
            "Canonical URL",
            "Imágenes sin alt text",
            "Open Graph tags"
        ],
        "severity": "low/medium",
        "implementation": "detector_ssl_seo.py"
    },
    
    "CMS Desactualizado": {
        "description": "Detecta WordPress y otros CMS con versiones antiguas",
        "detects": [
            "WordPress (versión, plugins, tema)",
            "Joomla",
            "Drupal",
            "Shopify",
            "Wix",
            "Librerías JS desactualizadas (jQuery, Bootstrap)"
        ],
        "severity": "high",
        "implementation": "detector_cms_placeholder.py"
    },
    
    "Contenido Placeholder": {
        "description": "Detecta contenido temporal o no finalizado",
        "patterns": [
            "Lorem ipsum",
            "Coming soon",
            "Under construction",
            "Imágenes placeholder",
            "Copyright desactualizado"
        ],
        "severity": "medium",
        "implementation": "detector_cms_placeholder.py"
    }
}

DETECCIONES_FASE_2 = {
    "Archivos Sensibles Expuestos": {
        "description": "Verifica accesibilidad de archivos confidenciales",
        "files_checked": [
            ".env",
            ".git/config",
            "phpinfo.php",
            "backup.sql",
            "database.sql",
            "wp-config.php.bak",
            "readme.html"
        ],
        "severity": "critical",
        "implementation": "detector_sensitive_info.py",
        "note": "Hace múltiples requests HTTP"
    },
    
    "Directory Listing": {
        "description": "Detecta directorios sin protección",
        "directories_checked": [
            "/admin",
            "/backup",
            "/uploads",
            "/private",
            "/.git"
        ],
        "severity": "high",
        "implementation": "detector_sensitive_info.py"
    }
}

METRICAS_RENDIMIENTO = {
    "Fase 1 (Quick Scan)": {
        "duration": "1-3 segundos",
        "http_requests": "1 (solo la página principal)",
        "intensity": "Bajo",
        "recommended_for": "Verificaciones rápidas, batch scanning"
    },
    
    "Fase 1 + 2 (Full Scan)": {
        "duration": "10-30 segundos",
        "http_requests": "15-20 (página + archivos + directorios)",
        "intensity": "Alto",
        "recommended_for": "Análisis completo de sitios individuales"
    }
}

ENDPOINTS_API = {
    "GET /api/health": "Health check del servicio",
    "POST /api/quick-check": "Escaneo rápido (solo Fase 1)",
    "POST /api/scan": "Escaneo completo (Fase 1 + 2 opcional)",
    "GET /api/scan/<id>": "Obtener resultado de escaneo por ID",
    "GET /api/scans": "Listar historial de escaneos"
}

if __name__ == "__main__":
    print("="*70)
    print("RESUMEN DE DETECCIONES IMPLEMENTADAS")
    print("="*70)
    
    print("\n🔵 FASE 1 - DETECCIONES BÁSICAS (Rápido)")
    print("-"*70)
    for nombre, info in DETECCIONES_FASE_1.items():
        print(f"\n✓ {nombre}")
        print(f"  {info['description']}")
        print(f"  Severidad: {info['severity']}")
    
    print("\n\n🔴 FASE 2 - DETECCIONES AVANZADAS (Intensivo)")
    print("-"*70)
    for nombre, info in DETECCIONES_FASE_2.items():
        print(f"\n✓ {nombre}")
        print(f"  {info['description']}")
        print(f"  Severidad: {info['severity']}")
    
    print("\n\n⚡ MÉTRICAS DE RENDIMIENTO")
    print("-"*70)
    for tipo, metrics in METRICAS_RENDIMIENTO.items():
        print(f"\n{tipo}:")
        for key, value in metrics.items():
            print(f"  {key}: {value}")
    
    print("\n\n🌐 API ENDPOINTS")
    print("-"*70)
    for endpoint, description in ENDPOINTS_API.items():
        print(f"{endpoint}")
        print(f"  → {description}")
    
    print("\n" + "="*70)
    print("Total Detecciones Fase 1: 9 categorías")
    print("Total Detecciones Fase 2: 2 categorías")
    print("="*70 + "\n")
