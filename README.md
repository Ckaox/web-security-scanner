# 🔍 Web Security & Error Scanner

**API REST para detectar problemas de seguridad, errores y optimización en sitios web**

![Python](https://img.shields.io/badge/python-3.11-blue)
![Flask](https://img.shields.io/badge/flask-3.0-green)
![License](https://img.shields.io/badge/license-MIT-blue)

Escáner profesional de sitios web que detecta:
- 🚨 Sitios hackeados y malware
- 🔴 Errores de código visibles
- 🔒 Problemas de seguridad y SSL
- 📈 Issues de SEO
- ⚠️ CMS desactualizados
- 📁 Archivos sensibles expuestos

## 🚀 Inicio Rápido

```bash
# 1. Instalar dependencias
pip install -r requirements.txt

# 2. Ejecutar API
python app.py

# 3. Escanear un sitio
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

## 📊 Características

### ✅ Fase 1 - Detecciones Básicas (1-3 segundos)
- **Errores de Código**: PHP Fatal Errors, Parse Errors, Warnings
- **Errores de DB**: PDOException, SQL errors, Connection failed
- **Sitios Hackeados**: "hacked by", "defaced by", mensajes de hackeo
- **Spam SEO**: Casino spam, pharma spam, contenido oculto
- **Malware**: eval(base64_decode), código ofuscado
- **API Keys Expuestas**: Stripe, AWS, Google, GitHub, etc. (12+ tipos)
- **Comentarios Sospechosos**: Passwords, TODOs, debug info en HTML
- **SSL/HTTPS**: Certificado, headers de seguridad (HSTS, X-Frame-Options)
- **SEO**: Title, meta description, H1, alt text, Open Graph
- **CMS**: WordPress desactualizado, plugins, librerías JS antiguas
- **Placeholder**: Lorem ipsum, "coming soon", copyright antiguo

### 🔴 Fase 2 - Detecciones Avanzadas (10-30 segundos)
- **Archivos Sensibles**: .env, .git/config, phpinfo.php, backups SQL (27 archivos)
- **Directory Listing**: Directorios expuestos (/admin, /backup, /uploads)
- **Archivos Instalación**: install.php, setup.php - CRÍTICO (8 archivos)
- **Paneles Admin**: wp-admin, phpmyadmin, /admin (12 paneles)
- **Archivos Log**: error.log, access.log, debug.log (9 archivos)
- **Robots.txt Intelligence**: Detecta si paths "Disallow" son accesibles

## 📖 Documentación

- **[INICIO_RAPIDO.md](INICIO_RAPIDO.md)** - Guía de inicio rápido
- **[USAGE.md](USAGE.md)** - Documentación completa de la API
- **[DETECCIONES.py](DETECCIONES.py)** - Lista detallada de todas las detecciones

## 🌐 API Endpoints

| Endpoint | Método | Descripción | Duración |
|----------|--------|-------------|----------|
| `/api/health` | GET | Health check | < 1s |
| `/api/quick-check` | POST | Escaneo rápido (Fase 1) | 1-3s |
| `/api/scan` | POST | Escaneo completo (Fase 1+2) | 10-30s |
| `/api/scan/<id>` | GET | Obtener resultado | < 1s |
| `/api/scans` | GET | Listar escaneos | < 1s |

## 💻 Uso desde Línea de Comandos

```bash
# Escaneo rápido
python test_scanner.py example.com --no-phase2

# Escaneo completo
python test_scanner.py example.com
```

## 🔧 Ejemplos de Uso

### Python

```python
import requests

# Escaneo completo
response = requests.post('http://localhost:5000/api/scan', json={
    'url': 'https://example.com',
    'enable_phase2': True,
    'timeout': 15
})

result = response.json()
print(f"Severidad: {result['data']['overall_severity']}")
print(f"Total issues: {result['data']['issues_summary']['total']}")

# Verificar problemas críticos
if result['data']['results']['security']['is_hacked']:
    print("🚨 ¡SITIO HACKEADO!")

if result['data']['results']['php_errors']['has_errors']:
    print("⚠️ Errores PHP encontrados")
```

### PowerShell

```powershell
$body = @{
    url = "https://example.com"
    enable_phase2 = $true
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://localhost:5000/api/scan" `
    -Method POST -Body $body -ContentType "application/json"
```

### cURL

```bash
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com",
    "enable_phase2": true,
    "timeout": 15
  }'
```

## 🎯 Casos de Uso

### Para Desarrolladores
- ✅ Verificar sitios antes de entregar a clientes
- ✅ Auditorías de seguridad automatizadas
- ✅ Monitoreo continuo de sitios en producción

### Para Agencias
- ✅ Prospección: escanea sitios de clientes potenciales
- ✅ Reportes de problemas para cerrar ventas
- ✅ Validación post-mantenimiento

### Para SEO
- ✅ Auditoría técnica SEO automatizada
- ✅ Detectar problemas de indexación
- ✅ Verificar meta tags y estructura

## 🚀 Deploy en Render

### 1. Subir a GitHub

```bash
git init
git add .
git commit -m "Initial commit"
git remote add origin <tu-repo>
git push -u origin main
```

### 2. Deploy en Render

1. Ve a [render.com](https://render.com)
2. New → Web Service
3. Conecta tu repositorio
4. Render detectará automáticamente la configuración
5. Click "Create Web Service"
6. ¡Listo! Tu API estará en `https://tu-app.onrender.com`

**Archivos de configuración incluidos:**
- `Procfile` - Configuración de Render
- `runtime.txt` - Python 3.11.7
- `requirements.txt` - Dependencias

## 📊 Respuesta de la API

```json
{
  "success": true,
  "scan_id": "scan_1_1707692400",
  "data": {
    "url": "https://example.com",
    "scan_timestamp": "2026-02-11 10:30:00",
    "scan_duration": 2.5,
    "overall_severity": "high",
    "issues_summary": {
      "critical": 0,
      "high": 2,
      "medium": 3,
      "low": 1,
      "total": 6
    },
    "results": {
      "php_errors": { "has_errors": false },
      "security": { "is_hacked": false, "has_spam_seo": true },
      "ssl": { "has_https": true, "issues": [...] },
      "seo": { "issues": [...] },
      "cms": { "is_wordpress": true, "version": "5.8.1" },
      "placeholder": { "has_placeholder": false },
      "sensitive_info": { ... }
    }
  }
}
```

## 🧪 Testing

```bash
# Ejecutar suite de tests de la API
python test_api.py

# Tests individuales de detectores
python detector_php_errors.py
python detector_hack_spam.py
python detector_ssl_seo.py
python detector_cms_placeholder.py
python detector_sensitive_info.py
```

## 📦 Estructura del Proyecto

```
├── scanner.py                    # Scanner principal
├── detector_php_errors.py        # Detector de errores
├── detector_hack_spam.py         # Detector de hackeos
├── detector_ssl_seo.py           # Detector SSL/SEO
├── detector_cms_placeholder.py   # Detector CMS
├── detector_sensitive_info.py    # Detector archivos sensibles
├── app.py                        # API Flask
├── test_scanner.py               # CLI tool
├── test_api.py                   # API tests
└── requirements.txt              # Dependencias
```

## ⚙️ Configuración

### Opciones del Scanner

```python
scanner = WebScanner(
    timeout=15,           # Timeout HTTP en segundos
    enable_phase2=True    # Habilitar escaneo de archivos
)
```

### Opciones de API Request

```json
{
  "url": "https://example.com",
  "enable_phase2": true,  // Opcional, default: true
  "timeout": 15           // Opcional, default: 15, max: 60
}
```

## 🔒 Seguridad

- ✅ Validación de URLs
- ✅ Timeout configurable
- ✅ Sin almacenamiento de credenciales
- ✅ Solo lectura (no modifica sitios)
- ⚠️ Rate limiting pendiente (próxima versión)

## 📈 Rendimiento

| Tipo de Scan | Duración | Requests HTTP | Uso |
|--------------|----------|---------------|-----|
| Quick Check (Fase 1) | 1-3s | 1 | Verificaciones rápidas |
| Full Scan (Fase 1+2) | 10-30s | 15-20 | Análisis completo |

## 🛠️ Tecnologías

- **Python 3.11**
- **Flask** - API REST
- **BeautifulSoup4** - HTML parsing
- **Requests** - HTTP client
- **Validators** - URL validation

## 📝 Licencia

MIT License - Libre para uso comercial y personal

## 🤝 Contribuciones

Las contribuciones son bienvenidas! Por favor:

1. Fork el proyecto
2. Crea una branch (`git checkout -b feature/nueva-deteccion`)
3. Commit cambios (`git commit -m 'Add nueva detección'`)
4. Push (`git push origin feature/nueva-deteccion`)
5. Abre un Pull Request

## 💡 Ideas para Mejoras

- [ ] Dashboard web con visualizaciones
- [ ] Exportar reportes en PDF
- [ ] Webhooks para notificaciones
- [ ] Escaneos programados
- [ ] Base de datos para historial persistente
- [ ] Rate limiting y caché
- [ ] Detección de más CMS (Magento, PrestaShop)
- [ ] Análisis de performance (Core Web Vitals)

## 📞 Soporte

Para preguntas o issues, abre un ticket en GitHub Issues.

---

**Desarrollado para detectar problemas en sitios web y ayudar a mejorar la seguridad online** 🔒
