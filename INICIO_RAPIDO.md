# 🔍 Web Security Scanner - Guía de Inicio Rápido

## 📦 Estructura del Proyecto

```
Error webs scraper/
├── 📄 Core del Scanner
│   ├── scanner.py                    # Scanner principal
│   ├── detector_php_errors.py        # Detector de errores PHP/DB
│   ├── detector_hack_spam.py         # Detector de hackeos y spam
│   ├── detector_ssl_seo.py           # Detector de SSL y SEO
│   ├── detector_cms_placeholder.py   # Detector de CMS y placeholder
│   └── detector_sensitive_info.py    # Detector de info sensible (Fase 2)
│
├── 🌐 API REST
│   ├── app.py                        # API Flask
│   └── test_api.py                   # Tests de la API
│
├── 🧪 Testing
│   ├── test_scanner.py               # Script CLI para testing
│   └── DETECCIONES.py                # Resumen de detecciones
│
├── 📋 Deployment
│   ├── requirements.txt              # Dependencias Python
│   ├── Procfile                      # Configuración Render
│   ├── runtime.txt                   # Versión de Python
│   └── .gitignore                    # Archivos a ignorar
│
└── 📖 Documentación
    ├── README.md                     # Documentación principal
    └── USAGE.md                      # Guía de uso de la API
```

## 🚀 Inicio Rápido (3 pasos)

### 1️⃣ Instalar dependencias

```powershell
pip install -r requirements.txt
```

### 2️⃣ Testear el scanner (CLI)

```powershell
# Escaneo rápido sin Fase 2
python test_scanner.py example.com --no-phase2

# Escaneo completo con Fase 2
python test_scanner.py example.com
```

### 3️⃣ Ejecutar la API

```powershell
python app.py
```

La API estará en: `http://localhost:5000`

## 🧪 Testear la API

En otra terminal:

```powershell
# Método 1: Suite completa de tests
python test_api.py

# Método 2: Con curl
curl http://localhost:5000/api/health
```

## 📝 Ejemplos de Uso

### Escaneo Rápido (1-3 segundos)

```powershell
# PowerShell
$body = @{ url = "https://example.com" } | ConvertTo-Json
Invoke-RestMethod -Uri "http://localhost:5000/api/quick-check" -Method POST -Body $body -ContentType "application/json"
```

### Escaneo Completo (10-30 segundos)

```powershell
# PowerShell
$body = @{
    url = "https://example.com"
    enable_phase2 = $true
    timeout = 15
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://localhost:5000/api/scan" -Method POST -Body $body -ContentType "application/json"
```

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
print(f"Issues: {result['data']['issues_summary']['total']}")

# Detalles de problemas
if result['data']['results']['php_errors']['has_errors']:
    print("⚠️ Errores PHP encontrados!")

if result['data']['results']['security']['is_hacked']:
    print("🚨 ¡SITIO HACKEADO!")
```

## 🌐 Deploy en Render

### Opción 1: Desde GitHub

1. Sube el proyecto a GitHub
2. Ve a [Render.com](https://render.com) → New → Web Service
3. Conecta tu repositorio
4. Render detectará automáticamente Procfile y requirements.txt
5. Click en "Create Web Service"
6. ¡Listo! Tu API estará en `https://tu-app.onrender.com`

### Opción 2: Deploy Manual

1. En Render.com → New → Web Service
2. Configuración:
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn app:app --bind 0.0.0.0:$PORT --workers 2 --timeout 120`
   - **Environment**: Python 3
3. Deploy!

### Variables de Entorno (Opcional)

```
PYTHON_VERSION=3.11.7
```

## 📊 ¿Qué detecta?

### ✅ Fase 1 (Rápido - 1-3 seg)
- Errores PHP/JavaScript visibles
- Errores de base de datos
- Sitios hackeados
- Spam SEO injection
- Código malicioso (eval, base64)
- Problemas de SSL/HTTPS
- Headers de seguridad faltantes
- SEO básico (title, meta, H1, alt)
- CMS desactualizados (WordPress, etc.)
- Contenido placeholder
- Copyright desactualizado

### 🔴 Fase 2 (Intensivo - 10-30 seg)
- Archivos sensibles expuestos (.env, .git, backups)
- Directory listing habilitado
- Paneles de admin accesibles

## 🎯 Casos de Uso

### Para Desarrolladores Web
```powershell
# Verificar tu sitio antes de entregar al cliente
python test_scanner.py tucliente.com
```

### Para Agencias
```python
# Script para verificar múltiples sitios
import requests

sitios = ['cliente1.com', 'cliente2.com', 'cliente3.com']

for sitio in sitios:
    result = requests.post('http://localhost:5000/api/quick-check', 
                          json={'url': sitio})
    data = result.json()['data']
    print(f"{sitio}: {data['overall_severity']} - {data['issues_summary']['total']} issues")
```

### Para Ventas
- Escanea el sitio del prospecto
- Muestra los problemas encontrados
- Ofrece tu servicio de corrección

## 📈 Próximas Mejoras Sugeridas

- [ ] Rate limiting por IP
- [ ] Caché de resultados recientes
- [ ] Queue system para escaneos largos
- [ ] Base de datos para persistencia
- [ ] Dashboard web con resultados visuales
- [ ] Exportar reportes en PDF
- [ ] Webhooks para notificaciones
- [ ] Escaneos programados

## 🆘 Troubleshooting

### Error: "ModuleNotFoundError"
```powershell
pip install -r requirements.txt
```

### La API no responde
```powershell
# Verificar que está corriendo
netstat -ano | findstr :5000
```

### Timeout en Fase 2
```json
{
  "url": "example.com",
  "enable_phase2": false  // Deshabilitar Fase 2
}
```

## 💡 Tips

1. **Fase 1** es suficiente para la mayoría de casos
2. **Fase 2** úsala solo cuando necesites verificar archivos expuestos
3. Para batch scanning, usa `quick-check` (más rápido)
4. Guarda los `scan_id` para consultar resultados después

## 📞 Soporte

¿Preguntas? Revisa:
- `DETECCIONES.py` - Lista completa de detecciones
- `USAGE.md` - Guía detallada de API
- `test_api.py` - Ejemplos de uso

---

**¡Listo para detectar problemas en sitios web!** 🚀
