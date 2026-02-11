# Ejemplos de uso de la API

## Instalar dependencias

```bash
pip install -r requirements.txt
```

## Ejecutar localmente

```bash
python app.py
```

La API estará disponible en `http://localhost:5000`

## Endpoints

### 1. Health Check
```bash
curl http://localhost:5000/api/health
```

### 2. Escaneo Rápido (Solo Fase 1)
```bash
curl -X POST http://localhost:5000/api/quick-check \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

### 3. Escaneo Completo (Fases 1 y 2)
```bash
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com",
    "enable_phase2": true,
    "timeout": 15
  }'
```

### 4. Obtener resultado de escaneo
```bash
curl http://localhost:5000/api/scan/scan_1_1234567890
```

### 5. Listar todos los escaneos
```bash
curl http://localhost:5000/api/scans?limit=10
```

## Ejemplo con Python

```python
import requests

# Escaneo completo
response = requests.post('http://localhost:5000/api/scan', json={
    'url': 'https://example.com',
    'enable_phase2': True,
    'timeout': 15
})

result = response.json()
print(f"Scan ID: {result['scan_id']}")
print(f"Severity: {result['data']['overall_severity']}")
print(f"Issues: {result['data']['issues_summary']['total']}")
```

## Detecciones implementadas

### Fase 1 - Detecciones Básicas (Rápido)
- ✅ Errores PHP/código visible
- ✅ Errores de base de datos
- ✅ Sitios hackeados
- ✅ Spam SEO injection
- ✅ Malware (eval, base64_decode, etc.)
- ✅ Certificado SSL
- ✅ Headers de seguridad
- ✅ SEO básico (title, meta, H1, alt text)
- ✅ CMS/plugins desactualizados (WordPress, etc.)
- ✅ Contenido placeholder (Lorem ipsum, etc.)
- ✅ Copyright desactualizado

### Fase 2 - Detecciones Avanzadas (Más intensivo)
- ✅ Archivos sensibles expuestos (.env, .git, backups, etc.)
- ✅ Directory listing habilitado
- ✅ Información de configuración expuesta

## Deploy en Render

1. Crear cuenta en [Render.com](https://render.com)

2. Crear nuevo Web Service

3. Conectar repositorio de GitHub

4. Configuración:
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn app:app --bind 0.0.0.0:$PORT --workers 2 --timeout 120`
   - **Environment**: Python 3

5. Variables de entorno (opcional):
   - `PYTHON_VERSION`: 3.11.7

6. Deploy!

La API estará disponible en: `https://tu-app.onrender.com`

## Testar API desplegada

```bash
curl https://tu-app.onrender.com/api/health
```

## Notas de rendimiento

- **Escaneo rápido (Fase 1)**: ~1-3 segundos
- **Escaneo completo (Fase 1 + 2)**: ~10-30 segundos (depende de la cantidad de archivos a verificar)

La Fase 2 hace múltiples requests para verificar archivos sensibles, por lo que es más lenta pero más completa.

## Rate Limiting

Actualmente no hay rate limiting implementado. Para producción, se recomienda agregar:
- Rate limiting por IP
- Caché de resultados
- Queue system para escaneos largos
