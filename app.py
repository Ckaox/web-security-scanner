"""
API REST para el Web Scanner
"""
from flask import Flask, request, jsonify
from flask_cors import CORS
from scanner import WebScanner
import validators
from datetime import datetime
import traceback

app = Flask(__name__)
CORS(app)  # Permitir CORS para llamadas desde cualquier origen

# Estado global para almacenar historial (en producción usar DB)
scan_history = {}
scan_counter = 0


@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0",
        "phases": ["Phase 1 - Basic", "Phase 2 - Sensitive Files"]
    })


@app.route('/api/scan', methods=['POST'])
def scan_url():
    """
    Endpoint principal para escanear una URL
    
    Body JSON:
    {
        "url": "https://example.com",
        "enable_phase2": true,  // opcional, default: true
        "timeout": 15  // opcional, default: 15
    }
    
    Returns:
        JSON con resultados del escaneo
    """
    global scan_counter, scan_history
    
    try:
        # Validar request
        if not request.json:
            return jsonify({
                "error": "Missing JSON body",
                "message": "Request must include JSON with 'url' field"
            }), 400
        
        url = request.json.get('url')
        if not url:
            return jsonify({
                "error": "Missing URL",
                "message": "Request must include 'url' field"
            }), 400
        
        # Validar formato de URL
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        if not validators.url(url):
            return jsonify({
                "error": "Invalid URL",
                "message": f"'{url}' is not a valid URL"
            }), 400
        
        # Obtener configuración opcional
        enable_phase2 = request.json.get('enable_phase2', True)
        timeout = request.json.get('timeout', 15)
        
        # Validar timeout
        if not isinstance(timeout, (int, float)) or timeout < 1 or timeout > 60:
            return jsonify({
                "error": "Invalid timeout",
                "message": "Timeout must be between 1 and 60 seconds"
            }), 400
        
        # Crear scanner y ejecutar
        scanner = WebScanner(
            timeout=timeout,
            enable_phase2=enable_phase2
        )
        
        print(f"\n🔍 Starting scan for: {url}")
        print(f"   Phase 2: {'enabled' if enable_phase2 else 'disabled'}")
        
        scan_result = scanner.scan(url)
        
        # Agregar ID al resultado
        scan_counter += 1
        scan_id = f"scan_{scan_counter}_{int(datetime.now().timestamp())}"
        scan_result["scan_id"] = scan_id
        
        # Guardar en historial (limitado a últimos 100)
        scan_history[scan_id] = scan_result
        if len(scan_history) > 100:
            # Eliminar el más antiguo por timestamp
            oldest = min(
                scan_history.keys(),
                key=lambda k: scan_history[k].get('scan_timestamp', '')
            )
            del scan_history[oldest]
        
        print(f"✅ Scan completed: {scan_id}")
        print(f"   Severity: {scan_result['overall_severity']}")
        print(f"   Duration: {scan_result['scan_duration']}s")
        
        return jsonify({
            "success": True,
            "scan_id": scan_id,
            "data": scan_result
        }), 200
    
    except Exception as e:
        error_trace = traceback.format_exc()
        print(f"❌ Error during scan: {str(e)}")
        print(error_trace)
        
        return jsonify({
            "error": "Scan failed",
            "message": str(e),
            "type": type(e).__name__
        }), 500


@app.route('/api/scan/<scan_id>', methods=['GET'])
def get_scan_result(scan_id):
    """
    Obtiene resultado de un escaneo previo
    
    Args:
        scan_id: ID del escaneo
        
    Returns:
        JSON con resultado del escaneo
    """
    if scan_id not in scan_history:
        return jsonify({
            "error": "Scan not found",
            "message": f"No scan found with ID '{scan_id}'"
        }), 404
    
    return jsonify({
        "success": True,
        "scan_id": scan_id,
        "data": scan_history[scan_id]
    }), 200


@app.route('/api/scans', methods=['GET'])
def list_scans():
    """
    Lista todos los escaneos en historial
    
    Query params:
        limit: número máximo de resultados (default: 20)
        
    Returns:
        JSON con lista de escaneos
    """
    limit = request.args.get('limit', 20, type=int)
    limit = min(max(1, limit), 100)  # Entre 1 y 100
    
    # Ordenar por timestamp (más recientes primero)
    sorted_scans = sorted(
        scan_history.items(),
        key=lambda x: x[1].get('scan_timestamp', ''),
        reverse=True
    )
    
    # Tomar solo los campos básicos para la lista
    scans_list = []
    for scan_id, scan_data in sorted_scans[:limit]:
        scans_list.append({
            "scan_id": scan_id,
            "url": scan_data.get('url'),
            "timestamp": scan_data.get('scan_timestamp'),
            "severity": scan_data.get('overall_severity'),
            "duration": scan_data.get('scan_duration'),
            "total_issues": scan_data.get('issues_summary', {}).get('total', 0)
        })
    
    return jsonify({
        "success": True,
        "total": len(scan_history),
        "showing": len(scans_list),
        "scans": scans_list
    }), 200


@app.route('/api/quick-check', methods=['POST'])
def quick_check():
    """
    Verificación rápida solo con Fase 1 (sin archivos sensibles)
    
    Body JSON:
    {
        "url": "https://example.com"
    }
    """
    try:
        if not request.json or not request.json.get('url'):
            return jsonify({
                "error": "Missing URL",
                "message": "Request must include 'url' field"
            }), 400
        
        url = request.json.get('url')
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        if not validators.url(url):
            return jsonify({
                "error": "Invalid URL",
                "message": f"'{url}' is not a valid URL"
            }), 400
        
        # Scanner rápido sin Fase 2
        scanner = WebScanner(timeout=10, enable_phase2=False)
        scan_result = scanner.scan(url)
        
        return jsonify({
            "success": True,
            "data": scan_result
        }), 200
    
    except Exception as e:
        return jsonify({
            "error": "Quick check failed",
            "message": str(e)
        }), 500


@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "error": "Not found",
        "message": "Endpoint not found"
    }), 404


@app.errorhandler(500)
def internal_error(error):
    return jsonify({
        "error": "Internal server error",
        "message": str(error)
    }), 500


if __name__ == '__main__':
    print("="*70)
    print("🚀 Web Security Scanner API")
    print("="*70)
    print("\nAvailable endpoints:")
    print("  GET  /api/health         - Health check")
    print("  POST /api/scan           - Full scan (Phase 1 + 2)")
    print("  POST /api/quick-check    - Quick scan (Phase 1 only)")
    print("  GET  /api/scan/<id>      - Get scan result")
    print("  GET  /api/scans          - List all scans")
    print("\n" + "="*70)
    print("Starting server on http://0.0.0.0:5000")
    print("="*70 + "\n")
    
    app.run(host='0.0.0.0', port=5000, debug=False)
