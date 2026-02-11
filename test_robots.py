#!/usr/bin/env python3
"""
Test rápido para robots.txt analysis
"""

from detector_sensitive_info import SensitiveInfoDetector

def test_robots_analysis():
    print("🧪 Testing robots.txt Analysis\n")
    
    # Test con GitHub que tiene robots.txt
    base_url = "https://github.com"
    detector = SensitiveInfoDetector()  # Sin parámetros, usa defaults
    
    print(f"📡 Testing: {base_url}")
    print("-" * 60)
    
    result = detector.scan_robots_txt(base_url)
    
    print(f"\n✓ robots.txt encontrado: {result['has_robots']}")
    print(f"  Paths Disallow encontrados: {len(result['disallowed_paths'])}")
    print(f"  Paths Disallow accesibles (problema): {len(result['accessible_disallowed'])}")
    print(f"  Severidad: {result['severity']}")
    
    if result['disallowed_paths']:
        print(f"\n📋 Primeros 5 paths Disallow:")
        for path in result['disallowed_paths'][:5]:
            print(f"     - {path}")
    
    if result['accessible_disallowed']:
        print(f"\n⚠️  Paths accesibles (deberían estar bloqueados):")
        for item in result['accessible_disallowed'][:3]:
            print(f"     🚨 {item['path']} (HTTP {item['status']})")
    
    print("\n" + "="*60)
    print("✅ Test completado!")

if __name__ == "__main__":
    test_robots_analysis()
