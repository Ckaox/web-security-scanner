"""
Script de prueba para la API del scanner
"""
import requests
import json
import time

API_BASE_URL = "http://localhost:5000/api"


def print_section(title):
    print("\n" + "="*70)
    print(f"  {title}")
    print("="*70)


def test_health_check():
    """Test del health check endpoint"""
    print_section("TEST 1: Health Check")
    
    try:
        response = requests.get(f"{API_BASE_URL}/health")
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        return response.status_code == 200
    except Exception as e:
        print(f"❌ Error: {e}")
        return False


def test_quick_check(url="httpbin.org/html"):
    """Test del quick check (sin Fase 2)"""
    print_section(f"TEST 2: Quick Check - {url}")
    
    try:
        payload = {"url": url}
        print(f"Sending: {json.dumps(payload)}")
        
        start = time.time()
        response = requests.post(f"{API_BASE_URL}/quick-check", json=payload)
        duration = time.time() - start
        
        print(f"\nStatus Code: {response.status_code}")
        print(f"Request Duration: {duration:.2f}s")
        
        if response.status_code == 200:
            data = response.json()
            print(f"\n✅ Success!")
            print(f"   Overall Severity: {data['data']['overall_severity']}")
            print(f"   Scan Duration: {data['data']['scan_duration']}s")
            print(f"   Issues Found: {data['data']['issues_summary']['total']}")
            return True
        else:
            print(f"❌ Error: {response.json()}")
            return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False


def test_full_scan(url="httpbin.org/html", enable_phase2=False):
    """Test del full scan"""
    print_section(f"TEST 3: Full Scan - {url} (Phase 2: {enable_phase2})")
    
    try:
        payload = {
            "url": url,
            "enable_phase2": enable_phase2,
            "timeout": 15
        }
        print(f"Sending: {json.dumps(payload)}")
        
        start = time.time()
        response = requests.post(f"{API_BASE_URL}/scan", json=payload)
        duration = time.time() - start
        
        print(f"\nStatus Code: {response.status_code}")
        print(f"Request Duration: {duration:.2f}s")
        
        if response.status_code == 200:
            data = response.json()
            scan_id = data['scan_id']
            scan_data = data['data']
            
            print(f"\n✅ Success!")
            print(f"   Scan ID: {scan_id}")
            print(f"   Overall Severity: {scan_data['overall_severity']}")
            print(f"   Scan Duration: {scan_data['scan_duration']}s")
            print(f"   Issues Summary:")
            for severity, count in scan_data['issues_summary'].items():
                if severity != 'total' and count > 0:
                    print(f"      {severity}: {count}")
            
            return True, scan_id
        else:
            print(f"❌ Error: {response.json()}")
            return False, None
    except Exception as e:
        print(f"❌ Error: {e}")
        return False, None


def test_get_scan(scan_id):
    """Test de obtener resultado por ID"""
    print_section(f"TEST 4: Get Scan Result - {scan_id}")
    
    try:
        response = requests.get(f"{API_BASE_URL}/scan/{scan_id}")
        print(f"Status Code: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"\n✅ Found scan!")
            print(f"   URL: {data['data']['url']}")
            print(f"   Timestamp: {data['data']['scan_timestamp']}")
            return True
        else:
            print(f"❌ Error: {response.json()}")
            return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False


def test_list_scans():
    """Test de listar escaneos"""
    print_section("TEST 5: List Scans")
    
    try:
        response = requests.get(f"{API_BASE_URL}/scans?limit=5")
        print(f"Status Code: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"\n✅ Success!")
            print(f"   Total scans: {data['total']}")
            print(f"   Showing: {data['showing']}")
            
            if data['scans']:
                print(f"\n   Recent scans:")
                for scan in data['scans'][:3]:
                    print(f"      - {scan['scan_id']}: {scan['url']} ({scan['severity']})")
            
            return True
        else:
            print(f"❌ Error: {response.json()}")
            return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False


def test_invalid_url():
    """Test con URL inválida"""
    print_section("TEST 6: Invalid URL")
    
    try:
        payload = {"url": "not-a-valid-url"}
        response = requests.post(f"{API_BASE_URL}/quick-check", json=payload)
        
        print(f"Status Code: {response.status_code}")
        
        if response.status_code == 400:
            print(f"✅ Correctly rejected invalid URL")
            print(f"   Error: {response.json().get('message')}")
            return True
        else:
            print(f"❌ Should have returned 400")
            return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False


def run_all_tests():
    """Ejecuta todos los tests"""
    print("\n" + "🧪 " + "="*66)
    print("  API TESTING SUITE")
    print("="*69)
    print("\n⚠️  Make sure the API is running on http://localhost:5000")
    print("   Run: python app.py\n")
    
    input("Press Enter to start tests...")
    
    results = []
    
    # Test 1: Health Check
    results.append(("Health Check", test_health_check()))
    time.sleep(1)
    
    # Test 2: Quick Check
    results.append(("Quick Check", test_quick_check()))
    time.sleep(1)
    
    # Test 3: Full Scan (sin Fase 2 para ser más rápido)
    success, scan_id = test_full_scan(enable_phase2=False)
    results.append(("Full Scan", success))
    time.sleep(1)
    
    # Test 4: Get Scan (si tenemos scan_id)
    if scan_id:
        results.append(("Get Scan", test_get_scan(scan_id)))
        time.sleep(1)
    
    # Test 5: List Scans
    results.append(("List Scans", test_list_scans()))
    time.sleep(1)
    
    # Test 6: Invalid URL
    results.append(("Invalid URL", test_invalid_url()))
    
    # Resumen
    print_section("TEST SUMMARY")
    passed = sum(1 for _, success in results if success)
    total = len(results)
    
    for test_name, success in results:
        emoji = "✅" if success else "❌"
        print(f"{emoji} {test_name}")
    
    print(f"\n{'='*70}")
    print(f"  Passed: {passed}/{total} ({passed/total*100:.0f}%)")
    print(f"{'='*70}\n")
    
    return passed == total


if __name__ == "__main__":
    run_all_tests()
