"""
Script simple para testear el scanner desde línea de comandos
"""
import sys
from scanner import WebScanner

def main():
    if len(sys.argv) < 2:
        print("Usage: python test_scanner.py <url> [--no-phase2]")
        print("\nExample:")
        print("  python test_scanner.py https://example.com")
        print("  python test_scanner.py example.com --no-phase2")
        sys.exit(1)
    
    url = sys.argv[1]
    enable_phase2 = '--no-phase2' not in sys.argv
    
    print(f"\n🔍 Scanning: {url}")
    print(f"   Phase 2: {'enabled' if enable_phase2 else 'disabled'}\n")
    
    scanner = WebScanner(timeout=15, enable_phase2=enable_phase2)
    result = scanner.scan(url)
    scanner.print_summary(result)

if __name__ == "__main__":
    main()
