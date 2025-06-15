# Οδηγός Γρήγορης Αναφοράς - Παρουσίαση Penetration Test

## 🎯 Key Points για κάθε Ευπάθεια

### 1. SQL Injection
**One-liner**: "Πλήρης πρόσβαση στη βάση δεδομένων με ένα απλό quote"
- **Demo**: `' OR '1'='1`
- **Impact**: Κλοπή όλων των passwords
- **Fix**: Parameterized queries

### 2. XSS
**One-liner**: "Κλοπή cookies και phishing μέσω αναζήτησης"
- **Demo**: `<script>alert('XSS')</script>`
- **Impact**: Session hijacking
- **Fix**: Output encoding

### 3. Authentication
**One-liner**: "Μάντεψε το password σε 5 λεπτά"
- **Demo**: Different error messages
- **Impact**: Account takeover
- **Fix**: Generic errors + rate limiting

### 4. IDOR
**One-liner**: "Δες τις παραγγελίες όλων αλλάζοντας ένα νούμερο"
- **Demo**: Change order ID in URL
- **Impact**: Data breach
- **Fix**: Access control checks

### 5. CSRF
**One-liner**: "Μεταφορά χρημάτων χωρίς να το ξέρεις"
- **Demo**: Hidden form auto-submit
- **Impact**: Unauthorized transactions
- **Fix**: CSRF tokens

## 📊 Slide Structure (15 λεπτά)

### Slide 1: Τίτλος (30 sec)
- Τίτλος εργασίας
- Όνομα/ΑΜ
- Μάθημα CDS201

### Slide 2: Agenda (30 sec)
1. Scope & Μεθοδολογία
2. Ευρήματα (5 vulnerabilities)
3. Live Demonstrations
4. Business Impact
5. Συστάσεις

### Slide 3: Scope & Tools (1 min)
- Django E-Shop Application
- OWASP Testing Guide
- Tools: Burp, SQLMap, Hydra, Python

### Slides 4-8: Vulnerabilities (2 min each = 10 min)
Για κάθε vulnerability:
- Τι είναι
- Πού βρέθηκε
- Live demo / Screenshot
- Impact
- Quick fix

### Slide 9: Risk Matrix (1 min)
Heat map με τις 5 ευπάθειες

### Slide 10: Business Impact (1 min)
- €100k+ potential losses
- GDPR violations
- Customer trust

### Slide 11: Recommendations (1 min)
- Immediate: Fix critical
- Short-term: Security training  
- Long-term: SDL process

### Slide 12: Q&A (30 sec)
"Ερωτήσεις;"

## 🚀 Quick Commands

```bash
# Terminal 1 - Start App
cd secure_eshop
python manage.py runserver

# Terminal 2 - SQL Injection
curl "http://localhost:8000/catalog/?q=' OR '1'='1"

# Terminal 3 - XSS
open xss_poc.html

# Terminal 4 - IDOR
python scripts/exploits/idor_exploit.py

# Terminal 5 - CSRF
python scripts/exploits/csrf_exploit.py
```

## 🎭 Demo Flow

### SQL Injection (2 min)
1. Normal search: "laptop"
2. Malicious: `' OR '1'='1`
3. Extract users: `' UNION SELECT...`
4. Show SQLMap

### XSS (2 min)
1. Search: `<script>alert(1)</script>`
2. Submit review with script
3. Show cookie theft

### Auth (2 min)
1. Show different errors
2. Run brute force
3. Crack MD5 hash

### IDOR (1 min)
1. Show my order
2. Change ID
3. See other's data

### CSRF (1 min)
1. Show no token
2. Open attack page
3. Auto-submit

## 💡 Power Phrases

- "Με ένα μόνο quote, έχω πρόσβαση σε όλα"
- "Το 90% των attacks είναι automated"
- "Security is not a feature, it's a process"
- "Ένα breach κοστίζει 100x περισσότερο από την πρόληψη"
- "GDPR fine up to 4% of annual turnover"

## 🔧 Troubleshooting

### "Demo δεν δουλεύει"
→ "Ας δούμε το screenshot που είχα ετοιμάσει"

### "Γιατί είναι σημαντικό;"
→ "Equifax breach: $700M, Yahoo: 3B accounts"

### "Πόσο εύκολο είναι;"
→ "Script kiddies με automated tools"

### "Υπάρχει 100% ασφάλεια;"
→ "Defense in depth, not single solution"

## 📝 Closing Statement

"Η ασφάλεια δεν είναι προϊόν αλλά διαδικασία. Οι ευπάθειες που είδαμε σήμερα είναι αποτρέψιμες με:
1. Secure coding practices
2. Regular testing
3. Developer training

Το κόστος της πρόληψης είναι ελάχιστο συγκριτικά με το κόστος ενός breach.

Ευχαριστώ για την προσοχή σας. Ερωτήσεις;"

## 🎯 Backup USB Contents

```
/USB_BACKUP/
├── PENETRATION_TEST_REPORT_GREEK.pdf
├── screenshots/
│   ├── 01_sql_injection.png
│   ├── 02_xss_reflected.png
│   ├── 03_xss_stored.png
│   ├── 04_user_enum.png
│   ├── 05_brute_force.png
│   ├── 06_idor.png
│   └── 07_csrf.png
├── demos/
│   ├── sql_injection_demo.mp4
│   ├── xss_demo.mp4
│   └── csrf_demo.mp4
├── exploits/
│   └── all_exploit_scripts.zip
└── presentation.pptx
```

## ⏱️ Time Management

- **Total**: 15 minutes
- **Buffer**: Keep 1 minute buffer
- **Timer**: Phone on silent, visible timer
- **Pace**: If behind, skip auth details
- **If ahead**: Expand on business impact

## 🎪 Showmanship Tips

1. **Start strong**: "Σε 15 λεπτά θα σας δείξω πώς να χακάρετε αυτό το site"
2. **Eye contact**: Scan the room
3. **Voice**: Clear, confident, vary pace
4. **Hands**: Use for emphasis, not fidgeting
5. **End strong**: "Questions?" + smile

---

**Remember**: You're the expert in the room. You built these vulnerabilities, you know them inside out. Confidence is key! 

Καλή επιτυχία! 🚀