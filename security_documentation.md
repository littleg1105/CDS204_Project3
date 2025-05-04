# Τεκμηρίωση Ασφάλειας - Secure E-Shop

## 1. Λειτουργικότητα αρχείων πηγαίου κώδικα

### models.py
- Περιγραφή των μοντέλων δεδομένων της εφαρμογής (Product, Cart, CartItem, κλπ)

### views.py
- Περιγραφή των views για login, catalog, add-to-cart, payment

### forms.py
- Περιγραφή των φορμών για login, shipping address, κλπ

### urls.py
- Περιγραφή των URL patterns της εφαρμογής

### templates/
- Περιγραφή των templates και του τρόπου που διασφαλίζουν την ασφάλεια

## 2. Διαχείριση δεδομένων συνόδου (Session Management)
- Παραγωγή secure session IDs μέσω του Django
- Ανανέωση session ID μετά τη σύνδεση για προστασία από session fixation
- Secure cookies με HttpOnly και SameSite flags

## 3. Προστασία από επιθέσεις User Enumeration
- Χρήση γενικών μηνυμάτων σφάλματος που δεν αποκαλύπτουν αν το username ή το password είναι λάθος
- Εφαρμογή σταθερού χρόνου καθυστέρησης (constant-time delay) για αποτροπή timing attacks
- Χρήση του django-axes για περιορισμό των προσπαθειών σύνδεσης

## 4. Προστασία κωδικών χρηστών στη βάση
- Χρήση του συστήματος hashing του Django (PBKDF2 με SHA256)
- Αποθήκευση μόνο των hash των κωδικών, ποτέ των ίδιων των κωδικών

## 5. Προστασία από SQL Injection
- Χρήση του ORM του Django για παραμετροποιημένα ερωτήματα
- Sanitization των παραμέτρων αναζήτησης και άλλων εισόδων χρήστη

## 6. Προστασία από CSRF
- Χρήση των CSRF tokens του Django σε όλες τις φόρμες POST
- Έλεγχος του HTTP Referer header
- Ρύθμιση του CSRF_COOKIE_SECURE και ασφαλείς πρακτικές για cookies

## 7. Προστασία από XSS
- Χρήση του συστήματος autoescape του Django στα templates
- Sanitization των δεδομένων εισόδου με τη βιβλιοθήκη bleach
- Εφαρμογή Content Security Policy

## 8. Άλλα μέτρα ασφαλείας
- Χρήση HTTPS με self-signed πιστοποιητικό
- Εφαρμογή HTTP Strict Transport Security (HSTS)
- Ρυθμίσεις ασφαλείας στο settings.py

## 9. Ρίσκα που δεν έχουν αντιμετωπιστεί
- Περιγραφή των ρίσκων που αναγνωρίζουμε αλλά δεν έχουμε αντιμετωπίσει