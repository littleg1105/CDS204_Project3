# Τεκμηρίωση Ασφάλειας - Secure E-Shop

## 1. Λειτουργικότητα αρχείων πηγαίου κώδικα

### models.py
- **Product**: Μοντέλο για την αποθήκευση των προϊόντων (όνομα, περιγραφή, τιμή, εικόνα)
- **Cart**: Αναπαριστά το καλάθι αγορών του χρήστη, συνδέεται με έναν χρήστη μέσω OneToOneField
- **CartItem**: Αναπαριστά ένα προϊόν στο καλάθι με την αντίστοιχη ποσότητα
- **ShippingAddress**: Αποθηκεύει τις διευθύνσεις αποστολής των χρηστών
- **Order**: Περιέχει τα στοιχεία μιας παραγγελίας (χρήστης, διεύθυνση, συνολικό ποσό, κατάσταση)
- **OrderItem**: Αναπαριστά ένα προϊόν σε μια παραγγελία με την ποσότητα και την τιμή αγοράς

### views.py
- **login_view**: Χειρίζεται την αυθεντικοποίηση των χρηστών
- **logout_view**: Χειρίζεται την αποσύνδεση των χρηστών
- **catalog_view**: Εμφανίζει τα προϊόντα, επιτρέπει την αναζήτηση, προστατεύει από XSS
- **add_to_cart**: Προσθέτει προϊόντα στο καλάθι του χρήστη, χρησιμοποιεί AJAX και CSRF protection
- **payment_view**: Διαχειρίζεται τη διαδικασία πληρωμής, συμπεριλαμβανομένης της επιβεβαίωσης παραγγελίας

### forms.py
- **LoginForm**: Φόρμα σύνδεσης με προστασία από user enumeration και timing attacks
- **ShippingAddressForm**: Φόρμα για καταχώρηση διεύθυνσης αποστολής με sanitization των εισόδων

### urls.py
- Ορίζει τα URL patterns της εφαρμογής, συνδέοντας τα URLs με τα αντίστοιχα views
- Χρησιμοποιεί την login_required διακόσμηση για τη διασφάλιση ότι μόνο αυθεντικοποιημένοι χρήστες έχουν πρόσβαση σε προστατευμένες σελίδες

### templates/
- **base.html**: Βασικό template με τη δομή της σελίδας, ρυθμίσεις CSP και φόρτωση των στατικών αρχείων
- **login.html**: Φόρμα σύνδεσης με CSRF protection
- **catalog.html**: Εμφάνιση προϊόντων, φόρμα αναζήτησης, προσθήκη στο καλάθι μέσω AJAX
- **payment.html**: Εμφάνιση καλαθιού, φόρμα διεύθυνσης, επιβεβαίωση παραγγελίας

### static/
- **css/styles.css**: Περιέχει τα styles της εφαρμογής (αποφεύγοντας inline styles για λόγους ασφαλείας CSP)
- **js/cart.js**: JavaScript για την προσθήκη προϊόντων στο καλάθι με AJAX

## 2. Διαχείριση δεδομένων συνόδου (Session Management)

Η διαχείριση των δεδομένων συνόδου (session data) στην εφαρμογή μας γίνεται ως εξής:

### Παραγωγή Session ID
- Χρησιμοποιούμε το ενσωματωμένο σύστημα sessions του Django
- Τα session IDs παράγονται με κρυπτογραφικά ασφαλείς γεννήτριες τυχαίων αριθμών
- Το Django χρησιμοποιεί το SECRET_KEY του project για την κρυπτογράφηση των sessions

### Έλεγχοι και ασφάλεια sessions
- Χρησιμοποιούμε το session framework του Django με την database-backed engine
- Έχουμε ενεργοποιήσει το SESSION_COOKIE_SECURE = True, διασφαλίζοντας ότι τα cookies αποστέλλονται μόνο μέσω HTTPS
- Έχουμε ορίσει το SESSION_COOKIE_HTTPONLY = True για να αποτρέψουμε την πρόσβαση στο session cookie μέσω JavaScript
- Χρησιμοποιούμε το SESSION_COOKIE_SAMESITE = 'Lax' για προστασία από CSRF επιθέσεις

### Προστασία από Session Fixation
- Μετά από επιτυχημένη σύνδεση, καλούμε την μέθοδο `request.session.cycle_key()` για να ανανεώσουμε το session ID
- Αυτό αποτρέπει επιθέσεις session fixation όπου ένας κακόβουλος χρήστης θα μπορούσε να ορίσει ένα γνωστό session ID

### Αποθήκευση δεδομένων συνόδου
- Τα δεδομένα συνόδου (όπως το ID της διεύθυνσης αποστολής στη διαδικασία πληρωμής) αποθηκεύονται με ασφάλεια στο session
- Χρησιμοποιούμε το `request.session['shipping_address_id'] = address.id` για την προσωρινή αποθήκευση της διεύθυνσης αποστολής
- Μετά την ολοκλήρωση της παραγγελίας, διαγράφουμε τα δεδομένα με `del request.session['shipping_address_id']`

## 3. Προστασία από επιθέσεις User Enumeration

Έχουμε υλοποιήσει πολλαπλά μέτρα προστασίας από επιθέσεις user enumeration στη σελίδα Login:

### Γενικά μηνύματα σφάλματος
- Χρησιμοποιούμε γενικό μήνυμα σφάλματος ("Τα στοιχεία σύνδεσης που εισάγατε δεν είναι έγκυρα") που δεν αποκαλύπτει αν το username υπάρχει ή το password είναι λάθος
- Το ίδιο μήνυμα εμφανίζεται τόσο για ανύπαρκτα usernames όσο και για λάθος passwords

### Προστασία από timing attacks
- Χρησιμοποιούμε τη constant-time συνάρτηση σύγκρισης hmac.compare_digest()
- Εφαρμόζουμε καθυστέρηση σταθερού χρόνου (300ms) με μικρή τυχαία παραλλαγή (0-100ms)
- Μετράμε το χρόνο εκτέλεσης για να διασφαλίσουμε ότι η συνολική διάρκεια είναι περίπου ίδια ανεξάρτητα από το αποτέλεσμα της αυθεντικοποίησης
- Αυτό αποτρέπει timing attacks που θα μπορούσαν να αποκαλύψουν αν ένα username υπάρχει

### Περιορισμός προσπαθειών σύνδεσης
- Χρησιμοποιούμε το django-axes για περιορισμό των προσπαθειών σύνδεσης
- Έχουμε ορίσει το AXES_FAILURE_LIMIT = 5 (κλείδωμα μετά από 5 αποτυχημένες προσπάθειες)
- Χρησιμοποιούμε το AXES_COOLOFF_TIME = 1 (διάρκεια κλειδώματος 1 ώρα)
- Παρακολουθούμε συνδυασμό username, IP address και user agent για τον εντοπισμό κακόβουλων χρηστών
- Αυτό αποτρέπει brute force επιθέσεις που θα μπορούσαν να χρησιμοποιηθούν για user enumeration

## 4. Προστασία κωδικών χρηστών στη βάση

Για την προστασία των κωδικών των χρηστών στη βάση δεδομένων, χρησιμοποιούμε:

### Χρήση ισχυρών αλγορίθμων hashing
- Χρησιμοποιούμε τον Argon2 password hasher (θεωρείται από τους πιο ασφαλείς)
- Έχουμε ρυθμίσει το PASSWORD_HASHERS στο settings.py:
  ```python
  PASSWORD_HASHERS = [
      'django.contrib.auth.hashers.Argon2PasswordHasher',
      'django.contrib.auth.hashers.PBKDF2PasswordHasher',
      'django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher',
  ]
  ```

### Αποθήκευση μόνο των hash των κωδικών
- Οι κωδικοί ποτέ δεν αποθηκεύονται σε plaintext στη βάση
- Χρησιμοποιείται το σύστημα hashing του Django που αποθηκεύει:
  - Τον αλγόριθμο που χρησιμοποιήθηκε
  - Ένα τυχαίο salt για κάθε κωδικό (προστασία από rainbow table attacks)
  - Τον αριθμό των επαναλήψεων (iterations)
  - Το hash του κωδικού

### Διαχείριση κωδικών
- Η διαχείριση των κωδικών γίνεται μέσω του Django Auth, που χειρίζεται με ασφάλεια τη δημιουργία, αποθήκευση και σύγκριση κωδικών
- Δεν εκτελούμε ποτέ άμεσες συγκρίσεις με κωδικούς, αλλά χρησιμοποιούμε την authenticate() του Django
- Οι κωδικοί δεν συμπεριλαμβάνονται ποτέ σε logs ή μηνύματα σφάλματος

## 5. Προστασία από SQL Injection

Η εφαρμογή μας προστατεύεται από επιθέσεις SQL Injection με τους ακόλουθους τρόπους:

### Χρήση του Django ORM
- Χρησιμοποιούμε αποκλειστικά το Django ORM για όλες τις αλληλεπιδράσεις με τη βάση δεδομένων
- Το Django ORM δημιουργεί αυτόματα παραμετροποιημένα ερωτήματα που προστατεύουν από SQL Injection
- Παράδειγμα ασφαλούς ερωτήματος στο catalog_view:
  ```python
  products = Product.objects.filter(
      Q(name__icontains=clean_query) | 
      Q(description__icontains=clean_query)
  )
  ```

### Sanitization εισόδων χρήστη
- Όλες οι είσοδοι χρήστη που χρησιμοποιούνται σε ερωτήματα καθαρίζονται πρώτα με το bleach
- Παράδειγμα από το catalog_view:
  ```python
  search_query = request.GET.get('q', '')
  clean_query = bleach.clean(search_query)
  ```

### Αποφυγή raw SQL ερωτημάτων
- Δεν χρησιμοποιούμε πουθενά raw SQL ερωτήματα που θα μπορούσαν να είναι ευάλωτα
- Όπου θα ήταν απαραίτητο να χρησιμοποιήσουμε raw SQL, θα χρησιμοποιούσαμε παραμετροποιημένα ερωτήματα:
  ```python
  # Ασφαλές παραμετροποιημένο ερώτημα
  Product.objects.raw("SELECT * FROM eshop_product WHERE name LIKE %s", [f'%{clean_query}%'])
  ```

### Περιορισμένα δικαιώματα στη βάση
- Στο περιβάλλον παραγωγής, ο χρήστης της βάσης δεδομένων θα έχει περιορισμένα δικαιώματα (μόνο SELECT, INSERT, UPDATE, DELETE)
- Ακόμα και αν κάποιος κατάφερνε να εκτελέσει SQL, δεν θα μπορούσε να αλλάξει το σχήμα της βάσης ή να εκτελέσει διαχειριστικές εντολές

## 6. Προστασία από CSRF

Έχουμε υλοποιήσει πολλαπλά μέτρα προστασίας από Cross-Site Request Forgery (CSRF):

### Χρήση CSRF tokens
- Χρησιμοποιούμε το Django's built-in CSRF protection middleware
- Όλες οι φόρμες POST περιλαμβάνουν το CSRF token με το template tag `{% csrf_token %}`
- Παράδειγμα στο login.html:
  ```html
  <form method="post" action="{% url 'login' %}">
      {% csrf_token %}
      <!-- form fields -->
  </form>
  ```

### CSRF protection σε AJAX requests
- Στις AJAX κλήσεις, συμπεριλαμβάνουμε το CSRF token στις HTTP κεφαλίδες
- Το CSRF token περνιέται μέσω data-attribute στα HTML elements
- Παράδειγμα στο cart.js:
  ```javascript
  const csrfToken = this.getAttribute('data-csrf-token');
  
  fetch('/add-to-cart/', {
      method: 'POST',
      headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': csrfToken
      },
      body: JSON.stringify({ product_id: productId })
  })
  ```

### Ασφαλείς ρυθμίσεις για CSRF cookies
- Έχουμε ενεργοποιήσει το CSRF_COOKIE_SECURE = True ώστε το CSRF cookie να αποστέλλεται μόνο μέσω HTTPS
- Έχουμε ορίσει το CSRF_COOKIE_SAMESITE = 'Lax' για πρόσθετη προστασία
- Έχουμε ορίσει το CSRF_TRUSTED_ORIGINS για να περιορίσουμε τα origins που μπορούν να κάνουν cross-site requests

### Καταγραφή CSRF errors
- Έχουμε ρυθμίσει logging για τα CSRF σφάλματα ώστε να μπορούμε να εντοπίζουμε πιθανές επιθέσεις

## 7. Προστασία από XSS

Έχουμε υλοποιήσει πολλαπλά μέτρα προστασίας από Cross-Site Scripting (XSS):

### Αυτόματο Escaping του Django
- Το Django παρέχει αυτόματο escaping των δεδομένων στα templates
- Όλες οι μεταβλητές που εμφανίζονται στα templates περνούν από HTML escaping
- Δεν χρησιμοποιούμε το filter `|safe` ή το tag `{% autoescape off %}` εκτός αν είναι απολύτως απαραίτητο

### Content Security Policy (CSP)
- Έχουμε εφαρμόσει ισχυρό Content Security Policy μέσω meta tag στο base.html:
  ```html
  <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; style-src 'self' https://cdn.jsdelivr.net; img-src 'self' data:; font-src 'self'; connect-src 'self'">
  ```
- Αυτό περιορίζει την εκτέλεση scripts και το φόρτωμα resources μόνο από αξιόπιστες πηγές
- Αποφεύγουμε τα inline styles και scripts, μεταφέροντάς τα σε εξωτερικά αρχεία

### Sanitization των εισόδων χρήστη
- Χρησιμοποιούμε το bleach για τον καθαρισμό όλων των εισόδων χρήστη
- Παράδειγμα στο catalog_view:
  ```python
  search_query = request.GET.get('q', '')
  clean_query = bleach.clean(search_query)
  ```
- Παράδειγμα στη φόρμα ShippingAddressForm:
  ```python
  def clean(self):
      cleaned_data = super().clean()
      for field in self.fields:
          if field in cleaned_data and isinstance(cleaned_data[field], str):
              cleaned_data[field] = bleach.clean(cleaned_data[field])
      return cleaned_data
  ```

### Προστασία από DOM-based XSS
- Όταν χειριζόμαστε δεδομένα μέσω JavaScript, χρησιμοποιούμε ασφαλείς μεθόδους για την εισαγωγή περιεχομένου
- Αντί για innerHTML, χρησιμοποιούμε textContent ή δημιουργούμε elements με το DOM API

## 8. Ασφαλής χρήση HTTPS

Έχουμε υλοποιήσει ασφαλή χρήση του HTTPS:

### Self-signed πιστοποιητικό
- Δημιουργήσαμε ένα self-signed πιστοποιητικό για τοπική ανάπτυξη
- Χρησιμοποιούμε το django-extensions και το runserver_plus για να τρέξουμε τον server με HTTPS

### HTTPS-only access
- Έχουμε ενεργοποιήσει το SECURE_SSL_REDIRECT για ανακατεύθυνση από HTTP σε HTTPS
- Όλα τα cookies έχουν το Secure flag ενεργοποιημένο
- Έχουμε ενεργοποιήσει το HTTP Strict Transport Security (HSTS)

### Ρυθμίσεις ασφαλείας HTTPS
- Έχουμε προσθέσει τις ακόλουθες ρυθμίσεις στο settings.py:
  ```python
  SECURE_SSL_REDIRECT = True
  SESSION_COOKIE_SECURE = True
  CSRF_COOKIE_SECURE = True
  SECURE_BROWSER_XSS_FILTER = True
  SECURE_CONTENT_TYPE_NOSNIFF = True
  SECURE_HSTS_SECONDS = 31536000
  SECURE_HSTS_INCLUDE_SUBDOMAINS = True
  SECURE_HSTS_PRELOAD = True
  ```

## 9. Ρίσκα που δεν έχουν αντιμετωπιστεί

Παρά τις προσπάθειές μας για μια ασφαλή εφαρμογή, αναγνωρίζουμε ότι υπάρχουν ορισμένα ρίσκα που δεν έχουμε αντιμετωπίσει πλήρως:

### Περιορισμοί του development environment
- Σε περιβάλλον ανάπτυξης χρησιμοποιούμε self-signed πιστοποιητικό, ενώ σε περιβάλλον παραγωγής θα πρέπει να χρησιμοποιηθεί ένα πιστοποιητικό από αναγνωρισμένη Αρχή Πιστοποίησης
- Η SQLite που χρησιμοποιούμε για ανάπτυξη δεν είναι κατάλληλη για περιβάλλον παραγωγής

### Έλλειψη rate limiting για API endpoints
- Δεν έχουμε υλοποιήσει rate limiting για API endpoints (π.χ. add-to-cart)
- Αυτό θα μπορούσε να επιτρέψει DoS επιθέσεις στην εφαρμογή

### Ανάγκη για περισσότερους ελέγχους στην είσοδο διεύθυνσης
- Δεν έχουμε εφαρμόσει πλήρεις ελέγχους εγκυρότητας για τη διεύθυνση αποστολής
- Οι κακόβουλοι χρήστες θα μπορούσαν να εισάγουν μη έγκυρες διευθύνσεις

### Προσομοίωση συστήματος πληρωμών
- Δεν έχουμε υλοποιήσει ένα πραγματικό σύστημα πληρωμών με όλες τις απαραίτητες ασφαλείς πρακτικές
- Σε ένα πραγματικό e-shop, θα ήταν απαραίτητη η ενσωμάτωση ενός ασφαλούς payment gateway

### Έλλειψη πλήρους logging και monitoring
- Δεν έχουμε εφαρμόσει ολοκληρωμένο σύστημα καταγραφής συμβάντων και παρακολούθησης
- Αυτό θα καθιστούσε πιο δύσκολο τον εντοπισμό και την αντιμετώπιση περιστατικών ασφαλείας

### Περιορισμένη υλοποίηση του CAPTCHA
- Δεν έχουμε υλοποιήσει CAPTCHA στη φόρμα σύνδεσης
- Αυτό θα παρείχε πρόσθετη προστασία από αυτοματοποιημένες επιθέσεις brute force
