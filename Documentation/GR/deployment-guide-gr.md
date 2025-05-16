# Οδηγός Ανάπτυξης

Αυτός ο οδηγός παρέχει λεπτομερείς οδηγίες για την ανάπτυξη της εφαρμογής Secure E-Shop στο PythonAnywhere.

## Προαπαιτούμενα

- Ένα υπάρχον έργο Secure E-Shop έτοιμο για ανάπτυξη
- Ένας λογαριασμός PythonAnywhere (δωρεάν ή επί πληρωμή)
- Το έργο σας να φιλοξενείται στο GitHub, GitLab ή Bitbucket (συνιστάται)

## Βήμα 1: Μεταφόρτωση του Κώδικά σας στο PythonAnywhere

### Χρήση Git (Συνιστάται)

Εάν ο κώδικάς σας βρίσκεται στο GitHub, GitLab ή Bitbucket, κλωνοποιήστε τον από μια κονσόλα Bash:

```bash
# Ρυθμίστε το κλειδί SSH εάν δεν το έχετε κάνει ήδη
# Δείτε: https://help.pythonanywhere.com/pages/ExternalVCS

# Κλωνοποίηση του αποθετηρίου σας
git clone git@github.com:yourusername/secure-eshop.git
```

### Σημαντική Σημείωση για τα Ονόματα Καταλόγων

Τα ονόματα των Python modules δεν μπορούν να περιέχουν παύλες. Εάν ο κατάλογος του έργου σας έχει παύλα (π.χ., `secure-eshop`), πρέπει είτε:
- Να τον μετονομάσετε χρησιμοποιώντας κάτω παύλες (`secure_eshop`)
- Να δημιουργήσετε ένα συμβολικό σύνδεσμο: `ln -s secure-eshop secure_eshop`

## Βήμα 2: Δημιουργία Εικονικού Περιβάλλοντος

Στην κονσόλα Bash, δημιουργήστε ένα virtualenv χρησιμοποιώντας την ενσωματωμένη εντολή `mkvirtualenv`:

```bash
# Δημιουργία virtualenv (χρησιμοποιώντας mkvirtualenv για ευκολότερη διαχείριση)
mkvirtualenv --python=/usr/bin/python3.10 secure-eshop-virtualenv

# Ή εάν προτιμάτε μια συγκεκριμένη έκδοση Python:
mkvirtualenv --python=/usr/bin/python3.13 secure-eshop-virtualenv

# Η προτροπή σας θα αλλάξει για να δείξει ότι το virtualenv είναι ενεργό:
(secure-eshop-virtualenv)$ pip install django

# Εγκατάσταση όλων των εξαρτήσεων από το requirements.txt:
(secure-eshop-virtualenv)$ pip install -r requirements.txt
```

**Σημείωση**: Εάν δείτε `mkvirtualenv: command not found`, ελέγξτε [Εγκατάσταση Virtualenv Wrapper](https://help.pythonanywhere.com/pages/InstallingVirtualenvWrapper).

## Βήμα 3: Ρύθμιση της Εφαρμογής Web

### Δημιουργία Εφαρμογής Web με Χειροκίνητη Ρύθμιση

1. Μεταβείτε στην καρτέλα **Web** στο PythonAnywhere
2. Κάντε κλικ στο **Add a new web app**
3. Επιλέξτε **Manual configuration** (όχι Django)
   - **Σημαντικό**: Επιλέξτε Manual Configuration, όχι "Django" - αυτό είναι μόνο για νέα έργα
4. Επιλέξτε την έκδοση Python (ίδια με το virtualenv σας)
5. Κάντε κλικ για να δημιουργήσετε την εφαρμογή web

### Ρύθμιση Virtualenv

1. Στην καρτέλα Web, μεταβείτε στην ενότητα "Virtualenv"
2. Εισάγετε το όνομα του virtualenv σας: `secure-eshop-virtualenv`
3. Κάντε κλικ στο OK (θα συμπληρωθεί αυτόματα με την πλήρη διαδρομή)

### Ορισμός Καταλόγου Εργασίας

1. Στην ενότητα "Code", ορίστε και τα δύο:
   - Source code: `/home/username/secure-eshop`
   - Working directory: `/home/username/secure-eshop`

## Βήμα 4: Ρύθμιση του Αρχείου WSGI

### Επεξεργασία του Αρχείου WSGI

1. Στην καρτέλα Web, κάντε κλικ στον σύνδεσμο του αρχείου ρύθμισης WSGI
   - Θα ονομάζεται κάτι σαν `/var/www/username_pythonanywhere_com_wsgi.py`
2. Διαγράψτε τα πάντα στο αρχείο
3. Αντικαταστήστε με τη ρύθμιση Django:

```python
# +++++++++++ DJANGO +++++++++++
# Για να χρησιμοποιήσετε τη δική σας εφαρμογή Django, χρησιμοποιήστε κώδικα όπως αυτός:
import os
import sys

# υποθέτοντας ότι το αρχείο ρυθμίσεων Django βρίσκεται στο '/home/username/secure-eshop/eshop_project/settings.py'
path = '/home/username/secure-eshop'
if path not in sys.path:
    sys.path.insert(0, path)

os.environ['DJANGO_SETTINGS_MODULE'] = 'eshop_project.settings'

# στη συνέχεια:
from django.core.wsgi import get_wsgi_application
application = get_wsgi_application()
```

Αντικαταστήστε:
- `username` με το όνομα χρήστη σας στο PythonAnywhere
- `/home/username/secure-eshop` με την πραγματική διαδρομή προς το έργο σας (περιέχει το `manage.py`)
- `eshop_project.settings` με την πραγματική διαδρομή της μονάδας ρυθμίσεων

## Βήμα 5: Ρύθμιση Βάσης Δεδομένων MySQL

### Δημιουργία Βάσης Δεδομένων MySQL

1. Μεταβείτε στην καρτέλα **Databases**
2. Δημιουργήστε μια βάση δεδομένων (π.χ., `username$secure_eshop`)
3. Σημειώστε τα διαπιστευτήρια της βάσης δεδομένων σας:
   - Host: `username.mysql.pythonanywhere-services.com`
   - Username: `username`
   - Database name: `username$secure_eshop`
   - Password: (ορίζεται από εσάς)

### Ρύθμιση Ρυθμίσεων Βάσης Δεδομένων Django

Εγκαταστήστε τον πελάτη MySQL:
```bash
pip install mysqlclient
```

Ενημερώστε το αρχείο `.env` με τις ρυθμίσεις της βάσης δεδομένων (δείτε την ενότητα Μεταβλητές Περιβάλλοντος παρακάτω).

## Βήμα 6: Ρύθμιση Στατικών Αρχείων

### Ενημέρωση του settings.py

Βεβαιωθείτε ότι το `settings.py` σας έχει την ακόλουθη ρύθμιση:

```python
STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')

# Για ανάπτυξη, εάν έχετε στατικά αρχεία συγκεκριμένα για την εφαρμογή
STATICFILES_DIRS = [
    os.path.join(BASE_DIR, 'eshop/static'),
]
```

### Συλλογή Στατικών Αρχείων

```bash
cd /home/username/secure-eshop
workon secure-eshop-virtualenv
python manage.py collectstatic --noinput
```

### Ρύθμιση Στατικών Αρχείων στο PythonAnywhere

1. Μεταβείτε στην καρτέλα **Web**
2. Μεταβείτε στο **Static files**
3. Προσθέστε αντιστοιχίσεις:
   - URL: `/static/`
   - Directory: `/home/username/secure-eshop/staticfiles`
   - URL: `/media/` (εάν έχετε αρχεία πολυμέσων)
   - Directory: `/home/username/secure-eshop/media`

## Βήμα 7: Μεταβλητές Περιβάλλοντος (Ασφάλεια)

### Εγκατάσταση python-dotenv

```bash
pip install python-dotenv
```

### Δημιουργία Αρχείου .env

Δημιουργήστε το αρχείο `/home/username/secure-eshop/.env`:

```ini
# Ρυθμίσεις Django
SECRET_KEY=your-secret-key-here
DEBUG=False
ALLOWED_HOSTS=username.pythonanywhere.com

# Ρυθμίσεις βάσης δεδομένων
DB_NAME=username$secure_eshop
DB_USER=username
DB_PASSWORD=your-mysql-password
DB_HOST=username.mysql.pythonanywhere-services.com
DB_PORT=3306

# Ρυθμίσεις email
EMAIL_HOST_USER=your-email@example.com
EMAIL_HOST_PASSWORD=your-email-password
```

**Σημαντικό Βήμα Ασφαλείας**: Ορίστε σωστά δικαιώματα αρχείου: `chmod 600 .env`

### Βεβαιωθείτε ότι το settings.py Χρησιμοποιεί Μεταβλητές Περιβάλλοντος

Βεβαιωθείτε ότι το `settings.py` σας φορτώνει και χρησιμοποιεί μεταβλητές περιβάλλοντος:

```python
import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent

# Φόρτωση μεταβλητών περιβάλλοντος
load_dotenv(os.path.join(BASE_DIR, '.env'))

SECRET_KEY = os.getenv('SECRET_KEY')
DEBUG = os.getenv('DEBUG', 'False').lower() == 'true'
ALLOWED_HOSTS = os.getenv('ALLOWED_HOSTS', '').split(',')

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': os.getenv('DB_NAME'),
        'USER': os.getenv('DB_USER'),
        'PASSWORD': os.getenv('DB_PASSWORD'),
        'HOST': os.getenv('DB_HOST'),
        'PORT': os.getenv('DB_PORT', '3306'),
        'OPTIONS': {
            'init_command': "SET sql_mode='STRICT_TRANS_TABLES'",
            'charset': 'utf8mb4',
        }
    }
}
```

## Βήμα 8: Ρύθμιση HTTPS

Ενεργοποιήστε το **Force HTTPS** στις ρυθμίσεις ασφαλείας της καρτέλας Web.

## Βήμα 9: Εκτέλεση Migrations και Δημιουργία Υπερχρήστη

```bash
cd /home/username/secure-eshop
workon secure-eshop-virtualenv
python manage.py migrate
python manage.py createsuperuser
```

## Βήμα 10: Ρύθμιση OTP για Διαχειριστή

Εάν χρησιμοποιείτε OTP για αυθεντικοποίηση διαχειριστή, ρυθμίστε το:

```bash
python manage.py add_otp_device admin
```

Ο κωδικός QR θα δημιουργηθεί στον ριζικό κατάλογο του έργου. Θα πρέπει να τον κατεβάσετε για να τον σαρώσετε με την εφαρμογή αυθεντικοποίησης.

## Βήμα 11: Επανεκκίνηση της Εφαρμογής Web

Κάντε κλικ στο πράσινο κουμπί **Reload** στην καρτέλα Web.

## Εργασίες Συντήρησης

### Ενημέρωση της Εφαρμογής σας

1. Τραβήξτε τις τελευταίες αλλαγές
2. Ενεργοποιήστε το εικονικό περιβάλλον
3. Εγκαταστήστε νέες εξαρτήσεις: `pip install -r requirements.txt`
4. Εκτελέστε migrations: `python manage.py migrate`
5. Συλλέξτε στατικά αρχεία: `python manage.py collectstatic`
6. Επανεκκινήστε την εφαρμογή web

### Προβολή Αρχείων Καταγραφής

- **Αρχείο καταγραφής σφαλμάτων**: Web tab → Log files → Error log
- **Αρχείο καταγραφής διακομιστή**: Web tab → Log files → Server log
- **Αρχείο καταγραφής πρόσβασης**: Web tab → Log files → Access log

### Αντίγραφα Ασφαλείας Βάσης Δεδομένων

Χρησιμοποιήστε τις προγραμματισμένες εργασίες του PythonAnywhere για να δημιουργήσετε τακτικά αντίγραφα ασφαλείας:
```bash
mysqldump -u username -h username.mysql.pythonanywhere-services.com 'username$secure_eshop' > backup.sql
```

## Λίστα Ελέγχου για Παραγωγή

- [ ] `DEBUG = False` στην παραγωγή
- [ ] Το μυστικό κλειδί είναι μοναδικό και ασφαλές
- [ ] Οι κωδικοί πρόσβασης της βάσης δεδομένων είναι ισχυροί
- [ ] Τα στατικά αρχεία έχουν ρυθμιστεί σωστά
- [ ] Το HTTPS είναι ενεργοποιημένο
- [ ] Η καταγραφή σφαλμάτων έχει ρυθμιστεί
- [ ] Έχουν προγραμματιστεί αντίγραφα ασφαλείας
- [ ] Οι μεταβλητές περιβάλλοντος χρησιμοποιούνται για ευαίσθητα δεδομένα
- [ ] Το αρχείο `.env` δεν βρίσκεται στο σύστημα ελέγχου εκδόσεων
- [ ] Τα δικαιώματα αρχείων έχουν ρυθμιστεί σωστά

## Κοινά Προβλήματα και Λύσεις

### Πρόβλημα: ModuleNotFoundError
**Σφάλμα**: `ModuleNotFoundError: No module named 'your-app'`
**Λύση**: Τα modules της Python δεν μπορούν να έχουν παύλες. Μετονομάστε τον κατάλογό σας ή δημιουργήστε έναν συμβολικό σύνδεσμο.

### Πρόβλημα: Τα Στατικά Αρχεία Δεν Φορτώνονται
**Σφάλμα**: `The resource was blocked due to MIME type mismatch`
**Λύση**: 
- Ελέγξτε αν τα στατικά αρχεία έχουν συλλεχθεί στο σωστό κατάλογο
- Επαληθεύστε ότι η αντιστοίχιση στατικών αρχείων στην καρτέλα Web δείχνει στη σωστή τοποθεσία
- Βεβαιωθείτε ότι έχετε εκτελέσει `collectstatic`

### Πρόβλημα: Σφάλματα Σύνδεσης Βάσης Δεδομένων
**Λύση**: 
- Επαληθεύστε τα διαπιστευτήρια της βάσης δεδομένων
- Βεβαιωθείτε ότι το όνομα της βάσης δεδομένων ακολουθεί τη μορφή `username$dbname`
- Ελέγξτε ότι έχετε δημιουργήσει τη βάση δεδομένων στην καρτέλα Databases

### Πρόβλημα: Σφάλμα 500 Internal Server Error
**Λύση**: 
1. Ελέγξτε το αρχείο καταγραφής σφαλμάτων (σύνδεσμος στην καρτέλα Web)
2. Βεβαιωθείτε ότι `DEBUG=False` για την παραγωγή
3. Επαληθεύστε ότι έχουν εγκατασταθεί όλες οι εξαρτήσεις στο virtualenv
4. Ελέγξτε για συντακτικά σφάλματα στο settings.py

## Πρόσθετοι Πόροι

- [Επίσημος οδηγός ανάπτυξης PythonAnywhere](https://help.pythonanywhere.com/pages/DeployExistingDjangoProject/)
- [Λίστα Ελέγχου Ανάπτυξης Django](https://docs.djangoproject.com/en/stable/howto/deployment/checklist/)
