# Secure E-Shop

Μια ασφαλής εφαρμογή ηλεκτρονικού καταστήματος που αναπτύχθηκε με Django 5.2 LTS.

## Detailed Development Setup Guide

### Prerequisites
- Python 3.8 or higher
- Git
- OpenSSL for certificate generation
- (Optional) A Gmail account for email functionality

### Step 1: Clone the Repository
```bash
git clone <repository-url>
cd secure-eshop
```

### Step 2: Set Up Python Environment
Create and activate a virtual environment:
```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate
```

### Step 3: Install Dependencies
Install all required packages:
```bash
pip install -r requirements.txt
```

### Step 4: Create Log Directory
Ensure the logs directory exists:
```bash
mkdir -p logs
touch logs/app.log
```

### Step 5: Configure Environment Variables (Optional)
Create a `.env` file in the project root for email functionality:
```bash
# Create .env file
touch .env

# Add email configuration (edit with your details)
echo "EMAIL_HOST_USER=youremail@gmail.com" >> .env
echo "EMAIL_HOST_PASSWORD=your-app-password" >> .env
```
Note: For Gmail, you'll need to use an "App Password" rather than your account password. You can generate one in your Google Account security settings.

### Step 6: Set Up the Database
Run database migrations:
```bash
python manage.py migrate
```

### Step 7: Create Admin User
Create a superuser for admin access:
```bash
python manage.py createsuperuser
```
Follow the prompts to create your admin username, email, and password.

### Step 8: Set Up Two-Factor Authentication for Admin (Added May 14, 2025)
Set up OTP for the admin user:
```bash
python manage.py add_otp_device admin
```
This will generate a QR code at admin_qrcode.png that you can scan with an authenticator app like Google Authenticator, Microsoft Authenticator, or Authy.

For more details, see the [OTP Guide](ADMIN_OTP_SETUP.md).

### Step 9: Generate SSL Certificate
Generate a self-signed SSL certificate for HTTPS:
```bash
mkdir -p certificates
openssl req -x509 -newkey rsa:4096 -keyout config/certificates/key.pem -out config/certificates/cert.pem -days 365 -nodes
```
When prompted, provide the required information or press Enter to use defaults.

### Step 10: Start the Development Server
Start the development server with SSL:
```bash
python manage.py runserver_plus --cert-file=config/certificates/cert.pem --key-file=config/certificates/key.pem
```

### Step 11: Access the Application
Open your browser and navigate to:
- **Website**: https://localhost:8000/
- **Admin Interface**: https://localhost:8000/admin/ (now protected with two-factor authentication)

### Common Development Tasks

#### Running Tests
To run all tests:
```bash
python manage.py test
```

To run a specific test:
```bash
python manage.py test eshop.tests.TestClassName.test_method_name
```

#### Creating New Migrations
After modifying models:
```bash
python manage.py makemigrations eshop
python manage.py migrate
```

#### Collecting Static Files
```bash
python manage.py collectstatic
```

### Browser Security Warning
When you first access the site, your browser will warn about the self-signed certificate. This is expected in development. You can proceed by:
- In Chrome: Click "Advanced" and then "Proceed to localhost (unsafe)"
- In Firefox: Click "Advanced" > "Accept the Risk and Continue"
- In Safari: Click "Show Details" > "visit this website"

### Troubleshooting
- **Certificate Issues**: Ensure certificates are correctly generated and the paths match in the runserver command
- **Database Errors**: Try deleting `db.sqlite3` and running migrations again
- **Static Files Not Loading**: Run `python manage.py collectstatic`
- **Email Errors**: Check your `.env` configuration and Gmail security settings
- **OTP Issues**: If you're having issues with OTP authentication, you can regenerate the OTP device using the management command

## Λειτουργικότητα

- Σελίδα Login: Ασφαλής αυθεντικοποίηση χρηστών
- Σελίδα Καταλόγου Προϊόντων: Προβολή και αναζήτηση προϊόντων, προσθήκη στο καλάθι
- Σελίδα Πληρωμών: Προβολή καλαθιού, συμπλήρωση διεύθυνσης αποστολής, ολοκλήρωση παραγγελίας
- Admin Panel: Διαχείριση προϊόντων, παραγγελιών και χρηστών με two-factor authentication (προστέθηκε στις 14/5/2025)

## Μέτρα Ασφαλείας

Περισσότερες λεπτομέρειες διαθέσιμες στα αρχεία:
- [Security Documentation](Documentation/security_documentation.md) (5 Μαΐου 2025)
- [Security Analysis](Documentation/security_analysis.md) (14 Μαΐου 2025)
- [Code Explanation](Documentation/code_explanation.md) (11 Μαΐου 2025)
- [PythonAnywhere Setup Guide](Documentation/python_anywhere_setup.md) (11 Μαΐου 2025)
- [OTP Implementation Guide](Documentation/otp_guide.md) (14 Μαΐου 2025)

## Πρόσφατες Ενημερώσεις

- **14 Μαΐου 2025**: Προσθήκη Two-Factor Authentication (2FA) στο διαχειριστικό panel
- **11 Μαΐου 2025**: Ενημέρωση της τεκμηρίωσης και οδηγιών για το PythonAnywhere deployment
- **5 Μαΐου 2025**: Ολοκλήρωση της ασφαλούς ανάλυσης της εφαρμογής


---



# Εργασία 3η: Ανάπτυξη Ηλεκτρονικού Καταστήματος

**Περιγραφή:**
Ημερομηνία Παράδοσης Τεκμηρίωσης: Δευτέρα 2 Ιουνίου 2025

Στο πλαίσιο της παρούσας εργασίας καλείστε να αναπτύξετε ένα μικρό e-shop (με περιορισμένες λειτουργίες) σε γλώσσα προγραμματισμού της επιλογής σας. Στόχος της εργασίας είναι η εφαρμογή καλών πρακτικών κατά την ανάπτυξη οι οποίες θα μειώσουν σημαντικά την ευπαθή επιφάνεια του e-shop.
 
## Λειτουργικές απαιτήσεις

Η εφαρμογή θα πρέπει να καλύπτει (μόνο) τις παρακάτω λειτουργικές απαιτήσεις:
 
* Όλο το περιεχόμενο της εφαρμογής θα πρέπει να είναι διαθέσιμο μόνο μέσω HTTPS. Το πιστοποιητικό που θα χρησιμοποιηθεί στο web server θα παραχθεί από εσάς.
 
* Η εφαρμογή θα αποτελείται από τρεις δυναμικές σελίδες:
   * Σελίδα Login
   * Σελίδα καταλόγου προϊόντων
   * Σελίδα πληρωμών
 
### Σελίδα Login
* Επιτρέπει την αυθεντικοποίηση των χρηστών.
 
### Σελίδα καταλόγου προϊόντων
* Διαθέσιμη μόνο σε αυθεντικοποιημένους χρήστες.
* Κάθε προϊόν που παρουσιάζεται θα πρέπει να ακολουθείται από σύνδεσμο που το προσθέτει στο καλάθι αγορών [1].
* Θα επιτρέπεται στο χρήστη αναζήτηση στον κατάλογο και τα αποτελέσματα της αναζήτησης θα εμφανίζονται στη σελίδα του καταλόγου [1].
* Η σελίδα θα αναφέρει αν παρουσιάζονται όλα τα προϊόντα ή μόνο τα προϊόντα που αφορούν μια συγκεκριμένη αναζήτηση.
* Η σελίδα θα πρέπει να φέρει υποσημείωση (footer) που θα περιγράφει τον αριθμό των αντικειμένων που έχουν προστεθεί στο καλάθι ή συνοπτική παρουσίαση των αντικειμένων που έχουν προστεθεί στο καλάθι.
 
### Σελίδα πληρωμών
* Διαθέσιμη μόνο σε αυθεντικοποιημένους χρήστες.
* Παρουσιάζει τα προϊόντα που έχουν προστεθεί στο καλάθι.
* Ο χρήστης θα μπορεί να συμπληρώσει τη διεύθυνση αποστολής σε φόρμα της σελίδας.
* Με την αποστολή των στοιχείων της φόρμας, θα παρουσιάζονται για τελική έγκριση όλα τα στοιχεία της παραγγελίας στο χρήστη (διεύθυνση, προϊόντα στο καλάθι) [1].
* Αν ο χρήστης εγκρίνει την παραγγελία τότε αυτή αποστέλλεται με email προς το διαχειριστή του καταστήματος.
 
[1] Ο χρήστης θα πρέπει να έχει πρόσβαση σε αυτή τη λειτουργία δίχως να αλλάξει σελίδα.
 
**Σημείωση:** Θα εξεταστείτε μόνον ως προς την υλοποίηση των παραπάνω λειτουργιών. Δεν απαιτείται ανάπτυξη άλλων λειτουργιών (π.χ. προσθαφαίρεση χρηστών κλπ.)
 
## Παραδοτέα

Παραδοτέα της εργασίας θα είναι:
 
1. Μια συνοπτική επίδειξη (15') της εφαρμογής που θα λάβει χώρα τις εβδομάδες 16-28/6/2025. Θα ακολουθήσουν ερωτήσεις προς τα μέλη της ομάδας σχετικές με την υλοποίηση της εφαρμογής.
 
2. Ένα αρχείο ZIP με τον πηγαίο κώδικα και την τεκμηρίωση της εφαρμογής. Το αρχείο θα πρέπει να αναρτηθεί στο e-class εντός της προθεσμίας υποβολής.
 
## Απαιτήσεις τεκμηρίωσης

H τεκμηρίωση θα πρέπει να περιγράφει:
 
* Ποια λειτουργικότητα υλοποιεί κάθε αρχείο του πηγαίου κώδικά σας.
* Τους τρόπους με τους οποίους γίνεται η διαχείριση των δεδομένων συνόδου (session data) στην εφαρμογή (παραγωγή session ID, έλεγχοι, αλλαγές στα δεδομένα συνόδου ή αντίστοιχες διαδικασίες με authentication token).
* Το μηχανισμό με τον οποίο αποτρέπονται οι επιθέσεις τύπου 'user enumeration' στη σελίδα Login.
* Τον τρόπο με τον οποίο προστατεύονται οι κωδικοί των χρηστών στη βάση.
* Τις παραμέτρους που γίνονται μέρος ερωτημάτων SQL και τον τρόπο με τον οποίο προστατεύεται η εφαρμογή από SQL injection επιθέσεις όταν επεξεργάζεται κάθε μία από αυτές.
* Τους μηχανισμούς ασφάλειας που υλοποιήσατε για να αντικρούσετε επιθέσεις τύπου Cross Site Request Forgery (CSRF).
* Για ποια λειτουργικότητα του e-shop υλοποιήσατε μέτρα προστασίας από επιθέσεις Cross Site Scripting (XSS) και ποια ήταν τα μέτρα αυτά.
* Ρίσκα τα οποία θεωρείτε ότι είναι σημαντικά και για τα οποία δεν έχετε υλοποιήσει κάποιο μέτρο προστασίας.
 
 
## Πληροφορίες υποβολής

Η εργασία είναι ομαδική και θα μετρήσει για το 50% του βαθμού του μαθήματος. Κάθε ομάδα μπορεί να αποτελείται από τέσσερα το πολύ άτομα. Τέλος, κάθε ομάδα θα ετοιμάσει ένα σετ παραδοτέων.