/**
 * Address validation script για φόρμες αποστολής
 * 
 * Αυτό το script παρέχει real-time client-side validation
 * για φόρμες διευθύνσεων αποστολής με άμεση ανατροφοδότηση.
 * 
 * Χαρακτηριστικά:
 * - Επικύρωση σε πραγματικό χρόνο (real-time validation)
 * - Οπτική ανατροφοδότηση με χρώματα και μηνύματα
 * - Ειδικοί κανόνες για ελληνικές διευθύνσεις
 * - Επικύρωση μορφής email και domain
 */

document.addEventListener('DOMContentLoaded', function() {
    // Αναζήτηση της φόρμας διεύθυνσης αποστολής
    // Τεχνική: Χρήση CSS selector για εύρεση της φόρμας
    const shippingForm = document.querySelector('form.shipping-address-form');
    if (!shippingForm) return; // Early exit αν δεν βρεθεί η φόρμα
    
    // Καθορισμός προτύπων επικύρωσης (validation patterns)
    // Χρήση Regular Expressions για έλεγχο μορφής δεδομένων
    const validationPatterns = {
        zip_code: {
            // RegExp για ελληνικό ΤΚ: ακριβώς 5 ψηφία
            pattern: /^\d{5}$/,
            message: 'Ο ταχυδρομικός κώδικας πρέπει να αποτελείται από 5 ψηφία'
        },
        phone: {
            // RegExp για ελληνικά τηλέφωνα:
            // - Προαιρετικό πρόθεμα +30/0030 
            // - Κινητά: 69ΧΧΧΧΧΧΧX (10 ψηφία)
            // - Σταθερά: 2ΧΧΧΧΧΧΧΧX (10 ψηφία)
            pattern: /^(?:\+30|0030)?(?:\s*)(?:(?:69\d{8})|(?:2\d{9}))$/,
            message: 'Παρακαλώ εισάγετε έγκυρο ελληνικό αριθμό τηλεφώνου (σταθερό ή κινητό)'
        },
        email: {
            // RegExp για email που ακολουθεί τα standards:
            // - Επιτρέπει γράμματα, αριθμούς και ειδικούς χαρακτήρες πριν το @
            // - Απαιτεί έγκυρο domain με τουλάχιστον ένα dot
            // - Περιορίζει μέγεθος TLD σε 2-63 χαρακτήρες
            pattern: /^[a-zA-Z0-9](?:[a-zA-Z0-9._%+-]{0,63}[a-zA-Z0-9])?@(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$/,
            message: 'Παρακαλώ εισάγετε έγκυρη διεύθυνση email'
        }
    };
    
    // Προσθήκη event listeners για input events σε όλα τα σχετικά πεδία
    // Event delegation pattern: Εφαρμογή ίδιας λογικής σε πολλαπλά elements
    shippingForm.querySelectorAll('input').forEach(input => {
        const fieldName = input.name;
        
        // Παράλειψη πεδίων που δεν έχουν πρότυπα επικύρωσης
        if (!validationPatterns[fieldName]) return;
        
        // Επικύρωση κατά την πληκτρολόγηση (real-time feedback)
        input.addEventListener('input', function() {
            validateField(input, validationPatterns[fieldName]);
        });
        
        // Επικύρωση κατά την απώλεια εστίασης για καλύτερο UX
        // Τεχνική: Διαφορετική συμπεριφορά σε blur vs. input για βέλτιστο UX
        input.addEventListener('blur', function() {
            validateField(input, validationPatterns[fieldName], true);
        });
    });
    
    // Χειριστής υποβολής φόρμας (form submission handler)
    shippingForm.addEventListener('submit', function(e) {
        // Αποτροπή υποβολής αν αποτύχει η επικύρωση
        if (!validateForm(shippingForm)) {
            e.preventDefault(); // Διακοπή του default submit behavior
            Notifications.error('Παρακαλώ διορθώστε τα σφάλματα στη φόρμα πριν συνεχίσετε');
        }
    });
    
    /**
     * Επικύρωση μεμονωμένου πεδίου φόρμας
     * 
     * Λειτουργία:
     * 1. Ελέγχει την τιμή έναντι του προτύπου RegExp
     * 2. Προσθέτει/αφαιρεί classes για οπτική ανατροφοδότηση
     * 3. Εμφανίζει μηνύματα σφάλματος όπου χρειάζεται
     * 
     * @param {HTMLElement} input - Το element input προς επικύρωση
     * @param {Object} validationRule - Ο κανόνας επικύρωσης προς εφαρμογή
     * @param {boolean} showMessage - Αν θα εμφανιστεί notification μήνυμα
     * @returns {boolean} Αν το πεδίο είναι έγκυρο
     */
    function validateField(input, validationRule, showMessage = false) {
        const value = input.value.trim(); // Αφαίρεση whitespace
        // Επιτρέπει κενές τιμές (θα ελεγχθούν από το required αν χρειάζεται)
        const isValid = value === '' || validationRule.pattern.test(value);
        
        // Προσθήκη οπτικής ανατροφοδότησης
        // Τεχνική: Χρήση Bootstrap classes για styling
        if (isValid) {
            input.classList.remove('is-invalid');
            input.classList.add('is-valid');
        } else {
            input.classList.remove('is-valid');
            input.classList.add('is-invalid');
            
            // Εμφάνιση notification αν ζητήθηκε
            if (showMessage && window.Notifications) {
                Notifications.warning(validationRule.message);
            }
            
            // Προσθήκη/ενημέρωση μηνύματος επικύρωσης
            // Τεχνική: DOM manipulation για εμφάνιση μηνυμάτων σφάλματος
            let feedbackElement = input.nextElementSibling;
            if (!feedbackElement || !feedbackElement.classList.contains('invalid-feedback')) {
                feedbackElement = document.createElement('div');
                feedbackElement.className = 'invalid-feedback';
                input.parentNode.insertBefore(feedbackElement, input.nextSibling);
            }
            feedbackElement.textContent = validationRule.message;
        }
        
        return isValid;
    }
    
    /**
     * Επικύρωση ολόκληρης της φόρμας
     * 
     * Λειτουργία:
     * 1. Επικυρώνει κάθε πεδίο που έχει πρότυπο επικύρωσης
     * 2. Επιστρέφει false αν οποιοδήποτε πεδίο είναι μη έγκυρο
     * 
     * @param {HTMLElement} form - Η φόρμα προς επικύρωση
     * @returns {boolean} Αν η φόρμα είναι έγκυρη
     */
    function validateForm(form) {
        let isValid = true;
        
        // Επικύρωση κάθε πεδίου με πρότυπο επικύρωσης
        form.querySelectorAll('input').forEach(input => {
            const fieldName = input.name;
            if (validationPatterns[fieldName]) {
                // Αν οποιοδήποτε πεδίο είναι μη έγκυρο, η φόρμα είναι μη έγκυρη
                // Τεχνική: Short-circuit evaluation - συνεχίζει να ελέγχει όλα τα πεδία
                if (!validateField(input, validationPatterns[fieldName], true)) {
                    isValid = false;
                }
            }
        });
        
        return isValid;
    }
    
    // Ειδική επικύρωση για ελληνικό context διευθύνσεων
    // Αλλάζει απαιτήσεις με βάση την επιλεγμένη χώρα
    const countryField = shippingForm.querySelector('[name="country"]');
    if (countryField) {
        countryField.addEventListener('change', function() {
            const countryValue = this.value.toLowerCase();
            // Έλεγχος αν η χώρα είναι Ελλάδα (διάφορες πιθανές εισαγωγές)
            const isGreece = ['ελλάδα', 'ελλαδα', 'greece', 'hellas'].includes(countryValue);
            
            // Εφαρμογή αυστηρότερης επικύρωσης για ελληνικές διευθύνσεις
            if (isGreece) {
                const zipField = shippingForm.querySelector('[name="zip_code"]');
                const phoneField = shippingForm.querySelector('[name="phone"]');
                
                if (zipField) {
                    // Ορισμός ΤΚ ως υποχρεωτικό για ελληνικές διευθύνσεις
                    zipField.setAttribute('required', 'required');
                    zipField.placeholder = 'ΤΚ (5 ψηφία)';
                }
                
                if (phoneField) {
                    // Ορισμός τηλεφώνου ως υποχρεωτικό για ελληνικές διευθύνσεις
                    phoneField.setAttribute('required', 'required');
                    phoneField.placeholder = 'Τηλέφωνο (π.χ. 2101234567)';
                }
                
                // Ειδοποίηση χρήστη για τις απαιτήσεις ελληνικής μορφής
                Notifications.info('Η διεύθυνση είναι στην Ελλάδα - απαιτούνται 5-ψήφιοι ΤΚ και έγκυρο ελληνικό τηλέφωνο');
            }
        });
    }
    
    /**
     * Συνάρτηση επαλήθευσης μορφής domain (σε επίπεδο client)
     * 
     * Εκτελεί βασικούς ελέγχους για τη μορφή του domain:
     * 1. Ελέγχει αν το domain έχει τουλάχιστον μία τελεία
     * 2. Ελέγχει αν το TLD έχει τουλάχιστον 2 χαρακτήρες
     * 
     * Περιορισμοί: Δεν μπορεί να επαληθεύσει την πραγματική ύπαρξη του domain
     * (αυτό γίνεται στο backend με DNS lookups)
     * 
     * @param {string} email - Η διεύθυνση email προς έλεγχο
     * @returns {boolean} Αν το domain έχει έγκυρη μορφή
     */
    function checkDomainFormat(email) {
        const domain = email.split('@')[1];
        if (!domain) return false;
        
        // Έλεγχος αν το domain έχει τουλάχιστον μία τελεία και έγκυρο TLD
        const parts = domain.split('.');
        if (parts.length < 2) return false;
        
        // Έλεγχος αν το TLD είναι τουλάχιστον 2 χαρακτήρες
        const tld = parts[parts.length - 1];
        return tld.length >= 2;
    }
    
    // Ειδικός χειρισμός πεδίου email (έλεγχος domain)
    // Παρέχει επιπλέον validation πέρα από το RegExp pattern
    const emailField = shippingForm.querySelector('[name="email"]');
    if (emailField) {
        emailField.addEventListener('blur', function() {
            const email = this.value.trim();
            
            // Έλεγχος μόνο αν υπάρχει email και περνάει τη βασική επικύρωση
            if (email && validationPatterns.email.pattern.test(email)) {
                // Έλεγχος μορφής domain ως best-effort client-side check
                // Σημείωση: Πλήρης επαλήθευση domain γίνεται στο backend
                if (!checkDomainFormat(email)) {
                    this.classList.remove('is-valid');
                    this.classList.add('is-invalid');
                    
                    Notifications.warning('Το domain του email δεν φαίνεται έγκυρο');
                    
                    // Προσθήκη μηνύματος επικύρωσης
                    let feedbackElement = this.nextElementSibling;
                    if (!feedbackElement || !feedbackElement.classList.contains('invalid-feedback')) {
                        feedbackElement = document.createElement('div');
                        feedbackElement.className = 'invalid-feedback';
                        this.parentNode.insertBefore(feedbackElement, this.nextSibling);
                    }
                    feedbackElement.textContent = 'Το domain του email δεν φαίνεται έγκυρο';
                }
            }
        });
    }
});