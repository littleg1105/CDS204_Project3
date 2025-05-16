/**
 * Cart Management Script
 * 
 * Αυτό το script χειρίζεται τη λειτουργικότητα του καλαθιού αγορών,
 * συμπεριλαμβανομένων ενημερώσεων ποσότητας, διαγραφής αντικειμένων,
 * και ενημέρωσης τιμών σε πραγματικό χρόνο.
 * 
 * Λειτουργίες:
 * - Αύξηση/μείωση ποσότητας με κουμπιά +/-
 * - Άμεση ενημέρωση μέσω πεδίου εισαγωγής
 * - Υπολογισμός και ενημέρωση τιμών
 * - Αφαίρεση προϊόντων από το καλάθι
 * - Επικύρωση φόρμας αποστολής
 */

document.addEventListener('DOMContentLoaded', function() {
    // =========================================================================
    // ΧΕΙΡΙΣΜΟΣ ΚΟΥΜΠΙΩΝ ΠΟΣΟΤΗΤΑΣ (+/-)
    // =========================================================================
    
    // Επιλογή όλων των κουμπιών αύξησης/μείωσης ποσότητας
    // Selector: Χρησιμοποιεί ένα κοινό class για όλα τα κουμπιά ποσότητας
    const quantityButtons = document.querySelectorAll('.quantity-btn');
    
    // Προσθήκη event listener σε κάθε κουμπί
    // Event Delegation: Εφαρμογή του ίδιου χειρισμού σε πολλαπλά παρόμοια elements
    quantityButtons.forEach(button => {
        button.addEventListener('click', function(e) {
            e.preventDefault();  // Αποτροπή default behavior του κουμπιού
            
            // Ανάκτηση απαραίτητων δεδομένων από data attributes
            // Data Attributes: Αποθήκευση δεδομένων στο DOM για χρήση από JavaScript
            const cartItemId = this.getAttribute('data-cart-item-id');  // ID του αντικειμένου
            const action = this.getAttribute('data-action');  // 'increase' ή 'decrease'
            const csrfToken = this.getAttribute('data-csrf-token');  // Για ασφάλεια CSRF
            
            // Εύρεση του σχετικού πεδίου εισαγωγής 
            // DOM Traversal: Πλοήγηση στο DOM tree από το κουμπί προς το input
            const inputField = this.parentElement.querySelector('.quantity-input');
            
            // Ενημέρωση της τιμής ποσότητας ανάλογα με την ενέργεια
            // Number Parsing: Μετατροπή του string σε integer για αριθμητικές πράξεις
            let currentQty = parseInt(inputField.value);
            
            // Λογική αύξησης/μείωσης με έλεγχο για ελάχιστη ποσότητα 1
            // Business Logic: Υποχρεωτική ελάχιστη ποσότητα 1
            if (action === 'decrease' && currentQty > 1) {
                currentQty--;  // Μείωση ποσότητας
            } else if (action === 'increase') {
                currentQty++;  // Αύξηση ποσότητας
            }
            
            // Ενημέρωση του πεδίου εισαγωγής με τη νέα τιμή
            inputField.value = currentQty;
            
            // Κλήση της συνάρτησης για ενημέρωση στο server
            // AJAX Update: Ασύγχρονη ενημέρωση του server χωρίς refresh της σελίδας
            updateCartItemQuantity(cartItemId, currentQty, csrfToken);
        });
    });
    
    // =========================================================================
    // ΧΕΙΡΙΣΜΟΣ ΑΜΕΣΗΣ ΑΛΛΑΓΗΣ ΑΠΟ INPUT
    // =========================================================================
    
    // Επιλογή όλων των πεδίων εισαγωγής ποσότητας
    const quantityInputs = document.querySelectorAll('.quantity-input');
    
    // Προσθήκη event listener για το συμβάν change
    // Event Type: Το 'change' ενεργοποιείται όταν χάνεται το focus και η τιμή έχει αλλάξει
    quantityInputs.forEach(input => {
        input.addEventListener('change', function(e) {
            // Ανάκτηση δεδομένων από data attributes
            const cartItemId = this.getAttribute('data-cart-item-id');
            const csrfToken = this.getAttribute('data-csrf-token');
            
            // Λήψη και επικύρωση της νέας ποσότητας
            const newQty = parseInt(this.value);
            
            // Έλεγχος εγκυρότητας - ποσότητα πρέπει να είναι τουλάχιστον 1
            // Input Validation: Επικύρωση και διόρθωση τιμών εισόδου
            if (newQty < 1) {
                this.value = 1;  // Επαναφορά σε ελάχιστη επιτρεπτή τιμή
                return;  // Έξοδος από τη συνάρτηση χωρίς AJAX update
            }
            
            // Ενημέρωση του καλαθιού στο server
            updateCartItemQuantity(cartItemId, newQty, csrfToken);
        });
    });
    
    // =========================================================================
    // ΣΥΝΑΡΤΗΣΗ ΕΝΗΜΕΡΩΣΗΣ ΠΟΣΟΤΗΤΑΣ
    // =========================================================================
    
    /**
     * Ενημερώνει την ποσότητα ενός αντικειμένου στο καλάθι μέσω AJAX
     * 
     * Λειτουργία:
     * 1. Αποστολή του αιτήματος στο server με fetch
     * 2. Ενημέρωση των τιμών στο UI με βάση την απάντηση
     * 3. Χειρισμός πιθανών σφαλμάτων
     * 
     * @param {string} cartItemId - Το ID του αντικειμένου καλαθιού
     * @param {number} quantity - Η νέα ποσότητα
     * @param {string} csrfToken - Το token CSRF για ασφάλεια
     */
    function updateCartItemQuantity(cartItemId, quantity, csrfToken) {
        // Δημιουργία αιτήματος AJAX με το Fetch API
        // AJAX Request: Ασύγχρονη επικοινωνία με το server
        fetch('/update-cart-item/', {
            method: 'POST',  // HTTP Method για ενημέρωση δεδομένων
            headers: {
                'Content-Type': 'application/json',  // Μορφή δεδομένων
                'X-CSRFToken': csrfToken  // Ασφάλεια CSRF
            },
            body: JSON.stringify({ cart_item_id: cartItemId, quantity: quantity })  // Μετατροπή δεδομένων σε JSON
        })
        .then(response => {
            // Έλεγχος για HTTP errors
            // Error Handling: Αντιμετώπιση σφαλμάτων επικοινωνίας
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            // Parse του JSON response
            return response.json();
        })
        .then(data => {
            // Επιτυχής ενημέρωση - ανανέωση των στοιχείων UI
            
            // 1. Ενημέρωση του συνόλου του συγκεκριμένου προϊόντος
            // Number Formatting: Μορφοποίηση αριθμών με σταθερό αριθμό δεκαδικών
            const itemTotal = parseFloat(data.item_total);
            document.getElementById(`item-total-${cartItemId}`).textContent = itemTotal.toFixed(2) + '€';
            
            // 2. Ενημέρωση του συνολικού ποσού καλαθιού
            const cartTotal = parseFloat(data.cart_total);
            document.getElementById('cart-total').textContent = cartTotal.toFixed(2) + '€';
            
            // 3. Ενημέρωση της σύνοψης παραγγελίας (αν υπάρχει)
            // DOM Traversal: Αναζήτηση και ενημέρωση σχετικών στοιχείων στο DOM
            const orderSummary = document.querySelectorAll('.list-group-item');
            orderSummary.forEach(item => {
                // Εύρεση του συγκεκριμένου αντικειμένου στη σύνοψη παραγγελίας
                const productTitleElement = document.querySelector(`#cart-item-${cartItemId} td:first-child span`);
                
                // Αν βρεθεί το αντίστοιχο προϊόν στη σύνοψη
                if (productTitleElement && item.textContent.includes(productTitleElement.textContent)) {
                    // Υπολογισμός τιμής ανά τεμάχιο
                    const itemTotalValue = parseFloat(data.item_total);
                    const pricePerItem = itemTotalValue / quantity;
                    
                    // Ενημέρωση της ποσότητας και τιμής μονάδας
                    const smallTag = item.querySelector('small');
                    if (smallTag) {
                        smallTag.textContent = `${quantity} τεμ. x ${pricePerItem.toFixed(2)}€`;
                    }
                    
                    // Ενημέρωση της συνολικής τιμής προϊόντος
                    const priceElement = item.querySelector('span.text-muted');
                    if (priceElement) {
                        priceElement.textContent = itemTotalValue.toFixed(2) + '€';
                    }
                }
            });
            
            // 4. Ενημέρωση του τελικού συνόλου στη σύνοψη παραγγελίας
            const totalElement = document.querySelector('.list-group-item strong');
            if (totalElement) {
                const cartTotalValue = parseFloat(data.cart_total);
                totalElement.textContent = cartTotalValue.toFixed(2) + '€';
            }
        })
        .catch(error => {
            // Χειρισμός σφαλμάτων
            // Error Handling: Καταγραφή σφαλμάτων και ενημέρωση χρήστη
            console.error('Error:', error);
            alert('Σφάλμα κατά την ενημέρωση του καλαθιού.');
        });
    }
    
    // =========================================================================
    // ΕΠΙΚΥΡΩΣΗ ΦΟΡΜΑΣ
    // =========================================================================
    
    // Εύρεση της φόρμας αποστολής αν υπάρχει
    const form = document.getElementById('shipping-form');
    if (form) {
        // Προσθήκη event listener για το συμβάν υποβολής
        // Form Validation: Έλεγχος εγκυρότητας πριν την υποβολή
        form.addEventListener('submit', function(event) {
            // Έλεγχος εγκυρότητας φόρμας με HTML5 validation API
            if (!form.checkValidity()) {
                // Αποτροπή υποβολής αν η φόρμα δεν είναι έγκυρη
                event.preventDefault();
                event.stopPropagation();
                
                // Προσθήκη class για εμφάνιση validation feedback
                // Bootstrap Integration: Χρήση του συστήματος επικύρωσης του Bootstrap
                form.classList.add('was-validated');
            } else {
                // Η φόρμα είναι έγκυρη, θα υποβληθεί κανονικά
                console.log("Form is valid, submitting...");
            }
        });
    }
    
    // =========================================================================
    // ΧΕΙΡΙΣΜΟΣ ΚΟΥΜΠΙΩΝ ΔΙΑΓΡΑΦΗΣ
    // =========================================================================
    
    // Επιλογή όλων των κουμπιών διαγραφής από το καλάθι
    const removeFromCartButtons = document.querySelectorAll('.remove-from-cart-btn');
    
    // Προσθήκη event listener σε κάθε κουμπί διαγραφής
    removeFromCartButtons.forEach(button => {
        button.addEventListener('click', function(e) {
            e.preventDefault();  // Αποτροπή default συμπεριφοράς του συνδέσμου
            
            // Ανάκτηση απαραίτητων δεδομένων
            const cartItemId = this.getAttribute('data-cart-item-id');
            const csrfToken = this.getAttribute('data-csrf-token');
            
            // Ενημέρωση UI για οπτική ανατροφοδότηση - εμφάνιση spinner
            // UX Best Practice: Δείχνει στο χρήστη ότι η ενέργεια είναι σε εξέλιξη
            this.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span>';
            this.disabled = true;  // Αποφυγή διπλών κλικ
            
            // Δημιουργία και αποστολή AJAX request
            fetch('/remove-from-cart/', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken
                },
                body: JSON.stringify({ cart_item_id: cartItemId })
            })
            .then(response => {
                // Έλεγχος για HTTP errors
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                return response.json();
            })
            .then(data => {
                // Επιτυχής διαγραφή - ανανέωση της σελίδας
                // Page Refresh: Πλήρης ανανέωση για ενημέρωση όλων των στοιχείων
                window.location.reload();
            })
            .catch(error => {
                // Χειρισμός σφαλμάτων
                console.error('Error:', error);
                
                // Επαναφορά κουμπιού με μήνυμα σφάλματος
                this.innerHTML = 'Σφάλμα!';
                
                // Επαναφορά μετά από 2 δευτερόλεπτα
                setTimeout(() => {
                    this.innerHTML = 'Αφαίρεση';
                    this.disabled = false;
                }, 2000);
            });
        });
    });
});