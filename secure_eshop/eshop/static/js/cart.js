/**
 * Shopping Cart Management Script
 * 
 * Αυτό το script χειρίζεται την προσθήκη και αφαίρεση προϊόντων από το καλάθι αγορών
 * χρησιμοποιώντας AJAX requests για ομαλή εμπειρία χρήστη χωρίς refresh της σελίδας.
 * 
 * Λειτουργίες:
 * - Προσθήκη προϊόντων στο καλάθι με AJAX
 * - Αφαίρεση προϊόντων από το καλάθι με AJAX
 * - Ενημέρωση UI με βάση τα αποτελέσματα
 * - Χειρισμός σφαλμάτων και ανατροφοδότηση χρήστη
 */

document.addEventListener('DOMContentLoaded', function() {
    // =========================================================================
    // ΠΡΟΣΘΗΚΗ ΣΤΟ ΚΑΛΑΘΙ (Add to Cart)
    // =========================================================================
    
    // Εύρεση όλων των κουμπιών προσθήκης στο καλάθι στη σελίδα
    // Selector: Επιλέγει όλα τα elements με class 'add-to-cart-btn'
    const addToCartButtons = document.querySelectorAll('.add-to-cart-btn');
    
    // Προσθήκη event listener σε κάθε κουμπί προσθήκης
    // Τεχνική: Event delegation - Εφαρμογή κοινής λογικής σε πολλαπλά στοιχεία
    addToCartButtons.forEach(button => {
        button.addEventListener('click', function(e) {
            e.preventDefault();  // Αποτροπή default συμπεριφοράς του κουμπιού
            
            // Λήψη απαραίτητων δεδομένων από data attributes του κουμπιού
            // Data Attributes: Αποθήκευση δεδομένων στο DOM για χρήση από JavaScript
            const productId = this.getAttribute('data-product-id');
            const productName = this.getAttribute('data-product-name');
            const csrfToken = this.getAttribute('data-csrf-token');  // Απαραίτητο για ασφάλεια
            
            // Ενημέρωση UI για feedback στο χρήστη (loading state)
            // UX: Οπτική ανατροφοδότηση ότι το αίτημα βρίσκεται σε εξέλιξη
            this.innerHTML = 'Προσθήκη...';
            this.disabled = true;  // Αποτροπή πολλαπλών clicks
            
            // Δημιουργία και αποστολή AJAX request με το Fetch API
            // AJAX: Επιτρέπει ασύγχρονη επικοινωνία με τον server χωρίς page refresh
            fetch('/add-to-cart/', {
                method: 'POST',  // HTTP Method για δημιουργία/ενημέρωση δεδομένων
                headers: {
                    'Content-Type': 'application/json',  // Format δεδομένων
                    'X-CSRFToken': csrfToken  // CSRF Protection για ασφάλεια
                },
                body: JSON.stringify({ product_id: productId })  // Μετατροπή δεδομένων σε JSON
            })
            .then(response => {
                // Έλεγχος για HTTP errors (4xx, 5xx)
                // Error Handling: Αντιμετώπιση σφαλμάτων επικοινωνίας με τον server
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                // Parse του JSON response
                return response.json();
            })
            .then(data => {
                // Επιτυχής προσθήκη - ενημέρωση του UI
                
                // Ενημέρωση του αριθμού αντικειμένων στο καλάθι
                // DOM Manipulation: Ενημέρωση του UI βάσει των δεδομένων από το server
                const cartCount = document.getElementById('cart-items-count');
                if (cartCount) {
                    // Δυναμική προσαρμογή του κειμένου με βάση τον αριθμό (πληθυντικός/ενικός)
                    cartCount.innerHTML = 
                        `<strong>${data.cart_items_count}</strong> προϊόν${data.cart_items_count !== 1 ? 'α' : ''} στο καλάθι`;
                }
                
                // Ενεργοποίηση του κουμπιού πληρωμής αν υπάρχουν προϊόντα
                // Conditional UI: Προσαρμογή UI με βάση την κατάσταση του καλαθιού
                const paymentButton = document.querySelector('.payment-button');
                if (paymentButton) {
                    paymentButton.classList.remove('disabled');
                }
                
                // Ενημέρωση του κουμπιού για θετική επιβεβαίωση
                // UX Pattern: Επιβεβαίωση επιτυχίας με checkmark και προσωρινό μήνυμα
                button.innerHTML = 'Προστέθηκε ✓';
                
                // Επαναφορά του κουμπιού στην αρχική κατάσταση μετά από 2 δευτερόλεπτα
                // setTimeout: Ασύγχρονος προγραμματισμός για UI updates
                setTimeout(() => {
                    button.innerHTML = 'Προσθήκη στο καλάθι';
                    button.disabled = false;
                }, 2000);
                
                // Ανανέωση της σελίδας για ενημέρωση του preview καλαθιού
                // Σημείωση: Αυτό ακυρώνει μερικώς το πλεονέκτημα του AJAX.
                // Ιδανικά θα έπρεπε να ενημερωθεί μόνο το μέρος του DOM που αφορά το καλάθι
                window.location.reload();
            })
            .catch(error => {
                // Χειρισμός σφαλμάτων (πχ. network error, parsing error)
                // Error Handling: Παροχή feedback στο χρήστη σε περίπτωση αποτυχίας
                console.error('Error:', error);  // Καταγραφή για debugging
                
                // Ενημέρωση UI για το σφάλμα
                button.innerHTML = 'Σφάλμα - Προσπαθήστε ξανά';
                
                // Επαναφορά κουμπιού μετά από 2 δευτερόλεπτα
                setTimeout(() => {
                    button.innerHTML = 'Προσθήκη στο καλάθι';
                    button.disabled = false;
                }, 2000);
            });
        });
    });

    // =========================================================================
    // ΑΦΑΙΡΕΣΗ ΑΠΟ ΤΟ ΚΑΛΑΘΙ (Remove from Cart)
    // =========================================================================
    
    // Εύρεση όλων των κουμπιών αφαίρεσης από το καλάθι
    const removeFromCartButtons = document.querySelectorAll('.remove-from-cart-btn');
    
    // Προσθήκη event listener σε κάθε κουμπί αφαίρεσης
    removeFromCartButtons.forEach(button => {
        button.addEventListener('click', function(e) {
            e.preventDefault();  // Αποτροπή default συμπεριφοράς του κουμπιού
            
            // Λήψη απαραίτητων δεδομένων από data attributes
            const cartItemId = this.getAttribute('data-cart-item-id');
            const csrfToken = this.getAttribute('data-csrf-token');  // Για CSRF Protection
            
            // Ενημέρωση UI για feedback - εμφάνιση spinner
            // UX: Οπτική ένδειξη φόρτωσης με animation spinner από το Bootstrap
            this.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span>';
            this.disabled = true;  // Αποτροπή πολλαπλών clicks
            
            // Δημιουργία και αποστολή AJAX request
            fetch('/remove-from-cart/', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken  // Security: CSRF token για προστασία 
                },
                body: JSON.stringify({ cart_item_id: cartItemId })
            })
            .then(response => {
                // Έλεγχος για HTTP errors
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                // Parse του JSON response
                return response.json();
            })
            .then(data => {
                // Επιτυχής αφαίρεση - ενημέρωση του UI
                
                // Ενημέρωση του αριθμού αντικειμένων στο καλάθι
                const cartCount = document.getElementById('cart-items-count');
                if (cartCount) {
                    // Δυναμική προσαρμογή κειμένου με βάση τον αριθμό (πληθυντικός/ενικός)
                    cartCount.innerHTML = 
                        `<strong>${data.cart_items_count}</strong> προϊόν${data.cart_items_count !== 1 ? 'α' : ''} στο καλάθι`;
                }
                
                // Ανανέωση σελίδας για ενημέρωση του καλαθιού
                // Σημείωση: Όπως και με την προσθήκη, θα ήταν καλύτερη η ενημέρωση μόνο του DOM
                window.location.reload();
            })
            .catch(error => {
                // Χειρισμός σφαλμάτων
                console.error('Error:', error);  // Καταγραφή σφάλματος για debugging
                
                // Ενημέρωση UI για το σφάλμα
                this.innerHTML = 'Σφάλμα!';
                
                // Επαναφορά κουμπιού μετά από 2 δευτερόλεπτα
                setTimeout(() => {
                    this.innerHTML = 'X';  // Σύμβολο X για διαγραφή
                    this.disabled = false;
                }, 2000);
            });
        });
    });
});