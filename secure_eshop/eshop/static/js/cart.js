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

// Helper function για ενημέρωση του μετρητή καλαθιού
function updateCartCount(count) {
    const cartCount = document.getElementById('cart-items-count');
    if (cartCount) {
        // Δυναμική προσαρμογή του κειμένου με βάση τον αριθμό (πληθυντικός/ενικός)
        cartCount.innerHTML = 
            `<strong>${count}</strong> προϊόν${count !== 1 ? 'α' : ''} στο καλάθι`;
    }
}

// Helper function για ενημέρωση κουμπιού πληρωμής
function updatePaymentButton() {
    const paymentButton = document.querySelector('.payment-button');
    if (paymentButton) {
        paymentButton.classList.remove('disabled');
    }
}

// Helper function για επαναφορά κουμπιού με καθυστέρηση
function resetButtonAfterDelay(button, originalText, delay = 2000) {
    setTimeout(() => {
        button.innerHTML = originalText;
        button.disabled = false;
    }, delay);
}

// Helper function για εμφάνιση μηνύματος σφάλματος σε κουμπί
function showButtonError(button, originalText) {
    button.innerHTML = 'Σφάλμα - Προσπαθήστε ξανά';
    resetButtonAfterDelay(button, originalText);
}

// Helper function για αποστολή POST request
async function sendPostRequest(url, data, csrfToken) {
    const response = await fetch(url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': csrfToken
        },
        body: JSON.stringify(data)
    });
    
    if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
    }
    
    return response.json();
}

// Handler για προσθήκη στο καλάθι
async function handleAddToCart(event) {
    event.preventDefault();
    const button = event.target;
    
    // Λήψη απαραίτητων δεδομένων από data attributes του κουμπιού
    const productId = button.getAttribute('data-product-id');
    const csrfToken = button.getAttribute('data-csrf-token');
    
    // Ενημέρωση UI για feedback στο χρήστη (loading state)
    button.innerHTML = 'Προσθήκη...';
    button.disabled = true;
    
    try {
        // Αποστολή request
        const data = await sendPostRequest('/add-to-cart/', { product_id: productId }, csrfToken);
        
        // Επιτυχής προσθήκη - ενημέρωση του UI
        updateCartCount(data.cart_items_count);
        updatePaymentButton();
        
        // Ενημέρωση του κουμπιού για θετική επιβεβαίωση
        button.innerHTML = 'Προστέθηκε ✓';
        resetButtonAfterDelay(button, 'Προσθήκη στο καλάθι');
        
        // Ανανέωση της σελίδας για ενημέρωση του preview καλαθιού
        window.location.reload();
    } catch (error) {
        console.error('Error:', error);
        showButtonError(button, 'Προσθήκη στο καλάθι');
    }
}

// Handler για αφαίρεση από το καλάθι
async function handleRemoveFromCart(event) {
    event.preventDefault();
    const button = event.target;
    
    // Λήψη απαραίτητων δεδομένων από data attributes
    const cartItemId = button.getAttribute('data-cart-item-id');
    const csrfToken = button.getAttribute('data-csrf-token');
    
    // Ενημέρωση UI για feedback - εμφάνιση spinner
    button.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span>';
    button.disabled = true;
    
    try {
        // Αποστολή request
        const data = await sendPostRequest('/remove-from-cart/', { cart_item_id: cartItemId }, csrfToken);
        
        // Επιτυχής αφαίρεση - ενημέρωση του UI
        updateCartCount(data.cart_items_count);
        
        // Ανανέωση σελίδας για ενημέρωση του καλαθιού
        window.location.reload();
    } catch (error) {
        console.error('Error:', error);
        button.innerHTML = 'Σφάλμα!';
        resetButtonAfterDelay(button, 'X');
    }
}

// Αρχικοποίηση event listeners όταν φορτωθεί το DOM
function initializeCartHandlers() {
    // =========================================================================
    // ΠΡΟΣΘΗΚΗ ΣΤΟ ΚΑΛΑΘΙ (Add to Cart)
    // =========================================================================
    
    // Εύρεση όλων των κουμπιών προσθήκης στο καλάθι στη σελίδα
    const addToCartButtons = document.querySelectorAll('.add-to-cart-btn');
    
    // Προσθήκη event listener σε κάθε κουμπί προσθήκης
    addToCartButtons.forEach(button => {
        button.addEventListener('click', handleAddToCart);
    });

    // =========================================================================
    // ΑΦΑΙΡΕΣΗ ΑΠΟ ΤΟ ΚΑΛΑΘΙ (Remove from Cart)
    // =========================================================================
    
    // Εύρεση όλων των κουμπιών αφαίρεσης από το καλάθι
    const removeFromCartButtons = document.querySelectorAll('.remove-from-cart-btn');
    
    // Προσθήκη event listener σε κάθε κουμπί αφαίρεσης
    removeFromCartButtons.forEach(button => {
        button.addEventListener('click', handleRemoveFromCart);
    });
}

// Εκκίνηση της εφαρμογής όταν φορτωθεί το DOM
document.addEventListener('DOMContentLoaded', initializeCartHandlers);