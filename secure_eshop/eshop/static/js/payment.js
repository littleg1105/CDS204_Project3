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

// =========================================================================
// HELPER FUNCTIONS
// =========================================================================

/**
 * Υπολογίζει τη νέα ποσότητα με βάση την ενέργεια
 */
function calculateNewQuantity(currentQty, action) {
    // Λογική αύξησης/μείωσης με έλεγχο για ελάχιστη ποσότητα 1
    if (action === 'decrease' && currentQty > 1) {
        return currentQty - 1;
    } else if (action === 'increase') {
        return currentQty + 1;
    }
    return currentQty;
}

/**
 * Ενημερώνει το UI με τα νέα δεδομένα καλαθιού
 */
function updateCartUI(data, cartItemId) {
    // 1. Ενημέρωση του συνόλου του συγκεκριμένου προϊόντος
    const itemTotal = parseFloat(data.item_total);
    const itemTotalElement = document.getElementById(`item-total-${cartItemId}`);
    if (itemTotalElement) {
        itemTotalElement.textContent = itemTotal.toFixed(2) + '€';
    }
    
    // 2. Ενημέρωση του συνολικού ποσού καλαθιού
    const cartTotal = parseFloat(data.cart_total);
    const cartTotalElement = document.getElementById('cart-total');
    if (cartTotalElement) {
        cartTotalElement.textContent = cartTotal.toFixed(2) + '€';
    }
    
    // 3. Ενημέρωση της σύνοψης παραγγελίας
    updateOrderSummary(data, cartItemId);
    
    // 4. Ενημέρωση του τελικού συνόλου στη σύνοψη παραγγελίας
    updateFinalTotal(data.cart_total);
}

/**
 * Ενημερώνει τη σύνοψη παραγγελίας
 */
function updateOrderSummary(data, cartItemId) {
    const productTitleElement = document.querySelector(`#cart-item-${cartItemId} td:first-child span`);
    if (!productTitleElement) return;
    
    const orderSummary = document.querySelectorAll('.list-group-item');
    orderSummary.forEach(item => {
        if (item.textContent.includes(productTitleElement.textContent)) {
            updateOrderSummaryItem(item, data, cartItemId);
        }
    });
}

/**
 * Ενημερώνει ένα συγκεκριμένο αντικείμενο στη σύνοψη παραγγελίας
 */
function updateOrderSummaryItem(item, data, cartItemId) {
    const itemTotalValue = parseFloat(data.item_total);
    const quantityInput = document.querySelector(`#cart-item-${cartItemId} .quantity-input`);
    if (!quantityInput) return;
    
    const quantity = parseInt(quantityInput.value);
    const pricePerItem = itemTotalValue / quantity;
    
    // Ενημέρωση ποσότητας και τιμής μονάδας
    const smallTag = item.querySelector('small');
    if (smallTag) {
        smallTag.textContent = `${quantity} τεμ. x ${pricePerItem.toFixed(2)}€`;
    }
    
    // Ενημέρωση συνολικής τιμής προϊόντος
    const priceElement = item.querySelector('span.text-muted');
    if (priceElement) {
        priceElement.textContent = itemTotalValue.toFixed(2) + '€';
    }
}

/**
 * Ενημερώνει το τελικό σύνολο στη σύνοψη παραγγελίας
 */
function updateFinalTotal(cartTotal) {
    const totalElement = document.querySelector('.list-group-item strong');
    if (totalElement) {
        const cartTotalValue = parseFloat(cartTotal);
        totalElement.textContent = cartTotalValue.toFixed(2) + '€';
    }
}

/**
 * Εμφανίζει μήνυμα σφάλματος σε κουμπί και το επαναφέρει
 */
function showButtonError(button, errorText, originalText) {
    button.innerHTML = errorText;
    setTimeout(() => {
        button.innerHTML = originalText;
        button.disabled = false;
    }, 2000);
}

// =========================================================================
// AJAX FUNCTIONS
// =========================================================================

/**
 * Στέλνει AJAX POST request
 */
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

/**
 * Ενημερώνει την ποσότητα ενός αντικειμένου στο καλάθι μέσω AJAX
 */
async function updateCartItemQuantity(cartItemId, quantity, csrfToken) {
    try {
        const data = await sendPostRequest(
            '/update-cart-item/', 
            { cart_item_id: cartItemId, quantity: quantity },
            csrfToken
        );
        updateCartUI(data, cartItemId);
    } catch (error) {
        console.error('Error:', error);
        alert('Σφάλμα κατά την ενημέρωση του καλαθιού.');
    }
}

// =========================================================================
// EVENT HANDLERS
// =========================================================================

/**
 * Χειρίζεται τα κλικ στα κουμπιά ποσότητας (+/-)
 */
function handleQuantityButtonClick(event) {
    event.preventDefault();
    const button = event.target;
    
    // Ανάκτηση δεδομένων
    const cartItemId = button.getAttribute('data-cart-item-id');
    const action = button.getAttribute('data-action');
    const csrfToken = button.getAttribute('data-csrf-token');
    
    // Εύρεση του σχετικού πεδίου εισαγωγής
    const inputField = button.parentElement.querySelector('.quantity-input');
    let currentQty = parseInt(inputField.value);
    
    // Υπολογισμός νέας ποσότητας
    const newQty = calculateNewQuantity(currentQty, action);
    
    // Ενημέρωση πεδίου και server
    inputField.value = newQty;
    updateCartItemQuantity(cartItemId, newQty, csrfToken);
}

/**
 * Χειρίζεται τις αλλαγές στα πεδία εισαγωγής ποσότητας
 */
function handleQuantityInputChange(event) {
    const input = event.target;
    
    // Ανάκτηση δεδομένων
    const cartItemId = input.getAttribute('data-cart-item-id');
    const csrfToken = input.getAttribute('data-csrf-token');
    
    // Επικύρωση και ενημέρωση
    const newQty = parseInt(input.value);
    if (newQty < 1) {
        input.value = 1;
        return;
    }
    
    updateCartItemQuantity(cartItemId, newQty, csrfToken);
}

/**
 * Χειρίζεται την αφαίρεση προϊόντων από το καλάθι
 */
async function handleRemoveFromCart(event) {
    event.preventDefault();
    const button = event.target;
    
    // Ανάκτηση δεδομένων
    const cartItemId = button.getAttribute('data-cart-item-id');
    const csrfToken = button.getAttribute('data-csrf-token');
    
    // Loading state
    button.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span>';
    button.disabled = true;
    
    try {
        await sendPostRequest(
            '/remove-from-cart/', 
            { cart_item_id: cartItemId },
            csrfToken
        );
        window.location.reload();
    } catch (error) {
        console.error('Error:', error);
        showButtonError(button, 'Σφάλμα!', 'Αφαίρεση');
    }
}

/**
 * Χειρίζεται την υποβολή φόρμας
 */
function handleFormSubmit(event) {
    const form = event.target;
    
    if (!form.checkValidity()) {
        event.preventDefault();
        event.stopPropagation();
        form.classList.add('was-validated');
    } else {
        console.log("Form is valid, submitting...");
    }
}

// =========================================================================
// INITIALIZATION
// =========================================================================

/**
 * Αρχικοποιεί όλους τους event listeners
 */
function initializePaymentHandlers() {
    // Κουμπιά ποσότητας (+/-)
    const quantityButtons = document.querySelectorAll('.quantity-btn');
    quantityButtons.forEach(button => {
        button.addEventListener('click', handleQuantityButtonClick);
    });
    
    // Πεδία εισαγωγής ποσότητας
    const quantityInputs = document.querySelectorAll('.quantity-input');
    quantityInputs.forEach(input => {
        input.addEventListener('change', handleQuantityInputChange);
    });
    
    // Επικύρωση φόρμας
    const form = document.getElementById('shipping-form');
    if (form) {
        form.addEventListener('submit', handleFormSubmit);
    }
    
    // Κουμπιά διαγραφής
    const removeButtons = document.querySelectorAll('.remove-from-cart-btn');
    removeButtons.forEach(button => {
        button.addEventListener('click', handleRemoveFromCart);
    });
}

// Εκκίνηση όταν φορτωθεί το DOM
document.addEventListener('DOMContentLoaded', initializePaymentHandlers);