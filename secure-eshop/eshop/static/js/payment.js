document.addEventListener('DOMContentLoaded', function() {
    // Χειρισμός των κουμπιών +/- ποσότητας
    const quantityButtons = document.querySelectorAll('.quantity-btn');
    quantityButtons.forEach(button => {
        button.addEventListener('click', function(e) {
            e.preventDefault();
            const cartItemId = this.getAttribute('data-cart-item-id');
            const action = this.getAttribute('data-action');
            const csrfToken = this.getAttribute('data-csrf-token');
            const inputField = this.parentElement.querySelector('.quantity-input');
            
            let currentQty = parseInt(inputField.value);
            if (action === 'decrease' && currentQty > 1) {
                currentQty--;
            } else if (action === 'increase') {
                currentQty++;
            }
            
            inputField.value = currentQty;
            
            // Ενημέρωση της ποσότητας μέσω AJAX
            updateCartItemQuantity(cartItemId, currentQty, csrfToken);
        });
    });
    
    // Χειρισμός της άμεσης αλλαγής από το input
    const quantityInputs = document.querySelectorAll('.quantity-input');
    quantityInputs.forEach(input => {
        input.addEventListener('change', function(e) {
            const cartItemId = this.getAttribute('data-cart-item-id');
            const csrfToken = this.getAttribute('data-csrf-token');
            const newQty = parseInt(this.value);
            
            if (newQty < 1) {
                this.value = 1;
                return;
            }
            
            updateCartItemQuantity(cartItemId, newQty, csrfToken);
        });
    });
    
    // Συνάρτηση για την ενημέρωση της ποσότητας
    function updateCartItemQuantity(cartItemId, quantity, csrfToken) {
        fetch('/update-cart-item/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken
            },
            body: JSON.stringify({ cart_item_id: cartItemId, quantity: quantity })
        })
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            // Ενημέρωση του συνόλου του προϊόντος
            const itemTotal = parseFloat(data.item_total);
            document.getElementById(`item-total-${cartItemId}`).textContent = itemTotal.toFixed(2) + '€';
            
            // Ενημέρωση του συνολικού ποσού
            const cartTotal = parseFloat(data.cart_total);
            document.getElementById('cart-total').textContent = cartTotal.toFixed(2) + '€';
            
            // Ενημέρωση της σύνοψης παραγγελίας
            const orderSummary = document.querySelectorAll('.list-group-item');
            orderSummary.forEach(item => {
                // Αν βρούμε το αντικείμενο που ενημερώθηκε
                const productTitleElement = document.querySelector(`#cart-item-${cartItemId} td:first-child span`);
                if (productTitleElement && item.textContent.includes(productTitleElement.textContent)) {
                    const itemTotalValue = parseFloat(data.item_total);
                    const pricePerItem = itemTotalValue / quantity;
                    const smallTag = item.querySelector('small');
                    if (smallTag) {
                        smallTag.textContent = `${quantity} τεμ. x ${pricePerItem.toFixed(2)}€`;
                    }
                    const priceElement = item.querySelector('span.text-muted');
                    if (priceElement) {
                        priceElement.textContent = itemTotalValue.toFixed(2) + '€';
                    }
                }
            });
            
            // Ενημέρωση του συνολικού ποσού στη σύνοψη παραγγελίας
            const totalElement = document.querySelector('.list-group-item strong');
            if (totalElement) {
                const cartTotalValue = parseFloat(data.cart_total);
                totalElement.textContent = cartTotalValue.toFixed(2) + '€';
            }
        })
        .catch(error => {
            console.error('Error:', error);
            alert('Σφάλμα κατά την ενημέρωση του καλαθιού.');
        });
    }
    
    // Form validation
    const form = document.getElementById('shipping-form');
    if (form) {
        form.addEventListener('submit', function(event) {
            if (!form.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();
                form.classList.add('was-validated');
            } else {
                // Form is valid, will submit normally
                console.log("Form is valid, submitting...");
            }
        });
    }
    
    // Χειρισμός των κουμπιών διαγραφής
    const removeFromCartButtons = document.querySelectorAll('.remove-from-cart-btn');
    removeFromCartButtons.forEach(button => {
        button.addEventListener('click', function(e) {
            e.preventDefault();
            const cartItemId = this.getAttribute('data-cart-item-id');
            const csrfToken = this.getAttribute('data-csrf-token');
            
            // Αλλαγή εμφάνισης κουμπιού κατά τη διάρκεια του αιτήματος
            this.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span>';
            this.disabled = true;
            
            // Δημιουργία αιτήματος AJAX
            fetch('/remove-from-cart/', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken
                },
                body: JSON.stringify({ cart_item_id: cartItemId })
            })
            .then(response => {
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                return response.json();
            })
            .then(data => {
                // Ανανέωση της σελίδας
                window.location.reload();
            })
            .catch(error => {
                console.error('Error:', error);
                this.innerHTML = 'Σφάλμα!';
                setTimeout(() => {
                    this.innerHTML = 'Αφαίρεση';
                    this.disabled = false;
                }, 2000);
            });
        });
    });
});