document.addEventListener('DOMContentLoaded', function() {
    // Προσθήκη event listeners σε όλα τα κουμπιά προσθήκης στο καλάθι
    const addToCartButtons = document.querySelectorAll('.add-to-cart-btn');
    
    addToCartButtons.forEach(button => {
        button.addEventListener('click', function(e) {
            e.preventDefault();
            const productId = this.getAttribute('data-product-id');
            const productName = this.getAttribute('data-product-name');
            const csrfToken = this.getAttribute('data-csrf-token');
            
            // Αλλαγή εμφάνισης κουμπιού κατά τη διάρκεια του αιτήματος
            this.innerHTML = 'Προσθήκη...';
            this.disabled = true;
            
            // Δημιουργία αιτήματος AJAX
            fetch('/add-to-cart/', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken
                },
                body: JSON.stringify({ product_id: productId })
            })
            .then(response => {
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                return response.json();
            })
            .then(data => {
                // Ενημέρωση του αριθμού αντικειμένων στο καλάθι
                const cartCount = document.getElementById('cart-items-count');
                if (cartCount) {
                    cartCount.innerHTML = 
                        `<strong>${data.cart_items_count}</strong> προϊόν${data.cart_items_count !== 1 ? 'α' : ''} στο καλάθι`;
                }
                
                // Αφαίρεση της class disabled από το κουμπί πληρωμής
                const paymentButton = document.querySelector('.payment-button');
                if (paymentButton) {
                    paymentButton.classList.remove('disabled');
                }
                
                // Επαναφορά του κουμπιού
                button.innerHTML = 'Προστέθηκε ✓';
                setTimeout(() => {
                    button.innerHTML = 'Προσθήκη στο καλάθι';
                    button.disabled = false;
                }, 2000);
                
                // Ανανέωση της σελίδας για να ενημερωθεί το preview του καλαθιού
                window.location.reload();
            })
            .catch(error => {
                console.error('Error:', error);
                button.innerHTML = 'Σφάλμα - Προσπαθήστε ξανά';
                setTimeout(() => {
                    button.innerHTML = 'Προσθήκη στο καλάθι';
                    button.disabled = false;
                }, 2000);
            });
        });
    });

    // Προσθήκη event listeners για τα κουμπιά διαγραφής
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
                // Ενημέρωση του αριθμού αντικειμένων στο καλάθι
                const cartCount = document.getElementById('cart-items-count');
                if (cartCount) {
                    cartCount.innerHTML = 
                        `<strong>${data.cart_items_count}</strong> προϊόν${data.cart_items_count !== 1 ? 'α' : ''} στο καλάθι`;
                }
                
                // Ανανέωση της σελίδας για να ενημερωθεί το preview του καλαθιού
                window.location.reload();
            })
            .catch(error => {
                console.error('Error:', error);
                this.innerHTML = 'Σφάλμα!';
                setTimeout(() => {
                    this.innerHTML = 'X';
                    this.disabled = false;
                }, 2000);
            });
        });
    });





});