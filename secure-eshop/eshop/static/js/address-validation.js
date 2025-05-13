/**
 * Address validation script for shipping forms
 * 
 * This script provides real-time client-side validation
 * for shipping address forms with immediate feedback.
 */

document.addEventListener('DOMContentLoaded', function() {
    // Get the shipping address form if it exists
    const shippingForm = document.querySelector('form.shipping-address-form');
    if (!shippingForm) return;
    
    // Define validation patterns
    const validationPatterns = {
        zip_code: {
            pattern: /^\d{5}$/,
            message: 'Ο ταχυδρομικός κώδικας πρέπει να αποτελείται από 5 ψηφία'
        },
        phone: {
            pattern: /^(?:\+30|0030)?(?:\s*)(?:(?:69\d{8})|(?:2\d{9}))$/,
            message: 'Παρακαλώ εισάγετε έγκυρο ελληνικό αριθμό τηλεφώνου (σταθερό ή κινητό)'
        },
        email: {
            pattern: /^[a-zA-Z0-9](?:[a-zA-Z0-9._%+-]{0,63}[a-zA-Z0-9])?@(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$/,
            message: 'Παρακαλώ εισάγετε έγκυρη διεύθυνση email'
        }
    };
    
    // Add input event listeners to all relevant fields
    shippingForm.querySelectorAll('input').forEach(input => {
        const fieldName = input.name;
        
        // Skip fields that don't have validation patterns
        if (!validationPatterns[fieldName]) return;
        
        input.addEventListener('input', function() {
            validateField(input, validationPatterns[fieldName]);
        });
        
        // Also validate on blur for better UX
        input.addEventListener('blur', function() {
            validateField(input, validationPatterns[fieldName], true);
        });
    });
    
    // Form submission handler
    shippingForm.addEventListener('submit', function(e) {
        // Prevent form submission if validation fails
        if (!validateForm(shippingForm)) {
            e.preventDefault();
            Notifications.error('Παρακαλώ διορθώστε τα σφάλματα στη φόρμα πριν συνεχίσετε');
        }
    });
    
    /**
     * Validate a single form field
     * 
     * @param {HTMLElement} input - The input element to validate
     * @param {Object} validationRule - The validation rule to apply
     * @param {boolean} showMessage - Whether to show notification message
     * @returns {boolean} Whether the field is valid
     */
    function validateField(input, validationRule, showMessage = false) {
        const value = input.value.trim();
        const isValid = value === '' || validationRule.pattern.test(value);
        
        // Add visual feedback
        if (isValid) {
            input.classList.remove('is-invalid');
            input.classList.add('is-valid');
        } else {
            input.classList.remove('is-valid');
            input.classList.add('is-invalid');
            
            // Show notification if requested
            if (showMessage && window.Notifications) {
                Notifications.warning(validationRule.message);
            }
            
            // Add/update validation message
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
     * Validate the entire form
     * 
     * @param {HTMLElement} form - The form to validate
     * @returns {boolean} Whether the form is valid
     */
    function validateForm(form) {
        let isValid = true;
        
        // Validate each field with a validation pattern
        form.querySelectorAll('input').forEach(input => {
            const fieldName = input.name;
            if (validationPatterns[fieldName]) {
                // If any field is invalid, the form is invalid
                if (!validateField(input, validationPatterns[fieldName], true)) {
                    isValid = false;
                }
            }
        });
        
        return isValid;
    }
    
    // Special validation for Greek address context
    const countryField = shippingForm.querySelector('[name="country"]');
    if (countryField) {
        countryField.addEventListener('change', function() {
            const countryValue = this.value.toLowerCase();
            const isGreece = ['ελλάδα', 'ελλαδα', 'greece', 'hellas'].includes(countryValue);
            
            // Apply stricter validation for Greek addresses
            if (isGreece) {
                const zipField = shippingForm.querySelector('[name="zip_code"]');
                const phoneField = shippingForm.querySelector('[name="phone"]');
                
                if (zipField) {
                    zipField.setAttribute('required', 'required');
                    zipField.placeholder = 'ΤΚ (5 ψηφία)';
                }
                
                if (phoneField) {
                    phoneField.setAttribute('required', 'required');
                    phoneField.placeholder = 'Τηλέφωνο (π.χ. 2101234567)';
                }
                
                // Notify user about Greek format requirements
                Notifications.info('Η διεύθυνση είναι στην Ελλάδα - απαιτούνται 5-ψήφιοι ΤΚ και έγκυρο ελληνικό τηλέφωνο');
            }
        });
    }
    
    // Domain verification function (as best as we can client-side)
    function checkDomainFormat(email) {
        const domain = email.split('@')[1];
        if (!domain) return false;
        
        // Check if domain has at least one dot and valid TLD
        const parts = domain.split('.');
        if (parts.length < 2) return false;
        
        // Check TLD is at least 2 characters
        const tld = parts[parts.length - 1];
        return tld.length >= 2;
    }
    
    // Email field special handling (domain check)
    const emailField = shippingForm.querySelector('[name="email"]');
    if (emailField) {
        emailField.addEventListener('blur', function() {
            const email = this.value.trim();
            
            // Only check if there's an email and it passes basic validation
            if (email && validationPatterns.email.pattern.test(email)) {
                // Check domain format as a best-effort client-side check
                if (!checkDomainFormat(email)) {
                    this.classList.remove('is-valid');
                    this.classList.add('is-invalid');
                    
                    Notifications.warning('Το domain του email δεν φαίνεται έγκυρο');
                    
                    // Add validation message
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