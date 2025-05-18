/**
 * form-error-handler.js
 *
 * Αυτό το script μετατρέπει τα Django form errors σε toast notifications.
 * Χρησιμοποιεί data attributes για τη μεταφορά δεδομένων σφάλματος χωρίς inline scripts,
 * διατηρώντας τη συμβατότητα με το Content Security Policy (CSP).
 * 
 * Λειτουργικότητες:
 * - Επεξεργασία σφαλμάτων φόρμας (field errors και non-field errors)
 * - Επεξεργασία μηνυμάτων Django (error, warning, success, info)
 * - Μορφοποίηση και εμφάνιση σφαλμάτων ως toast notifications
 */

// Helper function για μορφοποίηση ονομάτων πεδίων
function formatFieldName(field) {
    // Αντικατάσταση _ με κενό και κεφαλαιοποίηση πρώτου γράμματος κάθε λέξης
    return field
        .replace(/_/g, ' ')
        .replace(/\b\w/g, l => l.toUpperCase());
}

// Helper function για εμφάνιση field errors
function displayFieldError(field, error) {
    const fieldName = formatFieldName(field);
    // Ασφαλής εμφάνιση σφάλματος - τόσο το fieldName όσο και το error 
    // έχουν ήδη sanitized από το Django
    Notifications.error(fieldName + ': ' + error, 7000); // 7000ms = 7 δευτερόλεπτα εμφάνισης
}

// Helper function για επεξεργασία field errors
function processFieldErrors(fieldErrors) {
    // Object.entries: Μετατροπή του object σε array από key-value pairs
    Object.entries(fieldErrors).forEach(([field, errors]) => {
        errors.forEach(error => displayFieldError(field, error));
    });
}

// Helper function για επεξεργασία non-field errors
function processNonFieldErrors(nonFieldErrors) {
    nonFieldErrors.forEach(error => {
        Notifications.error(error, 7000);
    });
}

// Helper function για εμφάνιση μηνύματος με βάση το level
function displayMessageByLevel(message) {
    const duration = 7000; // 7 δευτερόλεπτα
    
    switch(message.level) {
        case 'error':
            // Κρίσιμα σφάλματα - χρήση κόκκινου χρώματος
            Notifications.error(message.text, duration);
            break;
        case 'warning':
            // Προειδοποιήσεις - χρήση πορτοκαλί/κίτρινου χρώματος
            Notifications.warning(message.text, duration);
            break;
        case 'success':
            // Επιτυχείς ενέργειες - χρήση πράσινου χρώματος
            Notifications.success(message.text, duration);
            break;
        default:
            // Πληροφοριακά μηνύματα (info) - χρήση μπλε χρώματος
            Notifications.info(message.text, duration);
    }
}

// Helper function για επεξεργασία Django messages
function processDjangoMessages(messagesData) {
    messagesData.forEach(displayMessageByLevel);
}

// Main function για επεξεργασία container σφαλμάτων
function processErrorContainer(container) {
    try {
        // Ανάλυση των δεδομένων σφάλματος από το data attribute
        const errorsData = JSON.parse(container.dataset.formErrors);
        
        // Εμφάνιση σφαλμάτων πεδίων (field errors)
        if (errorsData.field_errors) {
            processFieldErrors(errorsData.field_errors);
        }
        
        // Εμφάνιση γενικών σφαλμάτων φόρμας (non-field errors)
        if (errorsData.non_field_errors) {
            processNonFieldErrors(errorsData.non_field_errors);
        }
        
        // Αφαίρεση του data attribute για αποφυγή επανεμφάνισης
        container.removeAttribute('data-form-errors');
    } catch (e) {
        // Χειρισμός σφαλμάτων ανάλυσης JSON
        console.error('Error parsing form errors:', e);
    }
}

// Main function για επεξεργασία container μηνυμάτων
function processMessageContainer(container) {
    try {
        // Ανάλυση των δεδομένων μηνυμάτων από το data attribute
        const messagesData = JSON.parse(container.dataset.messages);
        
        // Εμφάνιση κάθε μηνύματος με βάση το επίπεδο (level)
        processDjangoMessages(messagesData);
        
        // Αφαίρεση του data attribute για αποφυγή επανεμφάνισης
        container.removeAttribute('data-messages');
    } catch (e) {
        // Χειρισμός σφαλμάτων ανάλυσης JSON
        console.error('Error parsing messages:', e);
    }
}

// Αρχικοποίηση όταν φορτωθεί το DOM
function initializeFormErrorHandler() {
    // Αναζήτηση για στοιχεία που περιέχουν σφάλματα φόρμας
    const errorContainers = document.querySelectorAll('[data-form-errors]');
    errorContainers.forEach(processErrorContainer);
    
    // Αναζήτηση για Django messages
    const messageContainers = document.querySelectorAll('[data-messages]');
    messageContainers.forEach(processMessageContainer);
}

// Εκκίνηση όταν φορτωθεί το DOM
document.addEventListener('DOMContentLoaded', initializeFormErrorHandler);