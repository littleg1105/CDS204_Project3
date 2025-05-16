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

document.addEventListener('DOMContentLoaded', function() {
    // Αναζήτηση για στοιχεία που περιέχουν σφάλματα φόρμας
    // Selector: Επιλέγει όλα τα elements με το data attribute 'data-form-errors'
    const errorContainers = document.querySelectorAll('[data-form-errors]');
    
    // Επεξεργασία κάθε container σφαλμάτων
    // Pattern: Iteration over NodeList για επεξεργασία πολλαπλών elements
    errorContainers.forEach(container => {
        try {
            // Ανάλυση των δεδομένων σφάλματος από το data attribute
            // JSON.parse: Μετατροπή του JSON string σε JavaScript object
            const errorsData = JSON.parse(container.dataset.formErrors);
            
            // Εμφάνιση σφαλμάτων πεδίων (field errors)
            if (errorsData.field_errors) {
                // Object.entries: Μετατροπή του object σε array από key-value pairs
                // για εύκολη επανάληψη
                Object.entries(errorsData.field_errors).forEach(([field, errors]) => {
                    errors.forEach(error => {
                        // Μορφοποίηση του ονόματος πεδίου για εμφάνιση
                        // (κεφαλαιοποίηση, αφαίρεση underscores)
                        // Τεχνική: Regular expressions για μορφοποίηση κειμένου
                        const fieldName = field
                            .replace(/_/g, ' ')               // Αντικατάσταση _ με κενό
                            .replace(/\b\w/g, l => l.toUpperCase()); // Κεφαλαιοποίηση πρώτου γράμματος κάθε λέξης
                        
                        // Ασφαλής εμφάνιση σφάλματος - τόσο το fieldName όσο και το error 
                        // έχουν ήδη sanitized από το Django
                        // Ασφάλεια: Χρήση concatenation για σωστό escaping του μηνύματος
                        Notifications.error(fieldName + ': ' + error, 7000); // 7000ms = 7 δευτερόλεπτα εμφάνισης
                    });
                });
            }
            
            // Εμφάνιση γενικών σφαλμάτων φόρμας (non-field errors)
            // Τα non-field errors αφορούν ολόκληρη τη φόρμα και όχι συγκεκριμένα πεδία
            if (errorsData.non_field_errors) {
                errorsData.non_field_errors.forEach(error => {
                    Notifications.error(error, 7000);
                });
            }
            
            // Μετά την εμφάνιση των σφαλμάτων, αφαίρεση του data attribute
            // για αποφυγή επανεμφάνισης στην ανανέωση της σελίδας
            // Βελτιστοποίηση: Αποτροπή διπλής εμφάνισης των ίδιων σφαλμάτων
            container.removeAttribute('data-form-errors');
        } catch (e) {
            // Χειρισμός σφαλμάτων ανάλυσης JSON
            // Debugging: Καταγραφή σφαλμάτων στην κονσόλα για διάγνωση προβλημάτων
            console.error('Error parsing form errors:', e);
        }
    });
    
    // Αναζήτηση για Django messages
    // Django messages: Σύστημα προσωρινών μηνυμάτων του Django για feedback στο χρήστη
    const messageContainers = document.querySelectorAll('[data-messages]');
    
    // Επεξεργασία κάθε container μηνυμάτων
    messageContainers.forEach(container => {
        try {
            // Ανάλυση των δεδομένων μηνυμάτων από το data attribute
            const messagesData = JSON.parse(container.dataset.messages);
            
            // Εμφάνιση κάθε μηνύματος με βάση το επίπεδο (level)
            // Django Message Levels: Κατηγοριοποίηση μηνυμάτων ανά τύπο
            messagesData.forEach(message => {
                switch(message.level) {
                    case 'error':
                        // Κρίσιμα σφάλματα - χρήση κόκκινου χρώματος
                        Notifications.error(message.text, 7000);
                        break;
                    case 'warning':
                        // Προειδοποιήσεις - χρήση πορτοκαλί/κίτρινου χρώματος
                        Notifications.warning(message.text, 7000);
                        break;
                    case 'success':
                        // Επιτυχείς ενέργειες - χρήση πράσινου χρώματος
                        Notifications.success(message.text, 7000);
                        break;
                    default:
                        // Πληροφοριακά μηνύματα (info) - χρήση μπλε χρώματος
                        // Default case: Χειρισμός περιπτώσεων που δεν καλύπτονται ρητά
                        Notifications.info(message.text, 7000);
                }
            });
            
            // Αφαίρεση του data attribute για αποφυγή επανεμφάνισης
            container.removeAttribute('data-messages');
        } catch (e) {
            // Χειρισμός σφαλμάτων ανάλυσης JSON
            console.error('Error parsing messages:', e);
        }
    });
});