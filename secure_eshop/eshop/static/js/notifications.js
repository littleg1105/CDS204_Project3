/**
 * Notifications.js - Ένα απλό σύστημα toast notifications
 * 
 * Αυτό το module παρέχει λειτουργίες για την εμφάνιση toast notifications
 * για σφάλματα επικύρωσης φορμών και άλλα μηνύματα.
 * 
 * Χαρακτηριστικά:
 * - Προστασία από XSS με escape HTML χαρακτήρων
 * - Διαφορετικοί τύποι notifications (success, error, warning, info)
 * - Αυτόματο κλείσιμο μετά από καθορισμένο χρόνο
 * - Χειροκίνητο κλείσιμο με κουμπί
 * - Animations για ομαλή εμφάνιση/εξαφάνιση
 */

// Τύποι toast notifications
// Constant: Χρησιμοποιείται για αποφυγή string literals και εύκολη τροποποίηση
const NOTIFICATION_TYPES = {
    SUCCESS: 'success',
    ERROR: 'error',
    WARNING: 'warning',
    INFO: 'info'
};

// Κύριο αντικείμενο notifications
// Module Pattern: Encapsulation όλων των μεθόδων σε ένα αντικείμενο
const Notifications = {
    /**
     * Ασφαλής escape των ειδικών χαρακτήρων HTML για αποτροπή XSS επιθέσεων
     * 
     * XSS Prevention: Μετατρέπει ειδικούς χαρακτήρες σε HTML entities
     * ώστε να μην εκτελεστούν ως κώδικας στον browser
     * 
     * @param {string} str - Το string προς escape
     * @returns {string} - Το escaped string
     */
    escapeHTML: function(str) {
        if (!str) return '';
        
        // Αντικατάσταση όλων των επικίνδυνων χαρακτήρων με τα HTML entities τους
        return String(str)
            .replace(/&/g, '&amp;')    // & -> &amp;
            .replace(/</g, '&lt;')     // < -> &lt;
            .replace(/>/g, '&gt;')     // > -> &gt;
            .replace(/"/g, '&quot;')   // " -> &quot;
            .replace(/'/g, '&#039;');  // ' -> &#039;
    },
    
    /**
     * Δημιουργία και εμφάνιση ενός toast notification
     * 
     * DOM Manipulation: Δημιουργεί και προσθέτει στοιχεία στο DOM με προγραμματιστικό τρόπο
     * 
     * @param {string} message - Το μήνυμα προς εμφάνιση
     * @param {string} type - Τύπος notification (success, error, warning, info)
     * @param {number} duration - Διάρκεια σε milliseconds (προεπιλογή: 5000)
     * @returns {HTMLElement} - Το δημιουργημένο toast element
     */
    showToast: function(message, type = NOTIFICATION_TYPES.INFO, duration = 5000) {
        // Δημιουργία container αν δεν υπάρχει
        // Lazy Initialization: Δημιουργία του container μόνο όταν χρειάζεται
        let container = document.getElementById('toast-container');
        if (!container) {
            container = document.createElement('div');
            container.id = 'toast-container';
            document.body.appendChild(container);
        }
        
        // Δημιουργία του toast element με ασφαλές περιεχόμενο
        const toast = document.createElement('div');
        toast.className = `toast toast-${this.escapeHTML(type)}`;
        
        // Δημιουργία div περιεχομένου
        const contentDiv = document.createElement('div');
        contentDiv.className = 'toast-content';
        
        // Δημιουργία span μηνύματος με ασφαλώς escaped περιεχόμενο
        // Security: Χρήση textContent αντί innerHTML για αυτόματο escaping
        const messageSpan = document.createElement('span');
        messageSpan.className = 'toast-message';
        messageSpan.textContent = message; // Χρησιμοποιεί textContent για αυτόματο escaping
        
        // Δημιουργία κουμπιού κλεισίματος
        const closeButton = document.createElement('button');
        closeButton.className = 'toast-close';
        closeButton.textContent = '×';
        
        // Προσθήκη στοιχείων χρησιμοποιώντας DOM methods αντί innerHTML
        // Security Best Practice: Αποφυγή innerHTML για μεγαλύτερη ασφάλεια
        contentDiv.appendChild(messageSpan);
        contentDiv.appendChild(closeButton);
        toast.appendChild(contentDiv);
        
        // Προσθήκη του toast στο container
        container.appendChild(toast);
        
        // Εμφάνιση του toast με animation
        // Animation Technique: Χρήση setTimeout για να επιτρέψει το browser να επεξεργαστεί 
        // το νέο element πριν εφαρμόσει το animation class
        setTimeout(() => {
            toast.classList.add('toast-visible');
        }, 10);
        
        // Ρύθμιση του κουμπιού κλεισίματος
        // Event Delegation: Προσθήκη event listener στο κουμπί κλεισίματος
        const closeButtonElement = toast.querySelector('.toast-close');
        closeButtonElement.addEventListener('click', () => {
            this.closeToast(toast);
        });
        
        // Αυτόματο κλείσιμο μετά από συγκεκριμένη διάρκεια
        // Async: Χρήση setTimeout για προγραμματισμένο κλείσιμο του notification
        const toastTimeout = setTimeout(() => {
            this.closeToast(toast);
        }, duration);
        
        // Αποθήκευση του timeout για καθαρισμό σε περίπτωση χειροκίνητου κλεισίματος
        // Memory Management: Αποφυγή memory leaks από orphaned timeouts
        toast.dataset.timeout = toastTimeout;
        
        return toast;
    },
    
    /**
     * Κλείσιμο ενός toast notification
     * 
     * Animation & Cleanup: Προσθέτει animation εξόδου και μετά αφαιρεί το element από το DOM
     * 
     * @param {HTMLElement} toast - Το toast element προς κλείσιμο
     */
    closeToast: function(toast) {
        // Καθαρισμός του timeout
        // Memory Management: Αποφυγή εκτέλεσης timeouts σε elements που δεν υπάρχουν πλέον
        if (toast.dataset.timeout) {
            clearTimeout(parseInt(toast.dataset.timeout));
        }
        
        // Προσθήκη animation κλεισίματος
        // CSS Transitions: Χρήση CSS classes για animations
        toast.classList.remove('toast-visible');
        toast.classList.add('toast-hidden');
        
        // Αφαίρεση από το DOM μετά το animation
        // Async: Περιμένει να ολοκληρωθεί το animation πριν αφαιρέσει το element
        setTimeout(() => {
            if (toast.parentElement) {
                toast.parentElement.removeChild(toast);
            }
            
            // Αφαίρεση του container αν είναι άδειο
            // DOM Cleanup: Διατηρεί το DOM καθαρό αφαιρώντας περιττά elements
            const container = document.getElementById('toast-container');
            if (container && container.children.length === 0) {
                document.body.removeChild(container);
            }
        }, 300); // 300ms είναι η διάρκεια του animation
    },
    
    /**
     * Εμφάνιση notification επιτυχίας
     * 
     * Utility Method: Convenience method για εύκολη δημιουργία notification επιτυχίας
     * 
     * @param {string} message - Το μήνυμα προς εμφάνιση
     * @param {number} duration - Διάρκεια σε milliseconds
     * @returns {HTMLElement} - Το δημιουργημένο toast element
     */
    success: function(message, duration) {
        return this.showToast(message, NOTIFICATION_TYPES.SUCCESS, duration);
    },
    
    /**
     * Εμφάνιση notification σφάλματος
     * 
     * Utility Method: Wrapper για εύκολη δημιουργία notification σφάλματος
     * 
     * @param {string} message - Το μήνυμα προς εμφάνιση
     * @param {number} duration - Διάρκεια σε milliseconds
     * @returns {HTMLElement} - Το δημιουργημένο toast element
     */
    error: function(message, duration) {
        return this.showToast(message, NOTIFICATION_TYPES.ERROR, duration);
    },
    
    /**
     * Εμφάνιση notification προειδοποίησης
     * 
     * Utility Method: Wrapper για εύκολη δημιουργία notification προειδοποίησης
     * 
     * @param {string} message - Το μήνυμα προς εμφάνιση
     * @param {number} duration - Διάρκεια σε milliseconds
     * @returns {HTMLElement} - Το δημιουργημένο toast element
     */
    warning: function(message, duration) {
        return this.showToast(message, NOTIFICATION_TYPES.WARNING, duration);
    },
    
    /**
     * Εμφάνιση notification πληροφοριών
     * 
     * Utility Method: Wrapper για εύκολη δημιουργία notification πληροφοριών
     * 
     * @param {string} message - Το μήνυμα προς εμφάνιση
     * @param {number} duration - Διάρκεια σε milliseconds
     * @returns {HTMLElement} - Το δημιουργημένο toast element
     */
    info: function(message, duration) {
        return this.showToast(message, NOTIFICATION_TYPES.INFO, duration);
    },
    
    /**
     * Εμφάνιση σφαλμάτων επικύρωσης φόρμας ως toast notifications
     * 
     * Form Error Handling: Μετατρέπει τα σφάλματα φόρμας σε user-friendly notifications
     * 
     * @param {Object} errors - Αντικείμενο που περιέχει σφάλματα πεδίων
     */
    showFormErrors: function(errors) {
        // Iteration: Διατρέχει όλα τα πεδία με σφάλματα στο αντικείμενο
        for (const field in errors) {
            // hasOwnProperty: Αποφεύγει την επεξεργασία κληρονομημένων ιδιοτήτων
            if (errors.hasOwnProperty(field)) {
                const errorMessages = errors[field];
                // Εμφάνιση κάθε μηνύματος σφάλματος
                // Array Iteration: Προσπελαύνει κάθε μήνυμα σφάλματος στον πίνακα
                errorMessages.forEach(message => {
                    this.error(`${field}: ${message}`);
                });
            }
        }
    }
};

// Εξαγωγή του αντικειμένου Notifications για χρήση σε άλλα scripts
// Global Access: Καθιστά το Notifications προσβάσιμο από άλλα scripts μέσω του window
window.Notifications = Notifications;