/**
 * form-error-handler.js
 * 
 * This script converts Django form errors to toast notifications.
 * It uses a data attribute approach to pass error data without inline scripts,
 * maintaining CSP compliance.
 */

document.addEventListener('DOMContentLoaded', function() {
    // Look for elements with form errors
    const errorContainers = document.querySelectorAll('[data-form-errors]');
    errorContainers.forEach(container => {
        try {
            // Parse the error data from the data attribute
            const errorsData = JSON.parse(container.dataset.formErrors);
            
            // Display field errors
            if (errorsData.field_errors) {
                Object.entries(errorsData.field_errors).forEach(([field, errors]) => {
                    errors.forEach(error => {
                        // Format field name for display (capitalize, remove underscores)
                        const fieldName = field
                            .replace(/_/g, ' ')
                            .replace(/\b\w/g, l => l.toUpperCase());
                        
                        // Use safe error display - both fieldName and error are already sanitized by Django
                        // We use concatenation here so the message is properly escaped
                        Notifications.error(fieldName + ': ' + error, 7000);
                    });
                });
            }
            
            // Display non-field errors
            if (errorsData.non_field_errors) {
                errorsData.non_field_errors.forEach(error => {
                    Notifications.error(error, 7000);
                });
            }
            
            // After displaying errors, remove the data attribute to prevent showing again on page refresh
            container.removeAttribute('data-form-errors');
        } catch (e) {
            console.error('Error parsing form errors:', e);
        }
    });

    // Look for Django messages
    const messageContainers = document.querySelectorAll('[data-messages]');
    messageContainers.forEach(container => {
        try {
            // Parse the messages data from the data attribute
            const messagesData = JSON.parse(container.dataset.messages);
            
            messagesData.forEach(message => {
                switch(message.level) {
                    case 'error':
                        Notifications.error(message.text, 7000);
                        break;
                    case 'warning':
                        Notifications.warning(message.text, 7000);
                        break;
                    case 'success':
                        Notifications.success(message.text, 7000);
                        break;
                    default:
                        Notifications.info(message.text, 7000);
                }
            });
            
            // Remove the data attribute to prevent showing again on page refresh
            container.removeAttribute('data-messages');
        } catch (e) {
            console.error('Error parsing messages:', e);
        }
    });
});