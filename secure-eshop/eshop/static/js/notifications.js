/**
 * Notifications.js - A simple toast notification system
 * 
 * This module provides functionality to display toast notifications
 * for form validation errors and other messages.
 */

// Toast notification types
const NOTIFICATION_TYPES = {
    SUCCESS: 'success',
    ERROR: 'error',
    WARNING: 'warning',
    INFO: 'info'
};

// Main notification object
const Notifications = {
    /**
     * Create and show a toast notification
     * 
     * @param {string} message - The message to display
     * @param {string} type - Notification type (success, error, warning, info)
     * @param {number} duration - Duration in milliseconds (default: 5000)
     */
    showToast: function(message, type = NOTIFICATION_TYPES.INFO, duration = 5000) {
        // Create container if it doesn't exist
        let container = document.getElementById('toast-container');
        if (!container) {
            container = document.createElement('div');
            container.id = 'toast-container';
            document.body.appendChild(container);
        }
        
        // Create toast element
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.innerHTML = `
            <div class="toast-content">
                <span class="toast-message">${message}</span>
                <button class="toast-close">&times;</button>
            </div>
        `;
        
        // Add toast to container
        container.appendChild(toast);
        
        // Show the toast with animation
        setTimeout(() => {
            toast.classList.add('toast-visible');
        }, 10);
        
        // Set up close button
        const closeButton = toast.querySelector('.toast-close');
        closeButton.addEventListener('click', () => {
            this.closeToast(toast);
        });
        
        // Auto close after duration
        const toastTimeout = setTimeout(() => {
            this.closeToast(toast);
        }, duration);
        
        // Store timeout to clear if manually closed
        toast.dataset.timeout = toastTimeout;
        
        return toast;
    },
    
    /**
     * Close a toast notification
     * 
     * @param {HTMLElement} toast - The toast element to close
     */
    closeToast: function(toast) {
        // Clear the timeout
        if (toast.dataset.timeout) {
            clearTimeout(parseInt(toast.dataset.timeout));
        }
        
        // Add closing animation
        toast.classList.remove('toast-visible');
        toast.classList.add('toast-hidden');
        
        // Remove from DOM after animation
        setTimeout(() => {
            if (toast.parentElement) {
                toast.parentElement.removeChild(toast);
            }
            
            // Remove container if empty
            const container = document.getElementById('toast-container');
            if (container && container.children.length === 0) {
                document.body.removeChild(container);
            }
        }, 300);
    },
    
    /**
     * Show a success notification
     * 
     * @param {string} message - The message to display
     * @param {number} duration - Duration in milliseconds
     */
    success: function(message, duration) {
        return this.showToast(message, NOTIFICATION_TYPES.SUCCESS, duration);
    },
    
    /**
     * Show an error notification
     * 
     * @param {string} message - The message to display
     * @param {number} duration - Duration in milliseconds
     */
    error: function(message, duration) {
        return this.showToast(message, NOTIFICATION_TYPES.ERROR, duration);
    },
    
    /**
     * Show a warning notification
     * 
     * @param {string} message - The message to display
     * @param {number} duration - Duration in milliseconds
     */
    warning: function(message, duration) {
        return this.showToast(message, NOTIFICATION_TYPES.WARNING, duration);
    },
    
    /**
     * Show an info notification
     * 
     * @param {string} message - The message to display
     * @param {number} duration - Duration in milliseconds
     */
    info: function(message, duration) {
        return this.showToast(message, NOTIFICATION_TYPES.INFO, duration);
    },
    
    /**
     * Display form validation errors as toast notifications
     * 
     * @param {Object} errors - Object containing field errors
     */
    showFormErrors: function(errors) {
        for (const field in errors) {
            if (errors.hasOwnProperty(field)) {
                const errorMessages = errors[field];
                // Display each error message
                errorMessages.forEach(message => {
                    this.error(`${field}: ${message}`);
                });
            }
        }
    }
};

// Export the Notifications object for use in other scripts
window.Notifications = Notifications;