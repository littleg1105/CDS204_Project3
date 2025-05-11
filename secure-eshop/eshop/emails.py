# ============================================================================
# IMPORTS - Εισαγωγή απαραίτητων modules
# ============================================================================

# Django settings για πρόσβαση σε email configuration
from django.conf import settings
# Χρησιμότητα: Παρέχει πρόσβαση σε EMAIL_HOST, DEFAULT_FROM_EMAIL κλπ

# EmailMultiAlternatives για αποστολή email με HTML και text versions
from django.core.mail import EmailMultiAlternatives
# Χρησιμότητα: Επιτρέπει αποστολή email με multiple content types (HTML + plain text)
# Best practice: Πάντα στέλνουμε και text version για compatibility

# Template rendering functions
from django.template.loader import render_to_string
# Χρησιμότητα: Renders Django templates σε strings για email content

# HTML utilities
from django.utils.html import strip_tags
# Χρησιμότητα: Αφαιρεί HTML tags για δημιουργία plain text version

# Logging για monitoring και debugging
import logging
# Χρησιμότητα: Καταγραφή επιτυχημένων/αποτυχημένων αποστολών

# Δημιουργία logger instance για orders
logger = logging.getLogger('orders')
# Χρησιμότητα: Ξεχωριστός logger για order-related events


# ============================================================================
# SEND ORDER CONFIRMATION TO CUSTOMER
# Αποστολή email επιβεβαίωσης παραγγελίας στον πελάτη
# ============================================================================

def send_order_confirmation(order, user_email):
    """
    Send order confirmation email to the customer.
    
    Args:
        order: The Order instance
        user_email: Email address of the customer
        
    Returns:
        bool: True if email sent successfully, False otherwise
        
    Features:
    - HTML και plain text versions για compatibility
    - Template-based content για εύκολη maintenance
    - Error handling με logging
    - Προσαρμοσμένο subject με order ID
    """
    try:
        # Λήψη σχετικών δεδομένων για το email
        # Χρησιμότητα: Προετοιμασία context για templates
        order_items = order.items.all()  # Όλα τα προϊόντα της παραγγελίας
        shipping_address = order.shipping_address  # Διεύθυνση αποστολής
        
        # Context dictionary για template rendering
        # Χρησιμότητα: Παρέχει δεδομένα στα email templates
        context = {
            'order': order,
            'order_items': order_items,
            'shipping_address': shipping_address,
        }
        
        # Render HTML template
        # Χρησιμότητα: Δημιουργία όμορφου HTML email με styling
        html_content = render_to_string('emails/order_confirmation.html', context)
        
        # Render plain text template
        # Χρησιμότητα: Fallback για email clients που δεν υποστηρίζουν HTML
        text_content = render_to_string('emails/order_confirmation.txt', context)
        
        # Email metadata
        subject = f'Επιβεβαίωση Παραγγελίας #{order.id}'  # Dynamic subject με order ID
        from_email = settings.DEFAULT_FROM_EMAIL  # Από settings για flexibility
        
        # Δημιουργία email message με multiple alternatives
        # Χρησιμότητα: Υποστήριξη και HTML και plain text
        msg = EmailMultiAlternatives(
            subject=subject,
            body=text_content,      # Primary content (plain text)
            from_email=from_email,
            to=[user_email]         # List format for multiple recipients support
        )
        
        # Προσθήκη HTML version ως alternative
        # Χρησιμότητα: Email clients θα προτιμήσουν HTML αν το υποστηρίζουν
        msg.attach_alternative(html_content, "text/html")
        
        # Αποστολή email
        msg.send()
        
        # Success logging
        # Χρησιμότητα: Audit trail, monitoring, debugging
        logger.info(f"Order confirmation email sent to {user_email} for order #{order.id}")
        return True
        
    except Exception as e:
        # Error handling και logging
        # Χρησιμότητα: 
        # - Αποφυγή crash της εφαρμογής
        # - Καταγραφή προβλημάτων για debugging
        # - Graceful failure με return False
        logger.error(f"Failed to send order confirmation email: {str(e)}")
        return False


# ============================================================================
# SEND ORDER NOTIFICATION TO ADMIN
# Ειδοποίηση διαχειριστή για νέα παραγγελία
# ============================================================================

def send_order_notification_to_admin(order):
    """
    Send notification about new order to administrator.
    
    Args:
        order: The Order instance
        
    Returns:
        bool: True if email sent successfully, False otherwise
        
    Features:
    - Plain text format για simplicity
    - Detailed order information
    - Customer contact details
    - Error handling
    
    Security considerations:
    - Sends to configured admin email only
    - No sensitive customer data exposed
    """
    try:
        # Λήψη δεδομένων παραγγελίας
        order_items = order.items.all()
        shipping_address = order.shipping_address
        
        # Email metadata
        subject = f'Νέα παραγγελία #{order.id}'
        from_email = settings.DEFAULT_FROM_EMAIL
        to_email = settings.ADMIN_EMAIL  # Από settings για security
        
        # Δημιουργία λίστας προϊόντων με formatting
        # Χρησιμότητα: Clear, readable format για τον admin
        order_details = "\n".join([
            f"{item.quantity} x {item.product.name} ({item.price} €) = {item.get_total_price()} €"
            for item in order_items
        ])
        
        # Κατασκευή email body με multiline string
        # Χρησιμότητα: Readable format, όλες οι απαραίτητες πληροφορίες
        message = f"""
Νέα παραγγελία #{order.id}

Πελάτης: {order.user.username}

Προϊόντα:
{order_details}

Συνολικό ποσό: {order.total_price} €

Διεύθυνση αποστολής:
{shipping_address.name}
{shipping_address.address}
{shipping_address.zip_code} {shipping_address.city}
{shipping_address.country}
"""
        
        # Προσθήκη optional fields αν υπάρχουν
        # Χρησιμότητα: Μόνο relevant πληροφορίες, αποφυγή empty fields
        if shipping_address.phone:
            message += f"\nΤηλέφωνο: {shipping_address.phone}"
            
        if shipping_address.email:
            message += f"\nEmail: {shipping_address.email}"
        
        # Αποστολή email
        # Χρησιμότητα: Απλή text-only αποστολή για admin notification
        EmailMultiAlternatives(
            subject=subject,
            body=message,
            from_email=from_email,
            to=[to_email]  # List format
        ).send()
        
        # Success logging
        logger.info(f"Order notification email sent to admin for order #{order.id}")
        return True
        
    except Exception as e:
        # Error handling
        logger.error(f"Failed to send order notification email to admin: {str(e)}")
        return False
    
# ============================================================================
# Ανάλυση Χρησιμότητας ανά Block
# 1. Imports Section

# settings: Κεντρική διαχείριση email configuration
# EmailMultiAlternatives: Modern approach για multipart emails
# render_to_string: Template-based email content
# logging: Monitoring και debugging capabilities

# 2. Order Confirmation Function
# Sophisticated email για τον πελάτη:
# Template-based Content

# Maintainability: Εύκολη αλλαγή του design χωρίς code changes
# Consistency: Ίδιο branding με το website
# Localization ready: Templates μπορούν να μεταφραστούν

# Multi-format Support

# HTML version: Rich formatting, branding, styling
# Plain text fallback: Universal compatibility
# Best practice: Πάντα και τα δύο formats

# Error Handling

# Graceful failure: Δεν σταματά η διαδικασία παραγγελίας
# Logging: Tracking για troubleshooting
# Return value: Επιτρέπει handling στο calling code

# 3. Admin Notification Function
# Απλό, functional email για τον admin:
# Plain Text Format

# Simplicity: Γρήγορο reading, no distractions
# Reliability: Works everywhere
# Focus on content: Μόνο τα απαραίτητα data

# Detailed Information

# Complete order data: Όλα τα προϊόντα με τιμές
# Customer info: Contact details για επικοινωνία
# Shipping details: Πλήρης διεύθυνση

# Conditional Fields

# Clean output: Μόνο populated fields εμφανίζονται
# No empty lines: Professional appearance
# Flexibility: Works με optional fields

# Security Considerations

# Email Configuration: Από settings, όχι hardcoded
# No Sensitive Data: Μόνο order details, όχι payment info
# Admin Email: Configured centrally, not in code
# Error Messages: Δεν expose internal details

# Best Practices Implemented
# 1. Template Usage

# Separation of concerns (logic vs presentation)
# Easy maintenance και updates
# Consistent branding

# 2. Multi-format Emails

# HTML για rich experience
# Plain text για compatibility
# Both versions από templates

# 3. Error Handling

# Try-except blocks
# Logging για monitoring
# Return values για caller feedback

# 4. Logging Strategy

# Different log levels (info/error)
# Descriptive messages
# Order IDs για tracking