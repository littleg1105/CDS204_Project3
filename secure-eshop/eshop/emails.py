from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags
import logging

logger = logging.getLogger('orders')

def send_order_confirmation(order, user_email):
    """
    Send order confirmation email to the customer
    
    Args:
        order: The Order instance
        user_email: Email address of the customer
    """
    try:
        # Get order items and shipping address
        order_items = order.items.all()
        shipping_address = order.shipping_address
        
        # Context for email template
        context = {
            'order': order,
            'order_items': order_items,
            'shipping_address': shipping_address,
        }
        
        # Render HTML and text content
        html_content = render_to_string('emails/order_confirmation.html', context)
        text_content = render_to_string('emails/order_confirmation.txt', context)
        
        # Create email
        subject = f'Επιβεβαίωση Παραγγελίας #{order.id}'
        from_email = settings.DEFAULT_FROM_EMAIL
        
        # Create message with both HTML and text versions
        msg = EmailMultiAlternatives(subject, text_content, from_email, [user_email])
        msg.attach_alternative(html_content, "text/html")
        
        # Send the email
        msg.send()
        
        logger.info(f"Order confirmation email sent to {user_email} for order #{order.id}")
        return True
    
    except Exception as e:
        logger.error(f"Failed to send order confirmation email: {str(e)}")
        return False


def send_order_notification_to_admin(order):
    """
    Send notification about new order to administrator
    
    Args:
        order: The Order instance
    """
    try:
        # Get order items and shipping address
        order_items = order.items.all()
        shipping_address = order.shipping_address
        
        # Build email message
        subject = f'Νέα παραγγελία #{order.id}'
        from_email = settings.DEFAULT_FROM_EMAIL
        to_email = settings.ADMIN_EMAIL
        
        # Order details
        order_details = "\n".join([
            f"{item.quantity} x {item.product.name} ({item.price} €) = {item.get_total_price()} €"
            for item in order_items
        ])
        
        # Email message
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
        
        if shipping_address.phone:
            message += f"\nΤηλέφωνο: {shipping_address.phone}"
        
        if shipping_address.email:
            message += f"\nEmail: {shipping_address.email}"
        
        # Send email
        EmailMultiAlternatives(
            subject=subject,
            body=message,
            from_email=from_email,
            to=[to_email]
        ).send()
        
        logger.info(f"Order notification email sent to admin for order #{order.id}")
        return True
    
    except Exception as e:
        logger.error(f"Failed to send order notification email to admin: {str(e)}")
        return False