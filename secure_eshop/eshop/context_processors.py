"""
Context processors for the eshop application.
These processors add additional context variables to all templates.
"""
import json
import bleach
import html
from .utils.json_utils import dumps as json_dumps

# =============================================================================
# ΑΣΦΑΛΗΣ ΜΕΤΑΦΟΡΑ ΔΕΔΟΜΕΝΩΝ ΣΤΑ TEMPLATES
# =============================================================================
# Οι context processors προσθέτουν μεταβλητές στο context όλων των templates.
# Αυτός είναι ένας ΚΡΙΣΙΜΟΣ ΤΟΜΕΑΣ ΑΣΦΑΛΕΙΑΣ, καθώς αποτελεί γέφυρα μεταξύ
# του backend και του frontend. Αν τα δεδομένα δεν καθαριστούν κατάλληλα,
# υπάρχει κίνδυνος XSS επιθέσεων.

def form_errors(request):
    """
    Context processor that adds form error data to template context.
    This allows us to pass form errors to JavaScript without inline scripts.
    It also sanitizes all error messages to prevent XSS attacks.
    Returns:
    dict: A dictionary with form errors data in JSON format
    """
    context = {}
    
    # If there's a form in the context with errors
    if hasattr(request, 'form_errors'):
        form_errors_dict = {
            'field_errors': {},
            'non_field_errors': []
        }
        
        form = request.form_errors
        
        # Field errors - sanitize all values
        for field_name, errors in form.errors.items():
            if field_name != '__all__': # Skip non-field errors
                # Sanitize the field name (though Django field names should already be safe)
                safe_field_name = bleach.clean(field_name)
                
                # Create a list of sanitized error messages
                form_errors_dict['field_errors'][safe_field_name] = []
                
                for error in errors:
                    # =============================================================================
                    # ΔΙΠΛΟΣ ΚΑΘΑΡΙΣΜΟΣ - ΠΡΩΤΗ ΓΡΑΜΜΗ ΑΜΥΝΑΣ ΚΑΤΑ XSS
                    # =============================================================================
                    # Χρησιμοποιούμε δύο διαφορετικές μεθόδους καθαρισμού:
                    # 1. bleach.clean() - Αφαιρεί επικίνδυνο HTML και JavaScript
                    # 2. html.escape() - Μετατρέπει ειδικούς χαρακτήρες σε HTML entities
                    # 
                    # Αυτή η τεχνική "defense in depth" προσφέρει προστασία ακόμα κι αν
                    # το ένα στρώμα ασφαλείας παρακαμφθεί.
                    safe_error = html.escape(bleach.clean(str(error)))
                    form_errors_dict['field_errors'][safe_field_name].append(safe_error)
        
        # Non-field errors - sanitize all values
        if form.non_field_errors():
            for error in form.non_field_errors():
                # Double sanitization for extra security
                safe_error = html.escape(bleach.clean(str(error)))
                form_errors_dict['non_field_errors'].append(safe_error)
        
        # =============================================================================
        # ΑΣΦΑΛΗΣ ΜΕΤΑΤΡΟΠΗ ΣΕ JSON
        # =============================================================================
        # Χρησιμοποιούμε προσαρμοσμένη συνάρτηση json_dumps που:
        # 1. Χειρίζεται με ασφάλεια τύπους όπως UUID, datetime κλπ
        # 2. Αποφεύγει την έκθεση ευαίσθητων δεδομένων κατά την σειριοποίηση
        # 3. Έχει προστασία από αναδρομικές δομές που θα μπορούσαν να 
        #    προκαλέσουν DoS επιθέσεις
        context['form_errors_json'] = json_dumps(form_errors_dict)
        
    return context

def django_messages(request):
    """
    Context processor that adds Django messages to template context.
    This allows us to pass Django messages to JavaScript without inline scripts.
    Returns:
    dict: A dictionary with messages data in JSON format
    """
    context = {}
    
    # Process Django messages
    if hasattr(request, '_messages') and request._messages:
        messages_list = []
        
        for message in request._messages:
            # =============================================================================
            # ΑΣΦΑΛΗΣ ΔΙΑΧΕΙΡΙΣΗ ΜΗΝΥΜΑΤΩΝ
            # =============================================================================
            # Τα μηνύματα Django δεν περνούν από πρόσθετο καθαρισμό εδώ καθώς:
            # 1. Προέρχονται από το backend (έμπιστη πηγή)
            # 2. Στο template θα περάσουν αυτόματα από το HTML escaping του Django
            # 3. Αν περιέχουν δεδομένα χρήστη, αυτά πρέπει να έχουν καθαριστεί 
            #    πριν την αποθήκευσή τους στο σύστημα μηνυμάτων
            messages_list.append({
                'level': message.level_tag,
                'text': str(message)
            })
        
        # Convert to JSON string for data attribute using custom encoder that handles UUIDs
        context['messages_json'] = json_dumps(messages_list)
        
    return context