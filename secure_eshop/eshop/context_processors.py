"""
Context processors for the eshop application.

These processors add additional context variables to all templates.
"""

import json
import bleach
import html
from .utils.json_utils import dumps as json_dumps

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
            if field_name != '__all__':  # Skip non-field errors
                # Sanitize the field name (though Django field names should already be safe)
                safe_field_name = bleach.clean(field_name)
                
                # Create a list of sanitized error messages
                form_errors_dict['field_errors'][safe_field_name] = []
                
                for error in errors:
                    # Double sanitization for extra security: bleach + html escape
                    safe_error = html.escape(bleach.clean(str(error)))
                    form_errors_dict['field_errors'][safe_field_name].append(safe_error)
        
        # Non-field errors - sanitize all values
        if form.non_field_errors():
            for error in form.non_field_errors():
                # Double sanitization for extra security
                safe_error = html.escape(bleach.clean(str(error)))
                form_errors_dict['non_field_errors'].append(safe_error)
            
        # Convert to JSON string for data attribute using custom encoder that handles UUIDs
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
            messages_list.append({
                'level': message.level_tag,
                'text': str(message)
            })
            
        # Convert to JSON string for data attribute using custom encoder that handles UUIDs
        context['messages_json'] = json_dumps(messages_list)
    
    return context