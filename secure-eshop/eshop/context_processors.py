"""
Context processors for the eshop application.

These processors add additional context variables to all templates.
"""

import json

def form_errors(request):
    """
    Context processor that adds form error data to template context.
    
    This allows us to pass form errors to JavaScript without inline scripts.
    
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
        
        # Field errors
        for field_name, errors in form.errors.items():
            if field_name != '__all__':  # Skip non-field errors
                form_errors_dict['field_errors'][field_name] = [str(error) for error in errors]
        
        # Non-field errors
        if form.non_field_errors():
            form_errors_dict['non_field_errors'] = [str(error) for error in form.non_field_errors()]
            
        # Convert to JSON string for data attribute
        context['form_errors_json'] = json.dumps(form_errors_dict)
    
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
            
        # Convert to JSON string for data attribute
        context['messages_json'] = json.dumps(messages_list)
    
    return context