"""
Custom middleware χρησιμότητας και ασφάλειας για το Django eshop project.

Αυτό το module περιέχει custom middleware components που ενισχύουν την 
ασφάλεια και λειτουργικότητα της εφαρμογής. 

ΣΗΜΑΝΤΙΚΟ: Πολλά από τα security features έχουν απενεργοποιηθεί στο 
vulnerable branch για εκπαιδευτικούς σκοπούς penetration testing.
"""

import logging
import hashlib
import time
import functools
from django.conf import settings
from django.http import HttpResponse
from django.core.cache import cache
from django.utils.deprecation import MiddlewareMixin
from django.urls import resolve
from django.shortcuts import redirect
from django.contrib.auth.views import redirect_to_login
# VULNERABILITY: OTP imports disabled
# from django_otp import match_token
# from django_otp.decorators import otp_required

# Λήψη logger για καταγραφή security events
logger = logging.getLogger('security')

# ============================================================================
# SECURITY HEADERS MIDDLEWARE
# Χρησιμότητα: Προσθήκη security headers σε κάθε HTTP response
# ============================================================================

class SecurityHeadersMiddleware(MiddlewareMixin):
    """
    Middleware που προσθέτει σημαντικά security headers σε κάθε απάντηση HTTP.
    
    Αυτά τα headers προστατεύουν από διάφορες web vulnerabilities όπως:
    - XSS attacks (X-Content-Type-Options, X-XSS-Protection)
    - Clickjacking (X-Frame-Options)
    - Information disclosure (Referrer-Policy, Permissions-Policy)
    - Protocol downgrade attacks (HSTS)
    
    VULNERABILITY: Απενεργοποιημένο στο vulnerable branch
    """
    
    def process_response(self, request, response):
        """
        Προσθέτει security headers σε κάθε HTTP response.
        
        Args:
            request: Το Django request object
            response: Το Django response object που θα τροποποιηθεί
            
        Returns:
            HttpResponse: Το τροποποιημένο response με τα security headers
        """
        # Prevent MIME type sniffing
        # Αναγκάζει τον browser να σεβαστεί το declared content type
        response['X-Content-Type-Options'] = 'nosniff'
        
        # Enable browser XSS filter
        # Ενεργοποιεί το built-in XSS filter των browsers
        response['X-XSS-Protection'] = '1; mode=block'
        
        # Clickjacking protection - επιτρέπει frames μόνο από το ίδιο origin
        # Εναλλακτικά: DENY για πλήρη απαγόρευση frames
        response['X-Frame-Options'] = 'SAMEORIGIN'
        
        # Control information sent in Referer header
        # same-origin: Στέλνει full URL μόνο σε same-origin requests
        response['Referrer-Policy'] = 'same-origin'
        
        # Feature Policy / Permissions Policy
        # Περιορίζει ποια browser features μπορεί να χρησιμοποιήσει η σελίδα
        response['Permissions-Policy'] = (
            'geolocation=(), '    # Απαγόρευση πρόσβασης σε τοποθεσία
            'microphone=(), '     # Απαγόρευση πρόσβασης σε μικρόφωνο
            'camera=(), '         # Απαγόρευση πρόσβασης σε κάμερα
            'payment=(self), '    # Πληρωμές μόνο από το ίδιο origin
            'usb=()'             # Απαγόρευση πρόσβασης σε USB devices
        )
        
        # HTTP Strict Transport Security (HSTS)
        # Αναγκάζει HTTPS connections για τον καθορισμένο χρόνο
        if request.is_secure():  # Μόνο σε HTTPS connections
            response['Strict-Transport-Security'] = (
                'max-age=31536000; '      # 1 χρόνος
                'includeSubDomains; '     # Και για subdomains
                'preload'                 # Συμπερίληψη σε browser preload lists
            )
            
        return response


# ============================================================================
# OTP LOCKOUT MIDDLEWARE  
# Χρησιμότητα: Προστασία από brute force attacks στο OTP
# ============================================================================

class OTPLockoutMiddleware(MiddlewareMixin):
    """
    Middleware για προστασία από brute force attacks στο OTP verification.
    
    Παρακολουθεί αποτυχημένες προσπάθειες OTP και κλειδώνει προσωρινά
    τον λογαριασμό μετά από πολλές αποτυχίες.
    
    VULNERABILITY: Απενεργοποιημένο στο vulnerable branch
    """
    
    MAX_ATTEMPTS = 5        # Μέγιστες προσπάθειες
    LOCKOUT_DURATION = 300  # Διάρκεια κλειδώματος σε δευτερόλεπτα (5 λεπτά)
    
    def process_request(self, request):
        """
        Ελέγχει αν ο χρήστης είναι κλειδωμένος λόγω πολλών αποτυχημένων OTP.
        
        Args:
            request: Το Django request object
            
        Returns:
            HttpResponse ή None: Response με μήνυμα lockout ή None για συνέχεια
        """
        # Μόνο για authenticated users που δεν έχουν περάσει OTP
        if not request.user.is_authenticated:
            return None
            
        # Έλεγχος αν ο χρήστης είναι σε OTP lockout
        lockout_key = f'otp_lockout:{request.user.pk}'
        lockout_data = cache.get(lockout_key)
        
        if lockout_data and lockout_data.get('locked'):
            remaining_time = int(lockout_data['locked_until'] - time.time())
            if remaining_time > 0:
                logger.warning(
                    f"OTP lockout access attempt - User: {request.user.username}, "
                    f"Remaining time: {remaining_time}s"
                )
                return HttpResponse(
                    f"Πολλές αποτυχημένες προσπάθειες. "
                    f"Δοκιμάστε ξανά σε {remaining_time} δευτερόλεπτα.",
                    status=429
                )
            else:
                # Το lockout έχει λήξει
                cache.delete(lockout_key)
                
        return None


# ============================================================================
# ΥΠΟΣΤΗΡΙΚΤΙΚΕΣ ΣΥΝΑΡΤΗΣΕΙΣ ΓΙΑ RATE LIMITING (ΑΠΕΝΕΡΓΟΠΟΙΗΜΕΝΕΣ)
# ============================================================================

# VULNERABILITY: Όλες οι rate limiting functions είναι απενεργοποιημένες

def _parse_rate_limit(rate):
    """Parse rate limit string like '10/m' into count and seconds."""
    count, period = rate.split('/')
    count = int(count)
    
    # Convert period to seconds
    period_map = {
        's': 1,
        'm': 60,
        'h': 3600,
        'd': 86400
    }
    period_seconds = period_map.get(period, 60)
    
    return count, period_seconds


def _get_rate_limit_key_value(request, key):
    """Get the key value for rate limiting based on the key type."""
    if key == 'ip':
        # Get client IP, considering X-Forwarded-For for proxies
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', '')
        return hashlib.sha256(ip.encode()).hexdigest()
    elif key == 'user':
        if request.user.is_authenticated:
            return str(request.user.pk)
        else:
            return 'anonymous'
    else:
        return 'unknown'


def _check_and_update_rate_limit(cache_key, count_limit, period_seconds):
    """Check and update rate limit counter."""
    current_count = cache.get(cache_key, 0)
    
    if current_count >= count_limit:
        return True  # Rate limit exceeded
    
    # Increment counter
    try:
        cache.incr(cache_key)
    except ValueError:
        # Key doesn't exist, set it
        cache.set(cache_key, 1, period_seconds)
    
    return False


def _handle_rate_limit_exceeded(request, block):
    """Handle rate limit exceeded."""
    if block:
        logger.warning(
            f"Rate limit exceeded - IP: {request.META.get('REMOTE_ADDR')}, "
            f"Path: {request.path}"
        )
        return HttpResponse(
            "Too many requests. Please try again later.",
            status=429
        )
    return None


# VULNERABILITY: Custom rate limiting disabled
# def custom_ratelimit(key='ip', rate='10/m', method=None, block=True):
#     """
#     Προσαρμοσμένος decorator περιορισμού ρυθμού χρησιμοποιώντας την ενσωματωμένη cache του Django.
#     
#     Επιτρέπει τον έλεγχο του αριθμού των αιτημάτων που μπορεί να κάνει ένας χρήστης ή μια IP
#     σε συγκεκριμένο χρονικό διάστημα, αποτρέποντας επιθέσεις brute force και DoS.
#     
#     Args:
#         key: 'ip' ή 'user' για καθορισμό του κλειδιού περιορισμού ρυθμού
#         rate: μορφή όπως '10/m' για 10 αιτήματα ανά λεπτό
#         method: λίστα μεθόδων για εφαρμογή περιορισμού ρυθμού (π.χ., ['POST'])
#         block: αν θα μπλοκάρει το αίτημα όταν ξεπεραστεί το όριο ρυθμού
#         
#     Returns:
#         Συνάρτηση decorator που εφαρμόζει περιορισμό ρυθμού
#     """
#     def decorator(view_func):
#         @functools.wraps(view_func)  # Διατηρεί τα μεταδεδομένα της αρχικής συνάρτησης
#         def wrapped_view(request, *args, **kwargs):
#             # Έλεγχος αν η μέθοδος πρέπει να περιοριστεί
#             if method and request.method not in method:
#                 return view_func(request, *args, **kwargs)
#             
#             # Ανάλυση ορίου ρυθμού
#             count_limit, period_seconds = _parse_rate_limit(rate)
#             
#             # Λήψη της τιμής κλειδιού
#             key_value = _get_rate_limit_key_value(request, key)
#             
#             # Δημιουργία κλειδιού cache
#             cache_key = f"ratelimit:{key}:{key_value}:{view_func.__name__}"
#             
#             # Έλεγχος και ενημέρωση του ορίου ρυθμού
#             if _check_and_update_rate_limit(cache_key, count_limit, period_seconds):
#                 # Χειρισμός υπέρβασης ορίου
#                 response = _handle_rate_limit_exceeded(request, block)
#                 if response:
#                     return response
#             
#             # Εκτέλεση της αρχικής συνάρτησης view
#             return view_func(request, *args, **kwargs)
#         
#         return wrapped_view
#     return decorator

# VULNERABILITY: Form rate limiting middleware disabled
# class FormRateLimitMiddleware(MiddlewareMixin):
#     """
#     Middleware για περιορισμό ρυθμού υποβολών φόρμας.
#     
#     Αυτό το middleware αποτρέπει επιθέσεις brute force περιορίζοντας το ρυθμό με τον οποίο
#     οι χρήστες μπορούν να υποβάλλουν φόρμες, με βάση τη διεύθυνση IP τους.
#     
#     Εστιάζει στην προστασία κρίσιμων endpoints όπως σελίδες σύνδεσης και πληρωμών.
#     """
#     
#     # Ρύθμιση περιορισμού ρυθμού
#     RATE_LIMIT = 10     # Μέγιστες υποβολές
#     TIME_PERIOD = 60    # Χρονική περίοδος σε δευτερόλεπτα
#     FORM_PATHS = [      # Διαδρομές για περιορισμό ρυθμού
#         '/login/',
#         '/payment/',
#     ]
#     
#     def process_request(self, request):
#         """
#         Επεξεργασία εισερχόμενων αιτημάτων για περιορισμό υποβολών φόρμας.
#         
#         Args:
#             request: Το αντικείμενο αιτήματος Django
#             
#         Returns:
#             None ή HttpResponse με κατάσταση 429 αν ξεπεραστεί το όριο ρυθμού
#         """
#         # Μόνο εφαρμογή σε αιτήματα POST σε διαδρομές υποβολής φόρμας
#         if request.method != 'POST' or not self._is_form_path(request.path):
#             return None
#             
#         # Λήψη IP πελάτη (λαμβάνοντας υπόψη το X-Forwarded-For για περιβάλλοντα proxy)
#         ip = self._get_client_ip(request)
#         
#         # Δημιουργία μοναδικού κλειδιού cache για αυτήν την IP και διαδρομή
#         cache_key = self._get_cache_key(ip, request.path)
#         
#         # Έλεγχος αν αυτή η IP έχει ξεπεράσει το όριο ρυθμού
#         if self._is_rate_limited(cache_key):
#             # Καταγραφή του συμβάντος για ανάλυση ασφαλείας
#             logger.warning(f"Υπέρβαση ορίου ρυθμού για IP {ip} στη διαδρομή {request.path}")
#             return HttpResponse("Πολλά αιτήματα. Δοκιμάστε ξανά αργότερα.", status=429)
#             
#         return None
#     
#     def _is_form_path(self, path):
#         """
#         Ελέγχει αν η διαδρομή είναι μια διαδρομή υποβολής φόρμας που πρέπει να περιοριστεί.
#         
#         Args:
#             path: Η διαδρομή URL του αιτήματος
#             
#         Returns:
#             Boolean: True αν η διαδρομή πρέπει να περιοριστεί, False διαφορετικά
#         """
#         return any(path.startswith(form_path) for form_path in self.FORM_PATHS)
#     
#     def _get_client_ip(self, request):
#         """
#         Λήψη της διεύθυνσης IP του πελάτη λαμβάνοντας υπόψη proxies.
#         
#         Υποστηρίζει τόσο άμεσες συνδέσεις όσο και περιβάλλοντα πίσω από proxy,
#         αποκτώντας την πραγματική IP του τελικού χρήστη.
#         
#         Args:
#             request: Το αντικείμενο αιτήματος Django
#             
#         Returns:
#             str: Η διεύθυνση IP του πελάτη
#         """
#         x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
#         if x_forwarded_for:
#             # Λήψη της IP του πελάτη (πρώτη στη λίστα)
#             ip = x_forwarded_for.split(',')[0].strip()
#         else:
#             ip = request.META.get('REMOTE_ADDR')
#         return ip
#     
#     def _get_cache_key(self, ip, path):
#         """
#         Δημιουργία κλειδιού cache από IP και διαδρομή.
#         
#         Κρυπτογραφεί την IP για λόγους ιδιωτικότητας, ώστε να μην αποθηκεύονται
#         διευθύνσεις IP σε απλή μορφή στην cache.
#         
#         Args:
#             ip: Η διεύθυνση IP του πελάτη
#             path: Η διαδρομή URL του αιτήματος
#             
#         Returns:
#             str: Το δημιουργημένο κλειδί cache
#         """
#         # Hash της IP για ιδιωτικότητα
#         hashed_ip = hashlib.sha256(ip.encode()).hexdigest()
#         return f"form_ratelimit:{hashed_ip}:{path}"
#     
#     def _is_rate_limited(self, cache_key):
#         """
#         Έλεγχος αν το αίτημα έχει περιορισμένο ρυθμό και ενημέρωση του μετρητή.
#         
#         Παρακολουθεί τον αριθμό των αιτημάτων που έχουν γίνει στη συγκεκριμένη περίοδο
#         και αποφασίζει αν πρέπει να επιβληθεί περιορισμός.
#         
#         Args:
#             cache_key: Το κλειδί cache για τον έλεγχο περιορισμού ρυθμού
#             
#         Returns:
#             Boolean: True αν το αίτημα πρέπει να περιοριστεί, False διαφορετικά
#         """
#         # Λήψη του τρέχοντος μετρητή υποβολών
#         submission_data = cache.get(cache_key)
#         
#         current_time = time.time()
#         
#         if submission_data is None:
#             # Πρώτη υποβολή στην περίοδο
#             submission_data = {
#                 'count': 1,
#                 'first_submission': current_time
#             }
#             cache.set(cache_key, submission_data, self.TIME_PERIOD)
#             return False
#             
#         # Έλεγχος αν έχει παρέλθει η χρονική περίοδος
#         if current_time - submission_data['first_submission'] > self.TIME_PERIOD:
#             # Επαναφορά μετρητή για νέα περίοδο
#             submission_data = {
#                 'count': 1,
#                 'first_submission': current_time
#             }
#             cache.set(cache_key, submission_data, self.TIME_PERIOD)
#             return False
#             
#         # Αύξηση μετρητή
#         submission_data['count'] += 1
#         cache.set(cache_key, submission_data, self.TIME_PERIOD)
#         
#         # Έλεγχος αν έχει ξεπεραστεί το όριο ρυθμού
#         if submission_data['count'] > self.RATE_LIMIT:
#             return True
#             
#         return False