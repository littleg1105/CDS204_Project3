"""
Custom middleware για ενισχυμένη ασφάλεια.

Αυτό το module παρέχει κλάσεις middleware για πρόσθετες προστασίες ασφαλείας.
Υλοποιεί μηχανισμούς όπως κλείδωμα OTP, rate limiting και προστασία φορμών.
"""

import logging
from django.utils.deprecation import MiddlewareMixin
from django.http import HttpResponseRedirect, HttpResponse
from django.core.cache import cache
from django.contrib import messages
from django.urls import reverse
import time
import hashlib
import functools

# Ρύθμιση logger για καταγραφή συμβάντων ασφαλείας
logger = logging.getLogger('security')

# Σταθερές για τις διαδρομές URL
ADMIN_LOGIN_PATH = '/admin/login/'

class OTPLockoutMiddleware(MiddlewareMixin):
    """
    Middleware για επιβολή κλειδώματος OTP σε όλα τα αιτήματα διαχείρισης.
    
    Αυτό το middleware ελέγχει αν ένας χρήστης είναι κλειδωμένος από την επαλήθευση OTP
    και αποκλείει την πρόσβαση στις σελίδες διαχείρισης εάν είναι.
    
    Λειτουργεί σε δύο επίπεδα:
    1. Στη σελίδα σύνδεσης: Ελέγχει αν το όνομα χρήστη είναι κλειδωμένο
    2. Σε όλες τις σελίδες διαχείρισης: Αναγκάζει αποσύνδεση για κλειδωμένους χρήστες
    """
    
    def process_request(self, request):
        """
        Ελέγχει αν ο χρήστης είναι κλειδωμένος από το OTP και επιβάλλει το κλείδωμα.
        
        Args:
            request: Το αντικείμενο αιτήματος Django
            
        Returns:
            None ή ανακατεύθυνση σε περίπτωση κλειδώματος
        """
        # Για τη σελίδα σύνδεσης, έλεγχος αν το όνομα χρήστη στο POST είναι κλειδωμένο
        if request.path == ADMIN_LOGIN_PATH and request.method == 'POST':
            username = request.POST.get('username')
            if username:
                # Έλεγχος αν αυτό το όνομα χρήστη είναι κλειδωμένο
                from .admin import OTPLockoutTracker
                if OTPLockoutTracker.check_lockout(username):
                    # Ανακατεύθυνση στη σύνδεση διαχείρισης με μήνυμα κλειδώματος
                    from django.shortcuts import redirect
                    from django.contrib import messages
                    
                    # Αντί να προσπαθούμε να χρησιμοποιήσουμε messages, θα το χειριστούμε
                    # μέσω του admin login view που προσθέτει μηνύματα στο context
                    return redirect(ADMIN_LOGIN_PATH)
        
        # Για όλες τις σελίδες διαχείρισης, επιβολή κλειδώματος αν είναι πιστοποιημένος
        elif request.path.startswith('/admin/'):
            # Παράλειψη αν δεν είναι πιστοποιημένος
            if not request.user.is_authenticated:
                return None
                
            # Έλεγχος αν ο χρήστης είναι κλειδωμένος
            username = request.user.username
            from .admin import OTPLockoutTracker
            if OTPLockoutTracker.check_lockout(username):
                # Ο χρήστης είναι κλειδωμένος - αναγκαστική αποσύνδεση και ανακατεύθυνση
                from django.contrib.auth import logout
                logout(request)
                
                # Ανακατεύθυνση στη σελίδα σύνδεσης
                from django.shortcuts import redirect
                return redirect(ADMIN_LOGIN_PATH)
            
        return None


def _parse_rate_limit(rate):
    """Parse rate limit string like '10/m' into count and period in seconds."""
    count, period = rate.split('/')
    count = int(count)
    
    period_map = {
        's': 1,      # δευτερόλεπτα
        'm': 60,     # λεπτά
        'h': 3600,   # ώρες
        'd': 86400,  # ημέρες
    }
    
    if period not in period_map:
        raise ValueError(f"Μη έγκυρη περίοδος ρυθμού: {period}")
    
    return count, period_map[period]


def _get_rate_limit_key_value(request, key):
    """Get the actual value to use for rate limiting based on the key type."""
    if key == 'ip':
        # Λήψη IP πελάτη, υποστηρίζει σενάρια πίσω από proxy
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR')
    
    if key == 'user':
        # Χρήση ID χρήστη για συνδεδεμένους χρήστες, αλλιώς IP
        if request.user.is_authenticated:
            return str(request.user.id)
        return request.META.get('REMOTE_ADDR')
    
    raise ValueError(f"Μη έγκυρος τύπος κλειδιού: {key}")


def _check_and_update_rate_limit(cache_key, count_limit, period_seconds):
    """Check if rate limit is exceeded and update the counter."""
    submission_data = cache.get(cache_key)
    current_time = time.time()
    
    if submission_data is None:
        # Πρώτη υποβολή στην περίοδο - αρχικοποίηση μετρητή
        submission_data = {
            'count': 1,
            'first_submission': current_time
        }
        cache.set(cache_key, submission_data, period_seconds)
        return False
    
    # Έλεγχος αν έχει παρέλθει η περίοδος
    if current_time - submission_data['first_submission'] > period_seconds:
        # Επαναφορά για νέα περίοδο
        submission_data = {
            'count': 1,
            'first_submission': current_time
        }
        cache.set(cache_key, submission_data, period_seconds)
        return False
    
    # Αύξηση μετρητή για υπάρχουσα περίοδο
    submission_data['count'] += 1
    cache.set(cache_key, submission_data, period_seconds)
    
    # Έλεγχος αν έχει ξεπεραστεί το όριο ρυθμού
    return submission_data['count'] > count_limit


def _handle_rate_limit_exceeded(request, block):
    """Handle the case when rate limit is exceeded."""
    logger.warning(
        f"Υπέρβαση ορίου ρυθμού - IP: {request.META.get('REMOTE_ADDR')}, "
        f"User: {request.user}, Path: {request.path}"
    )
    
    if block:
        return HttpResponse(
            "Έχετε υποβάλει πάρα πολλές αιτήσεις σε σύντομο χρονικό διάστημα. "
            "Παρακαλώ περιμένετε λίγο και δοκιμάστε ξανά.",
            status=429
        )
    return None


def custom_ratelimit(key='ip', rate='10/m', method=None, block=True):
    """
    Προσαρμοσμένος decorator περιορισμού ρυθμού χρησιμοποιώντας την ενσωματωμένη cache του Django.
    
    Επιτρέπει τον έλεγχο του αριθμού των αιτημάτων που μπορεί να κάνει ένας χρήστης ή μια IP
    σε συγκεκριμένο χρονικό διάστημα, αποτρέποντας επιθέσεις brute force και DoS.
    
    Args:
        key: 'ip' ή 'user' για καθορισμό του κλειδιού περιορισμού ρυθμού
        rate: μορφή όπως '10/m' για 10 αιτήματα ανά λεπτό
        method: λίστα μεθόδων για εφαρμογή περιορισμού ρυθμού (π.χ., ['POST'])
        block: αν θα μπλοκάρει το αίτημα όταν ξεπεραστεί το όριο ρυθμού
        
    Returns:
        Συνάρτηση decorator που εφαρμόζει περιορισμό ρυθμού
    """
    def decorator(view_func):
        @functools.wraps(view_func)  # Διατηρεί τα μεταδεδομένα της αρχικής συνάρτησης
        def wrapped_view(request, *args, **kwargs):
            # Έλεγχος αν η μέθοδος πρέπει να περιοριστεί
            if method and request.method not in method:
                return view_func(request, *args, **kwargs)
            
            # Ανάλυση ορίου ρυθμού
            count_limit, period_seconds = _parse_rate_limit(rate)
            
            # Λήψη της τιμής κλειδιού
            key_value = _get_rate_limit_key_value(request, key)
            
            # Δημιουργία κλειδιού cache
            cache_key = f"ratelimit:{key}:{key_value}:{view_func.__name__}"
            
            # Έλεγχος και ενημέρωση του ορίου ρυθμού
            if _check_and_update_rate_limit(cache_key, count_limit, period_seconds):
                # Χειρισμός υπέρβασης ορίου
                response = _handle_rate_limit_exceeded(request, block)
                if response:
                    return response
            
            # Εκτέλεση της αρχικής συνάρτησης view
            return view_func(request, *args, **kwargs)
        
        return wrapped_view
    return decorator

class FormRateLimitMiddleware(MiddlewareMixin):
    """
    Middleware για περιορισμό ρυθμού υποβολών φόρμας.
    
    Αυτό το middleware αποτρέπει επιθέσεις brute force περιορίζοντας το ρυθμό με τον οποίο
    οι χρήστες μπορούν να υποβάλλουν φόρμες, με βάση τη διεύθυνση IP τους.
    
    Εστιάζει στην προστασία κρίσιμων endpoints όπως σελίδες σύνδεσης και πληρωμών.
    """
    
    # Ρύθμιση περιορισμού ρυθμού
    RATE_LIMIT = 10     # Μέγιστες υποβολές
    TIME_PERIOD = 60    # Χρονική περίοδος σε δευτερόλεπτα
    FORM_PATHS = [      # Διαδρομές για περιορισμό ρυθμού
        '/login/',
        '/payment/',
    ]
    
    def process_request(self, request):
        """
        Επεξεργασία εισερχόμενων αιτημάτων για περιορισμό υποβολών φόρμας.
        
        Args:
            request: Το αντικείμενο αιτήματος Django
            
        Returns:
            None ή HttpResponse με κατάσταση 429 αν ξεπεραστεί το όριο ρυθμού
        """
        # Μόνο εφαρμογή σε αιτήματα POST σε διαδρομές υποβολής φόρμας
        if request.method != 'POST' or not self._is_form_path(request.path):
            return None
            
        # Λήψη IP πελάτη (λαμβάνοντας υπόψη το X-Forwarded-For για περιβάλλοντα proxy)
        ip = self._get_client_ip(request)
        
        # Δημιουργία μοναδικού κλειδιού cache για αυτήν την IP και διαδρομή
        cache_key = self._get_cache_key(ip, request.path)
        
        # Έλεγχος αν αυτή η IP έχει ξεπεράσει το όριο ρυθμού
        if self._is_rate_limited(cache_key):
            # Καταγραφή του συμβάντος για ανάλυση ασφαλείας
            logger.warning(f"Υπέρβαση ορίου ρυθμού για IP {ip} στη διαδρομή {request.path}")
            return HttpResponse("Πολλά αιτήματα. Δοκιμάστε ξανά αργότερα.", status=429)
            
        return None
    
    def _is_form_path(self, path):
        """
        Ελέγχει αν η διαδρομή είναι μια διαδρομή υποβολής φόρμας που πρέπει να περιοριστεί.
        
        Args:
            path: Η διαδρομή URL του αιτήματος
            
        Returns:
            Boolean: True αν η διαδρομή πρέπει να περιοριστεί, False διαφορετικά
        """
        return any(path.startswith(form_path) for form_path in self.FORM_PATHS)
    
    def _get_client_ip(self, request):
        """
        Λήψη της διεύθυνσης IP του πελάτη λαμβάνοντας υπόψη proxies.
        
        Υποστηρίζει τόσο άμεσες συνδέσεις όσο και περιβάλλοντα πίσω από proxy,
        αποκτώντας την πραγματική IP του τελικού χρήστη.
        
        Args:
            request: Το αντικείμενο αιτήματος Django
            
        Returns:
            str: Η διεύθυνση IP του πελάτη
        """
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            # Λήψη της IP του πελάτη (πρώτη στη λίστα)
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    
    def _get_cache_key(self, ip, path):
        """
        Δημιουργία κλειδιού cache από IP και διαδρομή.
        
        Κρυπτογραφεί την IP για λόγους ιδιωτικότητας, ώστε να μην αποθηκεύονται
        διευθύνσεις IP σε απλή μορφή στην cache.
        
        Args:
            ip: Η διεύθυνση IP του πελάτη
            path: Η διαδρομή URL του αιτήματος
            
        Returns:
            str: Το δημιουργημένο κλειδί cache
        """
        # Hash της IP για ιδιωτικότητα
        hashed_ip = hashlib.sha256(ip.encode()).hexdigest()
        return f"form_ratelimit:{hashed_ip}:{path}"
    
    def _is_rate_limited(self, cache_key):
        """
        Έλεγχος αν το αίτημα έχει περιορισμένο ρυθμό και ενημέρωση του μετρητή.
        
        Παρακολουθεί τον αριθμό των αιτημάτων που έχουν γίνει στη συγκεκριμένη περίοδο
        και αποφασίζει αν πρέπει να επιβληθεί περιορισμός.
        
        Args:
            cache_key: Το κλειδί cache για αναγνώριση του χρήστη και της διαδρομής
            
        Returns:
            Boolean: True αν έχει περιορισμένο ρυθμό, False διαφορετικά
        """
        # Λήψη του τρέχοντος μετρητή υποβολών
        submission_data = cache.get(cache_key)
        
        current_time = time.time()
        
        if submission_data is None:
            # Πρώτη υποβολή στην περίοδο
            submission_data = {
                'count': 1,
                'first_submission': current_time
            }
            cache.set(cache_key, submission_data, self.TIME_PERIOD)
            return False
            
        # Έλεγχος αν έχει παρέλθει η χρονική περίοδος
        if current_time - submission_data['first_submission'] > self.TIME_PERIOD:
            # Επαναφορά μετρητή για νέα περίοδο
            submission_data = {
                'count': 1,
                'first_submission': current_time
            }
            cache.set(cache_key, submission_data, self.TIME_PERIOD)
            return False
            
        # Αύξηση μετρητή
        submission_data['count'] += 1
        cache.set(cache_key, submission_data, self.TIME_PERIOD)
        
        # Έλεγχος αν έχει ξεπεραστεί το όριο ρυθμού
        if submission_data['count'] > self.RATE_LIMIT:
            return True
            
        return False