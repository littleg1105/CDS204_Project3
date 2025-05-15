"""
Custom middleware for enhanced security.

This module provides middleware classes for additional security protections.
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

# Configure logger
logger = logging.getLogger('security')

class OTPLockoutMiddleware(MiddlewareMixin):
    """
    Middleware to enforce OTP lockout on all admin requests.
    
    This middleware checks if a user is locked out from OTP verification
    and blocks access to admin pages if they are.
    """
    
    def process_request(self, request):
        """
        Check if user is locked out from OTP and enforce lockout.
        """
        # For login page, check if the username in POST is locked out
        if request.path == '/admin/login/' and request.method == 'POST':
            username = request.POST.get('username')
            if username:
                # Check if this username is locked out
                from .admin import OTPLockoutTracker
                if OTPLockoutTracker.check_lockout(username):
                    # Redirect to admin login with lockout message in context
                    from django.shortcuts import redirect
                    from django.contrib import messages
                    
                    # Instead of trying to use messages, we'll handle this
                    # through the admin login view which adds messages to context
                    return redirect('/admin/login/')
        
        # For all admin pages, enforce lockout if authenticated
        elif request.path.startswith('/admin/'):
            # Skip if not authenticated
            if not request.user.is_authenticated:
                return None
                
            # Check if user is locked out
            username = request.user.username
            from .admin import OTPLockoutTracker
            if OTPLockoutTracker.check_lockout(username):
                # User is locked out - force logout and redirect to login
                from django.contrib.auth import logout
                logout(request)
                
                # Redirect to login page
                from django.shortcuts import redirect
                return redirect('/admin/login/')
            
        return None


def custom_ratelimit(key='ip', rate='10/m', method=None, block=True):
    """
    Custom rate limiting decorator using Django's built-in cache.
    
    Args:
        key: 'ip' or 'user' to determine the rate limit key
        rate: format like '10/m' for 10 requests per minute
        method: list of methods to apply rate limiting (e.g., ['POST'])
        block: whether to block the request if rate limit is exceeded
        
    Returns:
        Decorator function that applies rate limiting
    """
    def decorator(view_func):
        @functools.wraps(view_func)
        def wrapped_view(request, *args, **kwargs):
            # Check if method should be rate limited
            if method and request.method not in method:
                return view_func(request, *args, **kwargs)
                
            # Parse rate limit
            count, period = rate.split('/')
            count = int(count)
            
            # Convert period to seconds
            if period == 's':
                period_seconds = 1
            elif period == 'm':
                period_seconds = 60
            elif period == 'h':
                period_seconds = 3600
            elif period == 'd':
                period_seconds = 86400
            else:
                raise ValueError(f"Invalid rate period: {period}")
                
            # Get the key value based on the key type
            if key == 'ip':
                # Get client IP
                x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
                if x_forwarded_for:
                    key_value = x_forwarded_for.split(',')[0].strip()
                else:
                    key_value = request.META.get('REMOTE_ADDR')
            elif key == 'user':
                if request.user.is_authenticated:
                    key_value = str(request.user.id)
                else:
                    key_value = request.META.get('REMOTE_ADDR')
            else:
                raise ValueError(f"Invalid key type: {key}")
                
            # Create a cache key
            cache_key = f"ratelimit:{key}:{key_value}:{view_func.__name__}"
            
            # Get current count
            submission_data = cache.get(cache_key)
            current_time = time.time()
            
            if submission_data is None:
                # First submission in period
                submission_data = {
                    'count': 1,
                    'first_submission': current_time
                }
                cache.set(cache_key, submission_data, period_seconds)
            else:
                # Check if period has elapsed
                if current_time - submission_data['first_submission'] > period_seconds:
                    # Reset for new period
                    submission_data = {
                        'count': 1,
                        'first_submission': current_time
                    }
                    cache.set(cache_key, submission_data, period_seconds)
                else:
                    # Increment counter
                    submission_data['count'] += 1
                    cache.set(cache_key, submission_data, period_seconds)
                    
                    # Check if rate limit exceeded
                    if submission_data['count'] > count:
                        logger.warning(
                            f"Rate limit exceeded - IP: {request.META.get('REMOTE_ADDR')}, "
                            f"User: {request.user}, Path: {request.path}"
                        )
                        
                        if block:
                            return HttpResponse(
                                "Έχετε υποβάλει πάρα πολλές αιτήσεις σε σύντομο χρονικό διάστημα. "
                                "Παρακαλώ περιμένετε λίγο και δοκιμάστε ξανά.",
                                status=429
                            )
                    
            return view_func(request, *args, **kwargs)
            
        return wrapped_view
    return decorator

class FormRateLimitMiddleware(MiddlewareMixin):
    """
    Middleware to rate limit form submissions.
    
    This middleware prevents brute force attacks by limiting the rate at which
    users can submit forms, based on their IP address.
    """
    
    # Rate limit configuration
    RATE_LIMIT = 10     # Maximum submissions
    TIME_PERIOD = 60    # Time period in seconds
    FORM_PATHS = [      # Paths to rate limit
        '/login/',
        '/payment/',
    ]
    
    def process_request(self, request):
        """
        Process incoming requests to limit form submissions.
        
        Args:
            request: The Django request object
            
        Returns:
            None or HttpResponse with 429 status if rate limit is exceeded
        """
        # Only apply to POST requests to form submission paths
        if request.method != 'POST' or not self._is_form_path(request.path):
            return None
            
        # Get client IP (considering X-Forwarded-For for proxy environments)
        ip = self._get_client_ip(request)
        
        # Create a unique cache key for this IP and path
        cache_key = self._get_cache_key(ip, request.path)
        
        # Check if this IP has exceeded the rate limit
        if self._is_rate_limited(cache_key):
            logger.warning(f"Rate limit exceeded for IP {ip} on path {request.path}")
            return HttpResponse("Too many requests. Please try again later.", status=429)
            
        return None
    
    def _is_form_path(self, path):
        """Check if the path is a form submission path to be rate limited."""
        return any(path.startswith(form_path) for form_path in self.FORM_PATHS)
    
    def _get_client_ip(self, request):
        """Get the client IP address considering proxies."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            # Get the client's IP (first in the list)
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    
    def _get_cache_key(self, ip, path):
        """Create a cache key from IP and path."""
        # Hash the IP for privacy
        hashed_ip = hashlib.sha256(ip.encode()).hexdigest()
        return f"form_ratelimit:{hashed_ip}:{path}"
    
    def _is_rate_limited(self, cache_key):
        """
        Check if the request is rate limited and update the counter.
        
        Returns True if rate limited, False otherwise.
        """
        # Get the current submission counter
        submission_data = cache.get(cache_key)
        
        current_time = time.time()
        
        if submission_data is None:
            # First submission in the period
            submission_data = {
                'count': 1,
                'first_submission': current_time
            }
            cache.set(cache_key, submission_data, self.TIME_PERIOD)
            return False
            
        # Check if time period has elapsed
        if current_time - submission_data['first_submission'] > self.TIME_PERIOD:
            # Reset counter for new period
            submission_data = {
                'count': 1,
                'first_submission': current_time
            }
            cache.set(cache_key, submission_data, self.TIME_PERIOD)
            return False
            
        # Increment counter
        submission_data['count'] += 1
        cache.set(cache_key, submission_data, self.TIME_PERIOD)
        
        # Check if rate limit exceeded
        if submission_data['count'] > self.RATE_LIMIT:
            return True
            
        return False