"""
Utility functions for the eshop application.

This module provides common utility functions used across the application.
"""

import dns.resolver
import dns.exception
import time
import logging
from django.core.cache import caches

# Get the DNS cache
dns_cache = caches['dns_cache']

# Configure logger
logger = logging.getLogger('security')

def verify_email_domain(email, timeout=3):
    """
    Verify if an email domain is valid by checking its DNS records.
    
    Uses caching to minimize lookups and includes timeout for performance.
    
    Args:
        email (str): The email address to verify
        timeout (int): Timeout in seconds for DNS lookups
        
    Returns:
        bool: True if the domain appears valid, False otherwise
    """
    if not email or '@' not in email:
        return False
        
    # Extract domain from email
    domain = email.split('@')[-1]
    
    # Check cache first
    cache_key = f'domain_verify:{domain}'
    cached_result = dns_cache.get(cache_key)
    
    if cached_result is not None:
        return cached_result
    
    # If not in cache, perform DNS lookups
    result = False
    
    try:
        # Try MX record lookup first (mail server)
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        
        # Check for MX records
        try:
            mx_records = resolver.resolve(domain, 'MX')
            if mx_records:
                result = True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            # If no MX records, try A record as fallback
            try:
                a_records = resolver.resolve(domain, 'A')
                if a_records:
                    result = True
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                result = False
                
    except dns.exception.Timeout:
        logger.warning(f"DNS lookup timeout for domain {domain}")
        # In case of timeout, assume the domain might be valid
        # but log the warning for monitoring
        return True
    except Exception as e:
        logger.error(f"Error verifying email domain {domain}: {str(e)}")
        # For unknown errors, be lenient and assume domain is valid
        return True
        
    # Cache the result
    dns_cache.set(cache_key, result)
    
    return result