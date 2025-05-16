"""
Βοηθητικές συναρτήσεις επαλήθευσης για την εφαρμογή eshop.
Αυτό το module παρέχει βοηθητικές λειτουργίες για την επικύρωση στοιχείων χρήστη,
συμπεριλαμβανομένων των domains email, αριθμών τηλεφώνου και άλλων δεδομένων.
"""

import dns.resolver    # Βιβλιοθήκη για DNS lookups
import dns.exception   # Χειρισμός εξαιρέσεων DNS
import logging         # Καταγραφή συμβάντων και σφαλμάτων
import time            # Λειτουργίες σχετικές με χρόνο
from django.core.cache import caches   # Σύστημα caching του Django

# Λήψη του DNS cache, χρήση του default αν δεν είναι διαθέσιμο
# Τεχνική βελτιστοποίησης: Αποφεύγει επαναλαμβανόμενα DNS lookups
try:
    dns_cache = caches['dns_cache']
except KeyError:
    dns_cache = caches['default']

# Ρύθμιση logger για καταγραφή συμβάντων ασφαλείας
# Χρησιμότητα: Επιτρέπει την καταγραφή προβλημάτων και περιστατικών ασφάλειας
logger = logging.getLogger('security')

def verify_email_domain(email, timeout=3):
    """
    Επαληθεύει αν ένα domain email είναι έγκυρο ελέγχοντας τα DNS records του.
    Χρησιμοποιεί caching για ελαχιστοποίηση των lookups και περιλαμβάνει timeout για καλύτερη απόδοση.
    
    Λειτουργία:
    1. Εξάγει το domain από το email
    2. Ελέγχει αν υπάρχει αποθηκευμένο αποτέλεσμα στην cache
    3. Αν όχι, εκτελεί DNS lookup για MX records (mail servers)
    4. Αν δεν βρεθούν MX records, ελέγχει για A records ως εναλλακτική
    5. Αποθηκεύει το αποτέλεσμα στην cache για μελλοντική χρήση
    
    Args:
        email (str): Η διεύθυνση email προς επαλήθευση
        timeout (int): Χρονικό όριο σε δευτερόλεπτα για DNS lookups
        
    Returns:
        bool: True αν το domain φαίνεται έγκυρο, False διαφορετικά
        
    Ασφάλεια:
    - Προστατεύει από κακόβουλα ή ανύπαρκτα email domains
    - Επιτρέπει τον εντοπισμό πιθανών typos στις διευθύνσεις email
    """
    # Βασικός έλεγχος εγκυρότητας email
    if not email or '@' not in email:
        return False
        
    # Εξαγωγή domain από το email
    domain = email.split('@')[-1]
    
    # Έλεγχος πρώτα στην cache
    # Βελτιστοποίηση: Αποφεύγει επαναλαμβανόμενα DNS lookups για το ίδιο domain
    cache_key = f'domain_verify:{domain}'
    cached_result = dns_cache.get(cache_key)
    if cached_result is not None:
        return cached_result
    
    # Αν δεν υπάρχει στην cache, εκτέλεση DNS lookups
    result = False
    try:
        # Ρύθμιση DNS resolver με timeout για αποφυγή καθυστερήσεων
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        
        # Έλεγχος για MX records (απαραίτητα για mail servers)
        try:
            mx_records = resolver.resolve(domain, 'MX')
            if mx_records:
                result = True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            # Αν δεν υπάρχουν MX records, έλεγχος για A records ως εναλλακτική
            # Μερικοί μικροί mail servers χρησιμοποιούν το ίδιο host για web και email
            try:
                a_records = resolver.resolve(domain, 'A')
                if a_records:
                    result = True
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                result = False
    except dns.exception.Timeout:
        # Χειρισμός timeouts: καταγραφή προειδοποίησης αλλά επιτρέπει συνέχιση
        logger.warning(f"DNS lookup timeout για το domain {domain}")
        # Σε περίπτωση timeout, υποθέτουμε ότι το domain μπορεί να είναι έγκυρο
        # αλλά καταγράφουμε την προειδοποίηση για παρακολούθηση
        return True
    except Exception as e:
        # Γενικός χειρισμός σφαλμάτων: καταγραφή αλλά επιστροφή True για αποφυγή
        # απόρριψης πιθανώς έγκυρων διευθύνσεων λόγω τεχνικών προβλημάτων
        logger.error(f"Σφάλμα κατά την επαλήθευση του email domain {domain}: {str(e)}")
        # Για άγνωστα σφάλματα, είμαστε επιεικείς και υποθέτουμε ότι το domain είναι έγκυρο
        return True
    
    # Αποθήκευση του αποτελέσματος στην cache για μελλοντική χρήση
    # Βελτιστοποίηση: Μειώνει load στους DNS servers και βελτιώνει performance
    dns_cache.set(cache_key, result)
    
    return result