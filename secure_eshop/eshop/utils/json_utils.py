import json
import uuid
from django.core.serializers.json import DjangoJSONEncoder

class UUIDEncoder(DjangoJSONEncoder):
    """
    Custom JSON encoder που χειρίζεται αντικείμενα UUID.
    
    Αυτός ο encoder επεκτείνει τον JSONEncoder του Django για να σειριοποιεί σωστά 
    αντικείμενα UUID μετατρέποντάς τα σε strings, καθιστώντας τα JSON-serializable.
    
    Πρόβλημα που επιλύει:
    - Τα αντικείμενα UUID δεν είναι JSON serializable από προεπιλογή
    - Χωρίς custom encoding, η σειριοποίηση JSON θα αποτύχει με TypeError
    
    Περιπτώσεις χρήσης:
    - API responses που περιέχουν UUID primary keys
    - AJAX responses σε Django views
    - Σειριοποίηση model instances με πεδία UUID
    """
    def default(self, obj):
        """
        Αντικαθιστά την προεπιλεγμένη μέθοδο κωδικοποίησης για χειρισμό αντικειμένων UUID.
        
        Αυτή η μέθοδος καλείται από τον JSON encoder για κάθε αντικείμενο κατά τη σειριοποίηση.
        Εάν το αντικείμενο είναι UUID, το μετατρέπει σε αναπαράσταση string.
        Διαφορετικά, αναθέτει την επεξεργασία στην υλοποίηση της γονικής κλάσης.
        
        Args:
            obj: Το αντικείμενο προς κωδικοποίηση
            
        Returns:
            Μια JSON serializable αναπαράσταση του αντικειμένου
        """
        if isinstance(obj, uuid.UUID):
            # Μετατροπή αντικειμένων UUID σε strings
            # Μορφή UUID string: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
            return str(obj)
        
        # Για όλους τους άλλους τύπους, χρησιμοποιεί τον τυπικό DjangoJSONEncoder
        # Αυτός χειρίζεται datetime, Decimal, Promise, κλπ.
        return super().default(obj)


def dumps(obj, **kwargs):
    """
    Σειριοποιεί ένα αντικείμενο σε μορφοποιημένο string JSON χρησιμοποιώντας τον UUIDEncoder.
    
    Λειτουργία διευκόλυνσης που τυλίγει την json.dumps() αλλά διασφαλίζει ότι 
    ο UUIDEncoder χρησιμοποιείται ως προεπιλογή. Αυτό απλοποιεί τη σειριοποίηση JSON 
    αντικειμένων που περιέχουν UUIDs οπουδήποτε στον κώδικα.
    
    Τεχνικές λεπτομέρειες:
    - Χρησιμοποιεί setdefault για να ορίσει την κλάση encoder μόνο αν δεν έχει καθοριστεί
    - Όλες οι άλλες παράμετροι της json.dumps μπορούν να περαστούν μέσω kwargs
    
    Args:
        obj: Το αντικείμενο προς σειριοποίηση σε JSON
        **kwargs: Πρόσθετα keyword arguments που θα περαστούν στην json.dumps()
        
    Returns:
        str: Ένα JSON μορφοποιημένο string
        
    Παράδειγμα χρήσης:
        data = {'id': uuid.uuid4(), 'name': 'Test'}
        json_str = dumps(data)  # Δεν χρειάζεται να καθοριστεί encoder
    """
    # Ορισμός του UUIDEncoder ως προεπιλεγμένη κλάση encoder αν δεν έχει καθοριστεί
    kwargs.setdefault('cls', UUIDEncoder)
    
    # Προώθηση του αντικειμένου και όλων των kwargs στην κανονική συνάρτηση json.dumps
    return json.dumps(obj, **kwargs)