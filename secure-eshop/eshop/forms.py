from django import forms
from django.contrib.auth import authenticate
from django.core.exceptions import ValidationError
from .models import ShippingAddress
import time
import bleach
import secrets
import hmac

class LoginForm(forms.Form):
    username = forms.CharField(
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Username'})
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Password'})
    )

    def __init__(self, *args, **kwargs):
        self.request = kwargs.pop('request', None)
        super().__init__(*args, **kwargs)

    def clean(self):
        cleaned_data = super().clean()
        username = cleaned_data.get('username')
        password = cleaned_data.get('password')

        if username and password:
            # Σταθερός χρόνος delay για προστασία από timing attacks
            # Αντί για απλό time.sleep, χρησιμοποιούμε μια πιο σύνθετη προσέγγιση
            # που δεν είναι τόσο εύκολο να παρακαμφθεί
            start_time = time.time()
            
            # Constant-time string comparison operation - δεν αποκαλύπτει 
            # πληροφορίες μέσω timing διαφορών
            def constant_time_compare(val1, val2):
                return hmac.compare_digest(
                    str(val1).encode('utf-8'),
                    str(val2).encode('utf-8')
                )
            
            # Πραγματικός έλεγχος αυθεντικοποίησης
            user = authenticate(self.request, username=username, password=password)
            
            # Προσθήκη τυχαίας καθυστέρησης για να μην αποκαλύπτεται αν υπάρχει ο χρήστης
            random_delay = secrets.randbelow(100) / 1000  # 0-100ms τυχαία καθυστέρηση
            execution_time = time.time() - start_time
            
            # Διασφάλιση ότι η συνολική διάρκεια είναι τουλάχιστον 300ms
            # ανεξάρτητα από το αν υπάρχει ο χρήστης ή όχι
            if execution_time < 0.3:
                time.sleep(0.3 - execution_time + random_delay)
            
            if not user:
                # Γενικό μήνυμα σφάλματος που δεν δίνει πληροφορίες
                # για το αν το username υπάρχει ή το password είναι λάθος
                raise ValidationError(
                    "Τα στοιχεία σύνδεσης που εισάγατε δεν είναι έγκυρα. Παρακαλώ προσπαθήστε ξανά."
                )
            
            # Αποθήκευση του χρήστη για χρήση στο view
            self.user = user
        
        return cleaned_data
    
class ShippingAddressForm(forms.ModelForm):
    class Meta:
        model = ShippingAddress
        fields = ['name', 'address', 'city', 'zip_code', 'country', 'phone', 'email']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Ονοματεπώνυμο'}),
            'address': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Διεύθυνση'}),
            'city': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Πόλη'}),
            'zip_code': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'ΤΚ'}),
            'country': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Χώρα'}),
            'phone': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Τηλέφωνο'}),
            'email': forms.EmailInput(attrs={'class': 'form-control', 'placeholder': 'Email'}),
        }
    
    def clean(self):
        cleaned_data = super().clean()
        
        # Καθαρισμός των δεδομένων εισόδου για προστασία από XSS
        for field in self.fields:
            if field in cleaned_data and isinstance(cleaned_data[field], str):
                cleaned_data[field] = bleach.clean(cleaned_data[field])
        
        return cleaned_data