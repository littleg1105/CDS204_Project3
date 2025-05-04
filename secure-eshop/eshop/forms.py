from django import forms
from django.contrib.auth import authenticate
from django.core.exceptions import ValidationError
from .models import ShippingAddress
import time
import bleach

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
        # Επιπλέον επικύρωση
        cleaned_data = super().clean()
        username = cleaned_data.get('username')
        password = cleaned_data.get('password')

        if username and password:
            # Σταθερός χρόνος καθυστέρησης για αποφυγή user enumeration
            time.sleep(0.1)
            
            # Τώρα περνάμε το request στο authenticate
            user = authenticate(self.request, username=username, password=password)
            if not user:
                # Γενικό μήνυμα σφάλματος - αποφυγή user enumeration
                raise ValidationError("Invalid username or password. Please try again.")
            
            # Αποθηκεύουμε τον χρήστη για χρήση στο view
            self.user = user
        
        return cleaned_data
    
class ShippingAddressForm(forms.ModelForm):
    class Meta:
        model = ShippingAddress
        fields = ['name', 'address', 'city', 'zip_code', 'country']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Ονοματεπώνυμο'}),
            'address': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Διεύθυνση'}),
            'city': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Πόλη'}),
            'zip_code': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'ΤΚ'}),
            'country': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Χώρα'}),
        }
    
    def clean(self):
        cleaned_data = super().clean()
        
        # Καθαρισμός των δεδομένων εισόδου για προστασία από XSS
        for field in self.fields:
            if field in cleaned_data and isinstance(cleaned_data[field], str):
                cleaned_data[field] = bleach.clean(cleaned_data[field])
        
        return cleaned_data