from django.db import models
from django.contrib.auth.models import AbstractUser
import uuid


class User(AbstractUser):
    """
    Custom User model that uses UUID as primary key instead of auto-incrementing integer.
    
    Χρησιμότητα:
    - Ασφαλέστερη υλοποίηση με μη-προβλέψιμα IDs
    - Αποφυγή enumeration attacks
    - Συμβατότητα με το υπόλοιπο σχήμα της βάσης
    """
    
    # Override the id field to use UUID
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        verbose_name='ID'
    )
    
    class Meta(AbstractUser.Meta):
        swappable = 'AUTH_USER_MODEL'
        verbose_name = 'Χρήστης'
        verbose_name_plural = 'Χρήστες'