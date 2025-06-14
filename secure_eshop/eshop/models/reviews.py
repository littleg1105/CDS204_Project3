"""
Product Review Model - Intentionally Vulnerable to XSS

WARNING: This model is intentionally vulnerable for educational purposes.
It stores user-generated content without proper sanitization.
"""

from django.db import models
from django.contrib.auth import get_user_model
from .products import Product

User = get_user_model()


class ProductReview(models.Model):
    """
    Model for product reviews - VULNERABLE TO XSS
    
    Security Issues:
    - No input sanitization
    - Review content stored as-is
    - Rating not validated properly
    """
    
    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name='reviews')
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    
    # VULNERABILITY: No max_length or validation
    title = models.TextField()
    
    # VULNERABILITY: Raw HTML/JavaScript can be stored
    content = models.TextField(
        help_text="Write your review here"
    )
    
    # VULNERABILITY: No validation on rating range
    rating = models.IntegerField()
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-created_at']
        
    def __str__(self):
        return f"Review by {self.user.username} for {self.product.name}"
    
    def save(self, *args, **kwargs):
        """
        VULNERABILITY: No sanitization before saving
        Allows storage of malicious scripts
        """
        # Intentionally not sanitizing input
        # In secure version, we would use:
        # self.title = bleach.clean(self.title)
        # self.content = bleach.clean(self.content)
        
        super().save(*args, **kwargs)