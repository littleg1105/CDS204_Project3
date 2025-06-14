#!/usr/bin/env python
"""
Script to populate the database with dummy data for testing purposes.
This includes users, products, carts, orders, and reviews.

VULNERABILITY WARNING: This script creates users with weak passwords
for demonstration of authentication vulnerabilities.
"""

import os
import sys
import django
from decimal import Decimal
import random
from datetime import datetime, timedelta
import argparse

# Add the project directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'eshop_project.settings')
django.setup()

from django.contrib.auth import get_user_model
from django.utils import timezone
from eshop.models import Product, Cart, CartItem, ShippingAddress, Order, OrderItem, ProductReview

User = get_user_model()


def create_users():
    """Create dummy users with intentionally weak passwords."""
    print("Creating users...")
    
    users_data = [
        # Admin user - already exists usually
        {
            'username': 'admin',
            'email': 'admin@eshop.gr',
            'password': 'admin123',  # VULNERABILITY: Weak password
            'first_name': 'Διαχειριστής',
            'last_name': 'Συστήματος',
            'is_staff': True,
            'is_superuser': True
        },
        # Regular users with weak passwords
        {
            'username': 'test',
            'email': 'test@example.com',
            'password': 'test123',  # VULNERABILITY: Weak password
            'first_name': 'Δοκιμαστικός',
            'last_name': 'Χρήστης'
        },
        {
            'username': 'john',
            'email': 'john@example.com',
            'password': 'password',  # VULNERABILITY: Common password
            'first_name': 'John',
            'last_name': 'Doe'
        },
        {
            'username': 'maria',
            'email': 'maria@example.com',
            'password': '123456',  # VULNERABILITY: Weak numeric password
            'first_name': 'Μαρία',
            'last_name': 'Παπαδοπούλου'
        },
        {
            'username': 'george',
            'email': 'george@example.com',
            'password': 'george',  # VULNERABILITY: Username as password
            'first_name': 'Γιώργος',
            'last_name': 'Γεωργίου'
        }
    ]
    
    created_users = []
    for user_data in users_data:
        try:
            user, created = User.objects.get_or_create(
                username=user_data['username'],
                defaults={
                    'email': user_data['email'],
                    'first_name': user_data['first_name'],
                    'last_name': user_data['last_name'],
                    'is_staff': user_data.get('is_staff', False),
                    'is_superuser': user_data.get('is_superuser', False)
                }
            )
            if created:
                user.set_password(user_data['password'])
                user.save()
                print(f"  ✓ Created user: {user.username}")
            else:
                print(f"  - User already exists: {user.username}")
            created_users.append(user)
        except Exception as e:
            print(f"  ✗ Error creating user {user_data['username']}: {e}")
    
    return created_users


def create_products():
    """Create dummy products for the shop."""
    print("\nCreating products...")
    
    products_data = [
        {
            'name': 'Laptop Dell XPS 13',
            'description': 'Υψηλής απόδοσης laptop με Intel Core i7, 16GB RAM, 512GB SSD. Ιδανικό για επαγγελματική χρήση.',
            'price': Decimal('1299.99')
        },
        {
            'name': 'iPhone 13 Pro',
            'description': 'Το τελευταίο μοντέλο της Apple με προηγμένη κάμερα και A15 Bionic chip.',
            'price': Decimal('1099.00')
        },
        {
            'name': 'Samsung 4K Smart TV 55"',
            'description': 'Smart TV με 4K ανάλυση, HDR και ενσωματωμένες εφαρμογές streaming.',
            'price': Decimal('899.99')
        },
        {
            'name': 'Sony WH-1000XM4',
            'description': 'Ασύρματα ακουστικά με κορυφαία ακύρωση θορύβου και 30 ώρες μπαταρία.',
            'price': Decimal('349.99')
        },
        {
            'name': 'iPad Air',
            'description': 'Ισχυρό tablet με M1 chip, 10.9" οθόνη και υποστήριξη Apple Pencil.',
            'price': Decimal('599.00')
        },
        {
            'name': 'Canon EOS R6',
            'description': 'Επαγγελματική mirrorless κάμερα με 20MP full-frame αισθητήρα.',
            'price': Decimal('2499.00')
        },
        {
            'name': 'PlayStation 5',
            'description': 'Κονσόλα παιχνιδιών νέας γενιάς με 4K gaming και ultra-fast SSD.',
            'price': Decimal('499.99')
        },
        {
            'name': 'Kindle Paperwhite',
            'description': 'E-reader με 6.8" οθόνη, αδιάβροχο και ρυθμιζόμενο warm light.',
            'price': Decimal('139.99')
        },
        {
            'name': 'Apple Watch Series 7',
            'description': 'Smartwatch με μεγαλύτερη οθόνη, αισθητήρες υγείας και fitness tracking.',
            'price': Decimal('399.00')
        },
        {
            'name': 'Bose SoundLink Revolve+',
            'description': 'Φορητό Bluetooth ηχείο με 360° ήχο και 16 ώρες μπαταρία.',
            'price': Decimal('299.99')
        }
    ]
    
    created_products = []
    for product_data in products_data:
        try:
            product, created = Product.objects.get_or_create(
                name=product_data['name'],
                defaults={
                    'description': product_data['description'],
                    'price': product_data['price']
                }
            )
            if created:
                print(f"  ✓ Created product: {product.name}")
            else:
                print(f"  - Product already exists: {product.name}")
            created_products.append(product)
        except Exception as e:
            print(f"  ✗ Error creating product {product_data['name']}: {e}")
    
    return created_products


def create_carts(users):
    """Create shopping carts for users."""
    print("\nCreating carts...")
    
    for user in users:
        if not user.is_superuser:  # Skip admin user
            try:
                cart, created = Cart.objects.get_or_create(user=user)
                if created:
                    print(f"  ✓ Created cart for user: {user.username}")
                else:
                    print(f"  - Cart already exists for user: {user.username}")
            except Exception as e:
                print(f"  ✗ Error creating cart for {user.username}: {e}")


def create_reviews(users, products):
    """Create product reviews with XSS vulnerabilities."""
    print("\nCreating product reviews...")
    
    # Sample reviews including some with XSS payloads
    reviews_data = [
        {
            'title': 'Εξαιρετικό προϊόν!',
            'content': 'Πολύ ευχαριστημένος με την αγορά. Άριστη ποιότητα και γρήγορη παράδοση.',
            'rating': 5
        },
        {
            'title': 'Καλό αλλά ακριβό',
            'content': 'Η ποιότητα είναι καλή αλλά η τιμή είναι λίγο υψηλή για τα χαρακτηριστικά.',
            'rating': 3
        },
        {
            'title': '<script>alert("XSS Test")</script>',  # VULNERABILITY: XSS payload
            'content': 'Δοκιμή ασφαλείας <img src=x onerror=alert("XSS")>',  # VULNERABILITY: XSS payload
            'rating': 4
        },
        {
            'title': 'Απογοητευτικό',
            'content': 'Το προϊόν ήρθε ελαττωματικό. Ζητώ επιστροφή χρημάτων.',
            'rating': 1
        },
        {
            'title': 'Πολύ καλό!',
            'content': 'Ακριβώς όπως το περίμενα. Συνιστώ ανεπιφύλακτα!',
            'rating': 5
        },
        {
            'title': 'Test <script>document.cookie</script>',  # VULNERABILITY: Cookie theft attempt
            'content': '<iframe src="javascript:alert(document.domain)"></iframe>',  # VULNERABILITY: XSS iframe
            'rating': 4
        }
    ]
    
    # Create reviews for random products by random users
    review_count = 0
    for _ in range(20):  # Create 20 reviews total
        try:
            user = random.choice([u for u in users if not u.is_superuser])
            product = random.choice(products)
            review_data = random.choice(reviews_data)
            
            # Check if user already reviewed this product
            existing_review = ProductReview.objects.filter(user=user, product=product).exists()
            if not existing_review:
                review = ProductReview.objects.create(
                    product=product,
                    user=user,
                    title=review_data['title'],
                    content=review_data['content'],
                    rating=review_data['rating']
                )
                review_count += 1
                print(f"  ✓ Created review by {user.username} for {product.name[:30]}...")
        except Exception as e:
            print(f"  ✗ Error creating review: {e}")
    
    print(f"  Total reviews created: {review_count}")




def create_orders(users, products):
    """Create sample orders."""
    print("\nCreating orders...")
    
    order_count = 0
    for user in users:
        if not user.is_superuser:  # Skip admin user
            try:
                # Create shipping address for user
                address, _ = ShippingAddress.objects.get_or_create(
                    user=user,
                    defaults={
                        'name': f"{user.first_name} {user.last_name}",
                        'address': f"Οδός Δοκιμής {random.randint(1, 100)}",
                        'city': random.choice(['Αθήνα', 'Θεσσαλονίκη', 'Πάτρα', 'Ηράκλειο']),
                        'zip_code': f"{random.randint(10000, 19999)}",
                        'country': 'Ελλάδα',
                        'phone': f"69{random.randint(10000000, 99999999)}",
                        'email': user.email
                    }
                )
                
                # Create 1-2 orders per user
                for _ in range(random.randint(1, 2)):
                    # Select random products
                    order_products = random.sample(products, random.randint(1, 4))
                    
                    # Calculate total
                    total = sum(p.price * random.randint(1, 3) for p in order_products)
                    
                    # Create order with random status
                    order = Order.objects.create(
                        user=user,
                        shipping_address=address,
                        total_price=total,
                        status=random.choice(['pending', 'processing', 'shipped', 'delivered'])
                    )
                    
                    # Add order items
                    for product in order_products:
                        OrderItem.objects.create(
                            order=order,
                            product=product,
                            quantity=random.randint(1, 3),
                            price=product.price
                        )
                    
                    # Adjust created_at to be in the past (using timezone-aware datetime)
                    days_ago = random.randint(1, 30)
                    order.created_at = timezone.now() - timedelta(days=days_ago)
                    order.save()
                    
                    order_count += 1
                    print(f"  ✓ Created order {order.id} for {user.username}")
                    
            except Exception as e:
                print(f"  ✗ Error creating order for {user.username}: {e}")
    
    print(f"  Total orders created: {order_count}")


def check_database_connection():
    """Check if we can connect to the database."""
    try:
        from django.db import connection
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
        print("✓ Database connection successful")
        return True
    except Exception as e:
        print(f"✗ Database connection failed: {e}")
        print("\nPlease ensure:")
        print("  1. The database is created")
        print("  2. Migrations have been run: python manage.py migrate")
        print("  3. The database settings in settings.py are correct")
        return False


def main():
    """Main function to populate all dummy data."""
    print("=== Populating Database with Dummy Data ===\n")
    
    # Check database connection first
    if not check_database_connection():
        return
    
    try:
        # Create data
        users = create_users()
        if not users:
            print("⚠️  No users created, skipping dependent data...")
            return
            
        products = create_products()
        if not products:
            print("⚠️  No products created, skipping dependent data...")
            return
            
        create_carts(users)
        create_reviews(users, products)
        create_orders(users, products)
        
        print("\n=== Database Population Complete ===")
        print(f"\nSummary:")
        try:
            print(f"  - Users: {User.objects.count()}")
            print(f"  - Products: {Product.objects.count()}")
            print(f"  - Carts: {Cart.objects.count()}")
            print(f"  - Reviews: {ProductReview.objects.count()}")
            print(f"  - Orders: {Order.objects.count()}")
        except Exception as e:
            print(f"  ✗ Error getting counts: {e}")
        
        print("\n⚠️  WARNING: This database contains intentional vulnerabilities!")
        print("  - Weak passwords (e.g., 'test123', 'password', '123456')")
        print("  - XSS payloads in product reviews")
        print("  - This is for educational penetration testing only!")
        
    except Exception as e:
        print(f"\n✗ Critical error during population: {e}")
        import traceback
        traceback.print_exc()


def clear_existing_data():
    """Clear existing data from the database."""
    print("\nClearing existing data...")
    try:
        # Delete in reverse order of dependencies
        print("  - Deleting reviews...")
        ProductReview.objects.all().delete()
        
        print("  - Deleting order items...")
        OrderItem.objects.all().delete()
        
        print("  - Deleting orders...")
        Order.objects.all().delete()
        
        print("  - Deleting shipping addresses...")
        ShippingAddress.objects.all().delete()
        
        print("  - Deleting cart items...")
        CartItem.objects.all().delete()
        
        print("  - Deleting carts...")
        Cart.objects.all().delete()
        
        print("  - Deleting products...")
        Product.objects.all().delete()
        
        # Only delete non-superuser accounts
        print("  - Deleting non-admin users...")
        User.objects.filter(is_superuser=False).delete()
        
        print("✓ Existing data cleared successfully\n")
        return True
    except Exception as e:
        print(f"✗ Error clearing data: {e}")
        return False


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Populate database with dummy data')
    parser.add_argument('--clear', action='store_true', 
                        help='Clear existing data before populating')
    args = parser.parse_args()
    
    if args.clear:
        # Add confirmation prompt
        response = input("⚠️  This will DELETE existing data. Continue? (yes/no): ")
        if response.lower() != 'yes':
            print("Operation cancelled.")
            sys.exit(0)
            
        # Check database connection first
        print("\nChecking database connection...")
        if not check_database_connection():
            sys.exit(1)
            
        if not clear_existing_data():
            print("Failed to clear data. Exiting.")
            sys.exit(1)
    
    main()