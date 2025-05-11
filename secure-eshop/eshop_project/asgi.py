# ============================================================================
# ASGI CONFIGURATION FILE
# Αρχείο διαμόρφωσης για Asynchronous Server Gateway Interface
# ============================================================================

"""
ASGI config for eshop_project project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.2/howto/deployment/asgi/
"""
# Χρησιμότητα του docstring:
# - Επίσημη τεκμηρίωση του αρχείου
# - Εξηγεί τον σκοπό (ASGI configuration)
# - Παρέχει link στην τεκμηρίωση του Django
# - Αυτόματα δημιουργείται από το django-admin startproject


# ============================================================================
# IMPORTS - Εισαγωγή απαραίτητων modules
# ============================================================================

# Operating system interface
import os
# Χρησιμότητα:
# - Παρέχει πρόσβαση σε environment variables
# - Χρησιμοποιείται για να ορίσει το DJANGO_SETTINGS_MODULE
# - Cross-platform compatibility

# Django ASGI application getter
from django.core.asgi import get_asgi_application
# Χρησιμότητα:
# - Βασική function του Django για δημιουργία ASGI application
# - Επιστρέφει ASGI-compatible callable
# - Διαχειρίζεται asynchronous requests


# ============================================================================
# ENVIRONMENT CONFIGURATION
# Ρύθμιση environment variables
# ============================================================================

# Ορισμός του Django settings module
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'eshop_project.settings')
# Χρησιμότητα:
# - Ορίζει ποιο settings module θα χρησιμοποιήσει το Django
# - setdefault: Θέτει τιμή μόνο αν δεν υπάρχει ήδη
# - Επιτρέπει override από external environment
# - Κρίσιμο για την εκκίνηση του Django


# ============================================================================
# ASGI APPLICATION CREATION
# Δημιουργία του ASGI application instance
# ============================================================================

# Δημιουργία και export του ASGI application
application = get_asgi_application()
# Χρησιμότητα:
# - Δημιουργεί το ASGI application object
# - Αυτό το object χειρίζεται όλα τα asynchronous requests
# - Module-level variable για εύκολη πρόσβαση από ASGI servers
# - Entry point για ASGI-compatible servers (Daphne, Uvicorn, etc.)









# ============================================================================
# # ΣΧΟΛΙΑ ΠΕΡΙΓΡΑΦΗΣ
# # ============================================================================

# ## Αναλυτική Επεξήγηση ASGI

# ### 1. Τι είναι το ASGI;
# **ASGI (Asynchronous Server Gateway Interface)** είναι:
# - Το πρότυπο για asynchronous Python web applications
# - Διάδοχος του WSGI με support για async/await
# - Επιτρέπει WebSockets, HTTP2, και long-polling
# - Υποστηρίζει parallel request handling

# ### 2. ASGI vs WSGI
# ```python
# # WSGI (Synchronous)
# def application(environ, start_response):
#     # Handles one request at a time
#     status = '200 OK'
#     headers = [('Content-type', 'text/plain')]
#     start_response(status, headers)
#     return [b"Hello World"]

# # ASGI (Asynchronous)
# async def application(scope, receive, send):
#     # Can handle multiple requests concurrently
#     await send({
#         'type': 'http.response.start',
#         'status': 200,
#         'headers': [[b'content-type', b'text/plain']],
#     })
#     await send({
#         'type': 'http.response.body',
#         'body': b'Hello World',
#     })
# ```

# ### 3. Χρησιμότητα του ASGI στο E-shop

# #### Real-time Features
# ```python
# # Μελλοντικές δυνατότητες με ASGI
# async def live_cart_updates(websocket):
#     """Real-time cart updates μέσω WebSocket."""
#     await websocket.accept()
#     while True:
#         data = await websocket.receive_json()
#         # Process cart update
#         await websocket.send_json({
#             'cart_total': calculate_total(),
#             'items_count': get_items_count()
#         })
# ```

# #### Asynchronous Database Queries
# ```python
# # Μελλοντική χρήση async ORM
# async def get_products_async():
#     """Asynchronous database query."""
#     products = await Product.objects.all().aexecute()
#     return products
# ```

# ### 4. Deployment με ASGI

# #### Development
# ```bash
# # Χρήση Daphne για development
# pip install daphne
# daphne eshop_project.asgi:application
# ```

# #### Production
# ```bash
# # Χρήση Uvicorn για production
# pip install uvicorn
# uvicorn eshop_project.asgi:application --host 0.0.0.0 --port 8000
# ```

# #### Nginx Configuration
# ```nginx
# # Nginx proxy για ASGI
# upstream asgi_backend {
#     server unix:/tmp/asgi.sock;
# }

# server {
#     listen 80;
#     server_name example.com;

#     location / {
#         proxy_pass http://asgi_backend;
#         proxy_http_version 1.1;
#         proxy_set_header Upgrade $http_upgrade;
#         proxy_set_header Connection "upgrade";
#         proxy_set_header Host $host;
#         proxy_set_header X-Real-IP $remote_addr;
#     }

#     location /ws/ {
#         proxy_pass http://asgi_backend;
#         proxy_http_version 1.1;
#         proxy_set_header Upgrade $http_upgrade;
#         proxy_set_header Connection "upgrade";
#     }
# }
# ```

# ### 5. Environment Variables

# ```python
# # Πιο σύνθετη διαχείριση environment
# import os
# from pathlib import Path
# from dotenv import load_dotenv

# # Load environment variables
# BASE_DIR = Path(__file__).resolve().parent.parent
# load_dotenv(BASE_DIR / '.env')

# # Set Django settings με fallback
# os.environ.setdefault(
#     'DJANGO_SETTINGS_MODULE',
#     os.getenv('DJANGO_SETTINGS_MODULE', 'eshop_project.settings')
# )

# application = get_asgi_application()
# ```

# ### 6. Extended ASGI Configuration

# ```python
# # asgi.py με WebSocket support
# import os
# from django.core.asgi import get_asgi_application
# from channels.routing import ProtocolTypeRouter, URLRouter
# from channels.auth import AuthMiddlewareStack
# import eshop.routing

# os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'eshop_project.settings')

# application = ProtocolTypeRouter({
#     "http": get_asgi_application(),
#     "websocket": AuthMiddlewareStack(
#         URLRouter(
#             eshop.routing.websocket_urlpatterns
#         )
#     ),
# })
# ```

# ### 7. Middleware για ASGI

# ```python
# # Custom ASGI middleware
# class TimingMiddleware:
#     def __init__(self, app):
#         self.app = app

#     async def __call__(self, scope, receive, send):
#         import time
#         start = time.time()
        
#         await self.app(scope, receive, send)
        
#         duration = time.time() - start
#         print(f"Request took {duration:.2f} seconds")

# # Εφαρμογή middleware
# application = TimingMiddleware(get_asgi_application())
# ```

# ### 8. Testing ASGI Applications

# ```python
# # tests/test_asgi.py
# import pytest
# from channels.testing import HttpCommunicator
# from eshop_project.asgi import application

# @pytest.mark.asyncio
# async def test_homepage():
#     """Test ASGI application responds to HTTP requests."""
#     communicator = HttpCommunicator(application, "GET", "/")
#     response = await communicator.get_response()
#     assert response["status"] == 200
#     assert response["body"] != b""
# ```

# ### 9. Performance Benefits

# ```python
# # Σύγκριση WSGI vs ASGI performance
# """
# WSGI (Traditional):
# - 1 thread = 1 request
# - Blocking I/O
# - Limited concurrency

# ASGI (Modern):
# - Event loop με async/await
# - Non-blocking I/O
# - High concurrency
# - WebSocket support
# - HTTP/2 support
# """
# ```

# ### 10. Monitoring και Logging

# ```python
# # Enhanced ASGI με logging
# import os
# import logging
# from django.core.asgi import get_asgi_application

# # Configure logging
# logging.basicConfig(
#     level=logging.INFO,
#     format='%(asctime)s [%(levelname)s] %(message)s'
# )
# logger = logging.getLogger(__name__)

# os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'eshop_project.settings')

# try:
#     application = get_asgi_application()
#     logger.info("ASGI application started successfully")
# except Exception as e:
#     logger.error(f"Failed to start ASGI application: {e}")
#     raise
# ```

# ## Use Cases για ASGI στο E-shop

# ### 1. Real-time Stock Updates
# ```python
# # Ενημέρωση stock σε real-time
# async def stock_updates(websocket, product_id):
#     """Stream stock updates για προϊόν."""
#     await websocket.accept()
    
#     while True:
#         stock = await get_product_stock(product_id)
#         await websocket.send_json({
#             'product_id': product_id,
#             'stock': stock,
#             'available': stock > 0
#         })
#         await asyncio.sleep(5)  # Update κάθε 5 δευτερόλεπτα
# ```

# ### 2. Live Order Tracking
# ```python
# # Live tracking παραγγελιών
# async def order_tracking(websocket, order_id):
#     """Real-time order status updates."""
#     await websocket.accept()
    
#     while True:
#         order_status = await get_order_status(order_id)
#         await websocket.send_json({
#             'order_id': order_id,
#             'status': order_status,
#             'updated_at': timezone.now().isoformat()
#         })
#         await asyncio.sleep(30)  # Check κάθε 30 δευτερόλεπτα
# ```

# ### 3. Chat Support
# ```python
# # Customer support chat
# async def support_chat(websocket, user_id):
#     """Real-time chat με customer support."""
#     await websocket.accept()
    
#     async for message in websocket:
#         # Process incoming message
#         response = await process_support_message(message)
#         await websocket.send_json(response)
# ```

# ## Συμπέρασμα

# Το ASGI configuration file είναι:
# - **Entry point** για asynchronous Django applications
# - **Foundation** για real-time features
# - **Gateway** για modern web protocols
# - **Performance enabler** για high-concurrency apps

# Για το τρέχον e-shop, το ASGI είναι preparation για μελλοντικές δυνατότητες:
# - WebSocket connections
# - Real-time updates
# - Asynchronous operations
# - Better scalability

# Είναι minimal configuration τώρα, αλλά ανοίγει πολλές δυνατότητες για το μέλλον.