from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate, logout
from django.views.decorators.http import require_http_methods
from django.views.decorators.debug import sensitive_post_parameters
from django.contrib.auth.signals import user_login_failed
from django.contrib import messages
from .forms import LoginForm
import logging

# Ρύθμιση logging για καταγραφή αποτυχημένων προσπαθειών σύνδεσης
logger = logging.getLogger('security')

def login_failed_callback(sender, credentials, **kwargs):
    logger.warning(f"Failed login attempt with username: {credentials.get('username')}")

user_login_failed.connect(login_failed_callback)

@require_http_methods(["GET", "POST"])
@sensitive_post_parameters('password')
def login_view(request):
    # Αν ο χρήστης είναι ήδη συνδεδεμένος, ανακατεύθυνση στον κατάλογο
    if request.user.is_authenticated:
        return redirect('catalog')
    
    if request.method == 'POST':
        form = LoginForm(request.POST, request=request)  # Περνάμε το request εδώ
        if form.is_valid():
            # Τώρα μπορούμε να πάρουμε τον χρήστη κατευθείαν από τη φόρμα
            user = form.user
            login(request, user)
            # Ανανέωση του session ID μετά την είσοδο (session fixation protection)
            request.session.cycle_key()
            # Ανακατεύθυνση στη σελίδα που ήταν πριν ή στον κατάλογο
            return redirect(request.GET.get('next', 'catalog'))
    else:
        form = LoginForm()
    
    return render(request, 'eshop/login.html', {'form': form})




def logout_view(request):
    logout(request)
    return redirect('login')


from django.contrib.auth.decorators import login_required

# Προσωρινή υλοποίηση - θα αντικατασταθεί αργότερα
@login_required
def catalog_view(request):
    return render(request, 'eshop/login.html', {'form': LoginForm()})