from django.shortcuts import render, HttpResponse, redirect
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages

from django.core.mail import send_mail, EmailMultiAlternatives, BadHeaderError
from django.conf import settings
from django.core import mail
from django.core.mail.message import EmailMessage

from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.urls import NoReverseMatch, reverse
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes, force_str, DjangoUnicodeDecodeError

from .utils import generate_token, TokenGenerator

from django.views.generic import View
#threading
import threading

class EmailThread(threading.Thread):
    def  __init__(self, email_message):
        self.email_message = email_message
        threading.Thread.__init__(self)

    def run(self):
        self.email_message.send()

# Create your views here.

def signup(request):
    if request.method == "POST":
        # username = request.post.get("username")
        email = request.POST.get("email")
        password = request.POST.get("password")
        confirm_password = request.POST.get("confirm_pass")
        if password != confirm_password:
            messages.warning(request, "Password don't match")
            return render(request, 'auth/signup.html')
        
        try:
            if User.objects.get(username=email):
                messages.warning(request, "Email has been regitered")
                return render(request, 'auth/signup.html')
        except Exception as e:
            pass
        # try:
        #     if User.objects.get(username=username):
        #         messages.warning(request, "Username is taken. Please choose another username")
        #         return render(request, 'auth/signup.html')
        # except Exception as e:
        #     pass

        myuser = User.objects.create_user(email, email, password)
        myuser.is_active = False
        myuser.save()
        current_site = get_current_site(request)
        email_subject = "Activate your account"
        message = render_to_string('auth/activate.html', {
            'user': myuser,
            'domain': '127.0.0.1:8000',
            'uid': urlsafe_base64_encode(force_bytes(myuser.pk)),
            'token': generate_token.make_token(myuser)
        })
        email_message = EmailMessage(email_subject, message, settings.EMAIL_HOST_USER, [email],)
        EmailThread(email_message).start()
        messages.info(request, "Activate your account by clicking link on your email")
        
        return redirect("/auth/login")
    
    
    return render(request, 'auth/signup.html')

class ActivateAccountView(View):
    def get(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except Exception as e:
            user = None

        if user and generate_token.check_token(user, token):
            user.is_active = True
            user.save()
            messages.info(request, "Congratulations! Your account has been activated")
            messages.info(request, "Please login")
            return redirect("/auth/login")
        else:
            return render(request, 'auth/activate_fail.html')

def loginUser(request):
    # if request.user.is_authenticated:
    #     return redirect("/")
    if request.method == "POST":
        email = request.POST.get("email")
        password = request.POST.get("password")

        try:
            myuser = User.objects.get(username=email)
        except:
            messages.error(request, "User doesn't exist. Please register")
        
        myuser = authenticate(request, username=email, password=password)

        if myuser is not None:
            login(request, myuser)
            messages.success(request, "Login Success")
            return redirect("/")
        else:
            messages.error(request, "Authentication Error")
    return render(request, 'auth/login.html')

class RequestResetEmailView(View):
    def get(self, request):
        return render(request, 'auth/reset-password-email.html')

    def post(self, request):
        email = request.POST.get("email")
        user = User.objects.filter(email=email)

        if user.exists():
            current_site = get_current_site(request)
            email_subject = 'Reset Your Password'
            message = render_to_string('auth/reset-user-password.html', {
                'user': user,
                'domain': '127.0.0.1:8000',
                'uid': urlsafe_base64_encode(force_bytes(user[0].pk)),
                'token': generate_token.make_token(user[0]),
            })

            email_message = EmailMessage(email_subject, message, settings.EMAIL_HOST_USER, [email])
            EmailThread(email_message).start()
            messages.info(request, "We have sent you an email with instruction on how to reset your password")
            return render(request, "auth/reset-password-email.html")

class SetNewPasswordView(View):
    def get(self, request, uidb64, token):
        context = {
            'uidb64': uidb64,
            'token': token,
        }

        try:
            user_id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=user_id)

            if not generate_token.check_token(user, token):
                messages.warning(request, "Password reset link is invalid")
                return render(request, "auth/reset-password-email.html")
            
        except DjangoUnicodeDecodeError as e:
            messages.error(request, e)

        return render(request, 'auth/set-new-password.html', context)
    
    def post(sel, request, uidb64, token):
        context = {
            'uidb64': uidb64,
            'token': token,
        }

        password = request.POST.get("new_password")
        confirm_password = request.POST.get("confirm_new_pass")

        if password != confirm_password:
            messages.warning(request, "Passwords don't match. Please check your passwords")
            return render(request, 'auth/set-new-password.html')

        try:
            user_id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=user_id)
            user.set_password(password)
            user.save()
            messages.success(request, "Password reset was successful")
            messages.success(request, "Please login with new password")
            return redirect("/auth.login/")
        except DjangoUnicodeDecodeError as e:
            messages.error(request, "Something went wrong")
            return render(request, "auth/set-new-password.html", context)



def logoutUser(request):
    # if request.user.is_authenticated:
    #     messages.info(request, "No logged in user")
    #     return redirect("/")
    logout(request)
    messages.success(request, "Logout success")
    return redirect('/auth/login')