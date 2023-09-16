from django.urls import path
from . import views

urlpatterns = [
    path('signup/', views.signup, name = 'signup'),
    path('login/', views.loginUser, name = 'login'),
    path('logout/', views.logoutUser, name = 'logout'),
    path('activate/<uidb64>/<token>/', views.ActivateAccountView.as_view(), name = 'activate'),
    path('reset-password-email/', views.RequestResetEmailView.as_view(), name = 'reset-password-email'),
    path('set-new-password/<uidb64>/<token>/', views.SetNewPasswordView.as_view(), name = 'set-new-password'),
]