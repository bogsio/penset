from django.urls import path
from . import views

app_name = 'accounts'

urlpatterns = [
    path('login/', views.login_page, name='login'),
    path('register/', views.register_page, name='register'),
    path('register/organization/', views.register_organization, name='register_organization'),
    path('social/organization-setup/', views.social_organization_setup, name='social_organization_setup'),
    path('logout/', views.logout_view, name='logout'),
    path('organization/', views.settings_page, name='settings'),
    path('settings/', views.user_settings_page, name='user_settings'),
    path('billing/', views.billing_page, name='billing'),
    path('update-targets/', views.update_targets, name='update_targets'),
    path('resend-verification/', views.resend_verification_email, name='resend_verification'),
    path('verification-sent/<str:email>/', views.verification_sent, name='verification_sent'),
    path('confirm-email/<str:key>/', views.CustomConfirmEmailView.as_view(), name='account_confirm_email'),
    path('social/signup/', views.CustomSocialSignupView.as_view(), name='socialaccount_signup'),
]