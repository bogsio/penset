from allauth.account.adapter import DefaultAccountAdapter
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from django.shortcuts import redirect
from django.urls import reverse
from django.contrib import messages
from django.template.loader import render_to_string
from django.core.mail import EmailMultiAlternatives
from .models import User


class CustomAccountAdapter(DefaultAccountAdapter):
    """
    Custom account adapter to handle organization assignment for new users.
    """
    
    def get_login_redirect_url(self, request):
        """
        Redirect users to organization setup if they don't have an organization.
        """
        user = request.user
        if user.is_authenticated and not user.organization:
            return reverse('accounts:social_organization_setup')
        return super().get_login_redirect_url(request)
    
    def respond_user_inactive(self, request, user):
        """
        Called when a user tries to login but is inactive.
        For our case, redirect to organization setup if they don't have an organization.
        """
        if not user.organization:
            # Store in session that this user needs organization setup
            request.session['needs_organization_setup'] = True
            return reverse('accounts:social_organization_setup')
        
        return super().respond_user_inactive(request, user)
    
    def confirm_email(self, request, email_address):
        """
        Called when an email address is confirmed.
        Activate the user and redirect to organization setup if needed.
        """
        user = email_address.user
        
        # First, verify the email address
        email_address.verified = True
        email_address.save()
        
        # Activate the user after email confirmation
        user.is_active = True
        user.save()
        
        # If user doesn't have an organization, redirect to setup
        if not user.organization:
            # Store in session that this user needs organization setup
            request.session['needs_organization_setup'] = True
            return reverse('accounts:social_organization_setup')
        
        return super().confirm_email(request, email_address)
    
    def send_mail(self, template_prefix, email, context):
        """
        Override to send HTML emails instead of text emails.
        """
        subject = render_to_string(f'{template_prefix}_subject.txt', context)
        # Remove any newlines from the subject
        subject = ''.join(subject.splitlines())
        
        # Try to render HTML template first
        try:
            html_body = render_to_string(f'{template_prefix}_message.html', context)
        except:
            # Fallback to text template if HTML doesn't exist
            html_body = render_to_string(f'{template_prefix}_message.txt', context)
        
        # Always render text version as well
        text_body = render_to_string(f'{template_prefix}_message.txt', context)
        
        # Create email with both HTML and text versions
        msg = EmailMultiAlternatives(subject, text_body, None, [email])
        msg.attach_alternative(html_body, "text/html")
        msg.send()
        
        # If this is an email confirmation, update the sent timestamp
        if template_prefix == 'account/email/email_confirmation':
            from allauth.account.models import EmailConfirmation
            from django.utils import timezone
            
            # Find the confirmation for this email
            try:
                confirmation = EmailConfirmation.objects.filter(
                    email_address__email=email,
                    sent__isnull=True
                ).order_by('-created').first()
                
                if confirmation:
                    confirmation.sent = timezone.now()
                    confirmation.save()
                    print(f'Updated sent timestamp for confirmation: {confirmation.key}')
            except Exception as e:
                print(f'Error updating confirmation sent timestamp: {e}')


class CustomSocialAccountAdapter(DefaultSocialAccountAdapter):
    """
    Custom social account adapter to handle organization assignment for social login users.
    """
    
    def is_auto_signup_allowed(self, request, sociallogin):
        """
        Prevent auto-signup if a user with the same email already exists.
        """
        email = sociallogin.account.extra_data.get('email')
        if email:
            from django.contrib.auth import get_user_model
            User = get_user_model()
            if User.objects.filter(email=email).exists():
                return False
        return super().is_auto_signup_allowed(request, sociallogin)
    
    def pre_social_login(self, request, sociallogin):
        """
        Called just after a user successfully authenticates via a social provider,
        but before the login is actually processed.
        """
        # Check if this is a new user (no existing account)
        if sociallogin.is_existing:
            return
        
        # For new users, we'll handle organization assignment in the post-login flow
        pass
    
    def save_user(self, request, sociallogin, form=None):
        """
        Save the user account and prepare for organization setup.
        """
        user = super().save_user(request, sociallogin, form)
        
        # Mark that this user needs organization setup
        request.session['needs_organization_setup'] = True
        
        return user
    
    def get_login_redirect_url(self, request, sociallogin):
        """
        Return the URL to redirect to after successful social login.
        """
        user = sociallogin.user
        if not user.organization:
            return reverse('accounts:social_organization_setup')
        return super().get_login_redirect_url(request, sociallogin)
    
    def get_connect_redirect_url(self, request, socialaccount):
        """
        Return the URL to redirect to after successfully connecting a social account.
        """
        user = request.user
        if not user.organization:
            return reverse('accounts:social_organization_setup')
        return super().get_connect_redirect_url(request, socialaccount)
