from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import PasswordChangeForm
from django.shortcuts import render, redirect, get_object_or_404
from django.conf import settings
from django.contrib import messages
from django.http import JsonResponse
from .models import User
from .forms import CustomUserCreationForm, OrganizationForm, OrganizationCreationForm, TargetInputForm
from organizations.models import Organization
from allauth.account.views import SignupView, ConfirmEmailView
from allauth.socialaccount.views import SignupView as SocialSignupView
from allauth.account.models import EmailAddress
from allauth.account.utils import send_email_confirmation


def login_page(request):
    """
    Serve the login page.
    """
    if request.method == 'POST':
        email = request.POST.get('username')  # Form field is named 'username' but contains email
        password = request.POST.get('password')
        
        if email and password:
            # Try to authenticate using email as username
            user = authenticate(request, username=email, password=password)
            if user is not None:
                # Check if user's email is verified
                try:
                    email_address = EmailAddress.objects.get(user=user, email=user.email)
                    if not email_address.verified:
                        # Send verification email automatically
                        send_email_confirmation(request, user)
                        messages.info(request, 'Your email address is not verified. A new verification email has been sent to your inbox. Please check your email and click the verification link to activate your account.')
                        return render(request, 'accounts/login.html', {'debug': settings.DEBUG})
                except EmailAddress.DoesNotExist:
                    # If no EmailAddress record exists, create one and send verification email
                    email_address = EmailAddress.objects.create(
                        user=user,
                        email=user.email,
                        verified=False,
                        primary=True
                    )
                    send_email_confirmation(request, user)
                    messages.info(request, 'Your email address is not verified. A verification email has been sent to your inbox. Please check your email and click the verification link to activate your account.')
                    return render(request, 'accounts/login.html', {'debug': settings.DEBUG})
                
                # Email is verified, proceed with login
                login(request, user, backend='django.contrib.auth.backends.ModelBackend')
                next_url = request.GET.get('next', '/')
                return redirect(next_url)
            else:
                messages.error(request, 'Invalid email or password.')
        else:
            messages.error(request, 'Please provide both email and password.')
    
    return render(request, 'accounts/login.html', {'debug': settings.DEBUG})


def register_page(request):
    """
    Serve the user registration page (step 1) with email verification.
    """
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            # Check if user already exists
            if User.objects.filter(email=form.cleaned_data['email']).exists():
                messages.error(request, 'A user with this email address already exists. Please use a different email or try logging in.')
                return render(request, 'accounts/register.html', {'debug': settings.DEBUG, 'form': form})
            
            # Create user but don't activate yet
            user = User.objects.create_user(
                username=form.cleaned_data['email'],
                email=form.cleaned_data['email'],
                first_name=form.cleaned_data['first_name'],
                last_name=form.cleaned_data['last_name'],
                password=form.cleaned_data['password1'],
                is_active=False  # User will be activated after email verification
            )
            
            # Create email address record for allauth
            email_address = EmailAddress.objects.create(
                user=user,
                email=user.email,
                primary=True,
                verified=False
            )
            
            # Send verification email
            from allauth.account.utils import send_email_confirmation
            send_email_confirmation(request, user, signup=True)
            
            messages.success(request, 'Registration successful! Please check your email and click the verification link to complete your registration.')
            return redirect('accounts:verification_sent', email=form.cleaned_data['email'])
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = CustomUserCreationForm()
    
    context = {
        'debug': settings.DEBUG,
        'form': form,
    }
    
    return render(request, 'accounts/register.html', context)


def register_organization(request):
    """
    Serve the organization registration page (step 2).
    """
    # Check if we have registration data from step 1
    registration_data = request.session.get('registration_data')
    if not registration_data:
        messages.error(request, 'Please complete user registration first.')
        return redirect('accounts:register')
    
    if request.method == 'POST':
        form = OrganizationCreationForm(request.POST)
        if form.is_valid():
            # Check if user already exists
            if User.objects.filter(email=registration_data['email']).exists():
                messages.error(request, 'A user with this email address already exists. Please use a different email or try logging in.')
                return redirect('accounts:register')
            
            try:
                # Create organization
                organization = form.save()
                
                # Create user with the stored data
                user = User.objects.create_user(
                    username=registration_data['email'],  # Use email as username
                    email=registration_data['email'],
                    first_name=registration_data['first_name'],
                    last_name=registration_data['last_name'],
                    password=registration_data['password'],
                    organization=organization,
                    is_organization_admin=True
                )
                
                # Clear session data
                del request.session['registration_data']
                
                # Log the user in
                login(request, user, backend='django.contrib.auth.backends.ModelBackend')
                
                messages.success(request, 'Registration completed successfully!')
                return redirect('reports:dashboard')
                
            except Exception as e:
                # Handle any database errors
                messages.error(request, f'Registration failed: {str(e)}. Please try again.')
                return render(request, 'accounts/register_organization.html', {
                    'debug': settings.DEBUG,
                    'form': form,
                    'user': request.user,
                })
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = OrganizationCreationForm()
    
    context = {
        'debug': settings.DEBUG,
        'form': form,
        'user': request.user,  # Pass user to template
    }
    
    return render(request, 'accounts/register_organization.html', context)


def logout_view(request):
    """
    Log out the user and redirect to login page.
    """
    logout(request)
    return redirect('accounts:login')


@login_required(login_url='/accounts/login/')
def settings_page(request):
    """
    Settings page for managing organization properties.
    """
    # Check if user can manage organization
    if not request.user.can_manage_organization():
        messages.error(request, 'You do not have permission to manage organization settings.')
        return redirect('reports:dashboard')
    
    organization = request.user.organization
    if not organization:
        messages.error(request, 'You are not associated with any organization.')
        return redirect('reports:dashboard')
    
    if request.method == 'POST':
        form = OrganizationForm(request.POST, instance=organization)
        if form.is_valid():
            form.save()
            messages.success(request, 'Organization settings updated successfully.')
            return redirect('accounts:settings')
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = OrganizationForm(instance=organization)
    
    context = {
        'debug': settings.DEBUG,
        'user': request.user,
        'organization': organization,
        'form': form,
    }
    
    return render(request, 'accounts/settings.html', context)


@login_required(login_url='/accounts/login/')
def update_targets(request):
    """
    Handle target updates for the organization.
    """
    if request.method == 'POST':
        form = TargetInputForm(request.POST)
        if form.is_valid():
            # Update organization targets
            organization = request.user.organization
            organization.targets = form.cleaned_data['targets']
            organization.save()
            
            if request.headers.get('X-Partial') or request.META.get('HTTP_X_PARTIAL'):
                # Return JSON response for AJAX requests
                return JsonResponse({
                    'success': True,
                    'message': 'Targets updated successfully!'
                })
            else:
                messages.success(request, 'Targets updated successfully!')
                # Redirect back to the referring page or dashboard
                next_url = request.META.get('HTTP_REFERER', '/')
                return redirect(next_url)
        else:
            if request.headers.get('X-Partial') or request.META.get('HTTP_X_PARTIAL'):
                # Return JSON response with errors for AJAX requests
                return JsonResponse({
                    'success': False,
                    'errors': form.errors
                }, status=400)
    else:
        form = TargetInputForm()
    
    # For GET requests, render the modal content
    if request.headers.get('X-Partial') or request.META.get('HTTP_X_PARTIAL'):
        return render(request, 'partials/target_input_modal.html', {'form': form})
    else:
        return render(request, 'partials/target_input_modal.html', {'form': form})


@login_required(login_url='/accounts/login/')
def social_organization_setup(request):
    """
    Handle organization setup for users who don't have an organization.
    This includes both social login users and email verification users.
    """
    # Check if user already has an organization
    if request.user.organization:
        messages.info(request, 'You already have an organization assigned.')
        return redirect('reports:dashboard')

    if request.method == 'POST':
        form = OrganizationCreationForm(request.POST)
        if form.is_valid():
            # Create organization
            organization = form.save()

            # Assign organization to user and make them admin
            request.user.organization = organization
            request.user.is_organization_admin = True
            request.user.role = 'admin'
            request.user.is_active = True  # Activate user after organization setup
            request.user.save()

            # Clear the session flag
            if 'needs_organization_setup' in request.session:
                del request.session['needs_organization_setup']

            messages.success(request, f'Welcome to {organization.name}! You have been set as the organization administrator.')
            return redirect('reports:dashboard')
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = OrganizationCreationForm()

    context = {
        'debug': settings.DEBUG,
        'form': form,
        'user': request.user,
    }

    return render(request, 'accounts/register_organization.html', context)


def resend_verification_email(request):
    """
    Handle resending verification emails.
    """
    if request.method == 'POST':
        email = request.POST.get('email')
        if email:
            try:
                user = User.objects.get(email=email)
                email_address = EmailAddress.objects.get(user=user, email=email)
                
                if not email_address.verified:
                    # Send verification email
                    send_email_confirmation(request, user, signup=True)
                    
                    # In DEBUG mode, try to open the email file in a new tab
                    if settings.DEBUG:
                        import os
                        import glob
                        from django.http import JsonResponse
                        
                        # Find the most recent email file
                        email_dir = settings.BASE_DIR / 'emails'
                        if email_dir.exists():
                            email_files = glob.glob(str(email_dir / '*.html'))
                            if email_files:
                                # Get the most recent file
                                latest_file = max(email_files, key=os.path.getctime)
                                # Return JSON with the file path for JavaScript to open
                                return JsonResponse({
                                    'success': True,
                                    'message': 'Verification email has been resent.',
                                    'email_file': f'/emails/{os.path.basename(latest_file)}'
                                })
                    
                    messages.success(request, 'Verification email has been resent. Please check your inbox.')
                else:
                    messages.info(request, 'This email address is already verified.')
                    
            except User.DoesNotExist:
                messages.error(request, 'No account found with this email address.')
            except EmailAddress.DoesNotExist:
                messages.error(request, 'No email address record found.')
        else:
            messages.error(request, 'Please provide an email address.')
    
    return redirect('accounts:verification_sent', email=request.POST.get('email', ''))


def verification_sent(request, email):
    """
    Show the verification sent page with the email address.
    """
    context = {
        'email': email,
        'debug': settings.DEBUG,
    }
    return render(request, 'account/verification_sent.html', context)


class CustomConfirmEmailView(ConfirmEmailView):
    """
    Custom email confirmation view that handles organization setup.
    """
    
    def get(self, *args, **kwargs):
        # Get the confirmation object
        self.object = self.get_object()
        
        # Call the confirm method to actually verify the email
        if self.object:
            self.object.confirm(self.request)
        
        # If confirmation was successful, check if user needs organization setup
        if hasattr(self, 'object') and self.object:
            # Get the user from the email confirmation object
            user = self.object.email_address.user
            
            # Activate the user
            user.is_active = True
            user.save()
            
            # If user doesn't have an organization, redirect to setup
            if not user.organization:
                from django.shortcuts import redirect
                from django.contrib.auth import login
                
                # Log the user in
                login(self.request, user, backend='django.contrib.auth.backends.ModelBackend')
                
                # Store in session that this user needs organization setup
                self.request.session['needs_organization_setup'] = True
                
                # Redirect to organization setup
                return redirect('accounts:social_organization_setup')
        
        # Call the parent get method to handle the response
        return super().get(*args, **kwargs)


class CustomSocialSignupView(SocialSignupView):
    """
    Custom social signup view to handle duplicate email errors gracefully.
    """
    
    def dispatch(self, request, *args, **kwargs):
        try:
            return super().dispatch(request, *args, **kwargs)
        except Exception as e:
            # Check if this is a duplicate email error
            if 'UNIQUE constraint failed: users.email' in str(e):
                messages.error(
                    request,
                    'An account with this email address already exists. Please log in with your password or use a different Google account.'
                )
                return redirect('accounts:login')
            else:
                # Re-raise other exceptions
                raise e


@login_required
def user_settings_page(request):
    """
    User settings page for profile management and password changes.
    """
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, 'Your password has been changed successfully.')
            return redirect('accounts:user_settings')
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = PasswordChangeForm(request.user)
    
    # Add styling to form fields
    for field in form.fields.values():
        field.widget.attrs.update({
            'class': 'form-input w-full max-w-2xl',
            'placeholder': field.label
        })
    
    context = {
        'form': form,
    }
    return render(request, 'accounts/user_settings.html', context)


@login_required
def billing_page(request):
    """
    Billing page for subscription and payment management.
    """
    context = {}
    return render(request, 'accounts/billing.html', context)