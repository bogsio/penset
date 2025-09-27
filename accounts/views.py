from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect, get_object_or_404
from django.conf import settings
from django.contrib import messages
from django.http import JsonResponse
from .models import User
from .forms import CustomUserCreationForm, OrganizationForm, OrganizationCreationForm, TargetInputForm
from organizations.models import Organization


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
                login(request, user)
                next_url = request.GET.get('next', '/')
                return redirect(next_url)
            else:
                messages.error(request, 'Invalid email or password.')
        else:
            messages.error(request, 'Please provide both email and password.')
    
    return render(request, 'accounts/login.html', {'debug': settings.DEBUG})


def register_page(request):
    """
    Serve the user registration page (step 1).
    """
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            # Store user data in session for step 2
            request.session['registration_data'] = {
                'email': form.cleaned_data['email'],
                'first_name': form.cleaned_data['first_name'],
                'last_name': form.cleaned_data['last_name'],
                'password': form.cleaned_data['password1']
            }
            return redirect('accounts:register_organization')
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
            # Create organization
            organization = form.save()
            
            # Create user with the stored data
            user = User.objects.create_user(
                username=registration_data['email'],  # Use email as username
                email=registration_data['email'],
                first_name=registration_data['first_name'],
                last_name=registration_data['last_name'],
                password=registration_data['password'],
                organization=organization
            )
            
            # Clear session data
            del request.session['registration_data']
            
            # Log the user in
            login(request, user)
            
            messages.success(request, 'Registration completed successfully!')
            return redirect('reports:dashboard')
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = OrganizationCreationForm()
    
    context = {
        'debug': settings.DEBUG,
        'form': form,
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
            
            if request.headers.get('X-Partial'):
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
            if request.headers.get('X-Partial'):
                # Return JSON response with errors for AJAX requests
                return JsonResponse({
                    'success': False,
                    'errors': form.errors
                }, status=400)
    else:
        form = TargetInputForm()
    
    # For GET requests, render the modal content
    if request.headers.get('X-Partial'):
        return render(request, 'partials/target_input_modal.html', {'form': form})
    else:
        return render(request, 'partials/target_input_modal.html', {'form': form})