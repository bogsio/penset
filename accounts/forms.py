from django import forms
from django.contrib.auth.forms import UserCreationForm
from organizations.models import Organization


class CustomUserCreationForm(forms.Form):
    """
    Custom user creation form that uses email as username.
    """
    email = forms.EmailField(required=True)
    first_name = forms.CharField(max_length=30, required=True)
    last_name = forms.CharField(max_length=30, required=True)
    password1 = forms.CharField(
        label="Password",
        widget=forms.PasswordInput,
        min_length=8,
        help_text="Password must be at least 8 characters long."
    )
    password2 = forms.CharField(
        label="Password confirmation",
        widget=forms.PasswordInput,
        help_text="Enter the same password as before, for verification."
    )

    def clean_password2(self):
        password1 = self.cleaned_data.get("password1")
        password2 = self.cleaned_data.get("password2")
        if password1 and password2 and password1 != password2:
            raise forms.ValidationError("Passwords don't match")
        return password2

    def save(self, commit=True):
        from django.contrib.auth import get_user_model
        User = get_user_model()
        user = User.objects.create_user(
            username=self.cleaned_data['email'],
            email=self.cleaned_data['email'],
            password=self.cleaned_data['password1'],
            first_name=self.cleaned_data['first_name'],
            last_name=self.cleaned_data['last_name']
        )
        return user


class OrganizationCreationForm(forms.ModelForm):
    """
    Form for creating a new organization during registration.
    """
    class Meta:
        model = Organization
        fields = ['name', 'description', 'website', 'contact_email']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        # Configure each field with consistent styling and placeholders
        self.fields['name'].widget.attrs.update({
            'class': 'form-input w-full max-w-2xl',
            'placeholder': 'Organization name'
        })
        
        self.fields['description'].widget.attrs.update({
            'class': 'form-input w-full max-w-2xl',
            'placeholder': 'Organization description',
            'rows': 4
        })
        
        self.fields['website'].widget.attrs.update({
            'class': 'form-input w-full max-w-2xl',
            'placeholder': 'https://example.com'
        })
        
        self.fields['contact_email'].widget.attrs.update({
            'class': 'form-input w-full max-w-2xl',
            'placeholder': 'contact@example.com'
        })


class OrganizationForm(forms.ModelForm):
    """
    Form for updating organization properties.
    """
    class Meta:
        model = Organization
        fields = ['name', 'description', 'website', 'contact_email', 'targets']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        # Configure each field with consistent styling and placeholders
        self.fields['name'].widget.attrs.update({
            'class': 'form-input w-full max-w-2xl',
            'placeholder': 'Organization name'
        })
        
        self.fields['description'].widget.attrs.update({
            'class': 'form-input w-full max-w-2xl',
            'placeholder': 'Organization description',
            'rows': 4
        })
        
        self.fields['website'].widget.attrs.update({
            'class': 'form-input w-full max-w-2xl',
            'placeholder': 'https://example.com'
        })
        
        self.fields['contact_email'].widget.attrs.update({
            'class': 'form-input w-full max-w-2xl',
            'placeholder': 'contact@example.com'
        })
        
        self.fields['targets'].widget.attrs.update({
            'class': 'form-input w-full max-w-2xl',
            'placeholder': 'example.com, 192.168.1.1, https://app.example.com',
            'rows': 3
        })


class TargetInputForm(forms.Form):
    """
    Form for users to input targets for their organization.
    """
    targets = forms.CharField(
        widget=forms.Textarea(attrs={
            'class': 'form-input w-full',
            'placeholder': 'example.com, 192.168.1.1, https://app.example.com',
            'rows': 4
        }),
        help_text="Enter targets separated by commas. Examples: domains (example.com), IP addresses (192.168.1.1), or URLs (https://app.example.com)"
    )
    consent_checkbox = forms.BooleanField(
        required=True,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox'
        }),
        label="I confirm that I am authorized to scan these targets and understand the risks involved"
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        # Add link to documentation (placeholder for now)
        self.fields['consent_checkbox'].help_text = (
            'By checking this box, you confirm that you have proper authorization to scan the specified targets. '
            'Please review our <a href="#" class="text-blue-400 hover:text-blue-300 underline" target="_blank">scanning policy and legal guidelines</a> '
            'before proceeding. You understand that unauthorized scanning may violate laws and terms of service.'
        )