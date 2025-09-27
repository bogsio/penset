"""
Template tags for the accounts app.
"""

from django import template

register = template.Library()

@register.simple_tag(takes_context=True)
def has_targets(context):
    """
    Check if the user's organization has targets set.
    """
    user = context['user']
    if user.is_authenticated and hasattr(user, 'organization') and user.organization:
        targets = user.organization.targets
        return bool(targets and targets.strip() and targets.strip() != 'None')
    return True  # Default to True for unauthenticated users (modal won't show)
