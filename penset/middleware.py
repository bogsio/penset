"""
Custom middleware to fix ORB (Cross-Origin Read Blocking) issues.
"""

from django.utils.deprecation import MiddlewareMixin


class FixORBMiddleware(MiddlewareMixin):
    """
    Middleware to fix Cross-Origin Read Blocking (ORB) issues
    by setting proper headers for static files.
    """
    
    def process_response(self, request, response):
        # Only apply to static files
        if request.path.startswith('/static/'):
            # Set headers to prevent ORB blocking
            response['Cross-Origin-Embedder-Policy'] = 'unsafe-none'
            response['Cross-Origin-Opener-Policy'] = 'unsafe-none'
            response['Cross-Origin-Resource-Policy'] = 'cross-origin'
            
            # Ensure proper content type
            if request.path.endswith('.css'):
                response['Content-Type'] = 'text/css; charset=utf-8'
            elif request.path.endswith('.js'):
                response['Content-Type'] = 'application/javascript; charset=utf-8'
        
        return response


def add_orb_headers(headers, path, url):
    """
    Function to add ORB-fixing headers for WhiteNoise static files.
    """
    # Add headers to prevent ORB blocking
    headers['Cross-Origin-Embedder-Policy'] = 'unsafe-none'
    headers['Cross-Origin-Opener-Policy'] = 'unsafe-none'
    headers['Cross-Origin-Resource-Policy'] = 'cross-origin'
    
    # Ensure proper content type for CSS and JS files
    if path.endswith('.css'):
        headers['Content-Type'] = 'text/css; charset=utf-8'
    elif path.endswith('.js'):
        headers['Content-Type'] = 'application/javascript; charset=utf-8'
