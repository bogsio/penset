from django.urls import path
from . import views

app_name = 'accounts'

urlpatterns = [
    path('login/', views.login_page, name='login'),
    path('register/', views.register_page, name='register'),
    path('register/organization/', views.register_organization, name='register_organization'),
    path('logout/', views.logout_view, name='logout'),
    path('settings/', views.settings_page, name='settings'),
    path('update-targets/', views.update_targets, name='update_targets'),
]