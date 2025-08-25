from django.urls import path
from django.contrib.auth import views as auth_views
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('generate/', views.generate_challenge, name='generate_challenge'),
    path('verify/', views.verify_dns, name='verify_dns'),
    path('download/<str:domain>/<str:filetype>/', views.download_cert, name='download_cert'),
    path('dashboard/', views.dashboard, name='dashboard'),

    # Auth URLs
    path('accounts/login/', auth_views.LoginView.as_view(template_name='login.html'), name='login'),
    path('accounts/logout/', auth_views.LogoutView.as_view(next_page='login'), name='logout'),

]