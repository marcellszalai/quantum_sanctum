from django.urls import path
from . import views

urlpatterns = [
    path('session/initiate', views.session_initiate, name='session_initiate'),
    path('session/verify', views.session_verify, name='session_verify'),
    path('data/upload', views.data_upload, name='data_upload'),
    path('data/retrieve', views.data_retrieve, name='data_retrieve'),
    path('session/health', views.session_health, name='session_health'),
    path('session/end', views.session_end, name='session_end'),
]