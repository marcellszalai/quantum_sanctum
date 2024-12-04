from django.urls import path
from . import views

urlpatterns = [
    path('session/initiate', views.session_initiate, name='session_initiate'),
    path('session/finalize', views.session_finalize, name='session_finalize'),
    path('data/upload', views.data_upload, name='data_upload'),
    path('data/retrieve', views.data_retrieve, name='data_retrieve'),
]