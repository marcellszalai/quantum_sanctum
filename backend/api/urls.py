from django.urls import path
from . import views

urlpatterns = [
    path('session/initiate', views.session_initiate, name='session_initiate'),
    path('data/upload', views.data_upload, name='data_upload'),
    path('data/list/<str:session_id>', views.list_uploaded_data, name='list_uploaded_data'),  # Added this
    path('data/retrieve', views.retrieve_data, name='retrieve_data'),
]