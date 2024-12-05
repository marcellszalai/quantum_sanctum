from django.urls import path
from . import views

urlpatterns = [
    path('process-cvc/', views.process_cvc, name='process_cvc'),  # Register the view
]