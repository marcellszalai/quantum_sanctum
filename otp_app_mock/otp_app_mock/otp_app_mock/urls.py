from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('frontend.urls')),  # Include the frontend app's URLs
]