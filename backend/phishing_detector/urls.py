from django.http import HttpResponse
from django.urls import path
from django.contrib import admin

from detector.views import detect_phishing

urlpatterns = [
    # Health Check
    path('health', lambda r: HttpResponse('OK')),

    path('admin/', admin.site.urls),
    path('api/v1/detect', detect_phishing, name='detect_phishing'),
]
