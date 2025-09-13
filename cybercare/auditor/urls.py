from django.urls import path
from . import views

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("export/pdf/", views.export_pdf, name="export_pdf"),
    path("export/json/", views.export_json, name="export_json"),
]
