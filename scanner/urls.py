from django.urls import path
from . import views

urlpatterns = [
    path('', views.upload_contract, name='upload_contract'),
    path('history/', views.scan_history, name='scan_history'),
    path('detail/<str:session_id>/', views.scan_detail, name='scan_detail'),
    path('api/status/<str:session_id>/', views.api_scan_status, name='api_scan_status'),
    # Simulator
    path('simulator/', views.simulator, name='simulator'),
    path('api/diagrams/', views.api_diagram_list, name='api_diagram_list'),
    path('api/diagram/save/', views.api_diagram_save, name='api_diagram_save'),
    path('api/diagram/<uuid:diagram_id>/', views.api_diagram_get, name='api_diagram_get'),
    path('api/diagram/analyze/', views.api_diagram_analyze, name='api_diagram_analyze'),
    path('export/diagram/<uuid:diagram_id>/', views.export_diagram_json, name='export_diagram_json'),
    # Token Analyzer
    path('token/', views.token_analyzer, name='token_analyzer'),
    path('export/token/<str:address>/', views.export_token_report_pdf, name='export_token_report_pdf'),
]
