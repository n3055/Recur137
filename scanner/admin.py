from django.contrib import admin
from django.utils.html import format_html
from .models import (
    ScanSession, Vulnerability, SecurityMetric, 
    AuditTrail, ComplianceFramework, ComplianceCheck
)

@admin.register(ScanSession)
class ScanSessionAdmin(admin.ModelAdmin):
    list_display = ['session_id', 'contract_name', 'risk_score', 'severity_level', 'status', 'scan_timestamp', 'scan_duration']
    list_filter = ['severity_level', 'status', 'scan_timestamp', 'risk_score']
    search_fields = ['session_id', 'contract_name', 'contract_hash']
    readonly_fields = ['id', 'scan_timestamp', 'scan_duration']
    ordering = ['-scan_timestamp']
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('session_id', 'contract_name', 'contract_hash', 'user')
        }),
        ('Scan Results', {
            'fields': ('risk_score', 'severity_level', 'status', 'scan_duration')
        }),
        ('Timestamps', {
            'fields': ('scan_timestamp',),
            'classes': ('collapse',)
        }),
    )

@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = ['title', 'vulnerability_type', 'severity', 'confidence', 'scan_session', 'detected_by']
    list_filter = ['severity', 'confidence', 'vulnerability_type', 'detected_by', 'scan_session__scan_timestamp']
    search_fields = ['title', 'description', 'cwe_id', 'scan_session__contract_name']
    readonly_fields = ['id']
    ordering = ['-severity', '-cvss_score']
    
    fieldsets = (
        ('Vulnerability Details', {
            'fields': ('title', 'vulnerability_type', 'description', 'severity', 'confidence')
        }),
        ('Technical Information', {
            'fields': ('cwe_id', 'cvss_score', 'line_number', 'code_snippet')
        }),
        ('Remediation', {
            'fields': ('remediation', 'references')
        }),
        ('Detection', {
            'fields': ('detected_by', 'scan_session')
        }),
    )

@admin.register(SecurityMetric)
class SecurityMetricAdmin(admin.ModelAdmin):
    list_display = ['scan_session', 'security_score', 'total_vulnerabilities', 'critical_vulnerabilities', 'compliance_score']
    list_filter = ['security_score', 'compliance_score', 'scan_session__scan_timestamp']
    search_fields = ['scan_session__contract_name']
    readonly_fields = ['id']
    
    fieldsets = (
        ('Vulnerability Counts', {
            'fields': ('total_vulnerabilities', 'critical_vulnerabilities', 'high_vulnerabilities', 'medium_vulnerabilities', 'low_vulnerabilities')
        }),
        ('Quality Metrics', {
            'fields': ('code_complexity', 'cyclomatic_complexity', 'maintainability_index')
        }),
        ('Scores', {
            'fields': ('security_score', 'gas_optimization_score', 'compliance_score')
        }),
        ('Session', {
            'fields': ('scan_session',)
        }),
    )

@admin.register(AuditTrail)
class AuditTrailAdmin(admin.ModelAdmin):
    list_display = ['action', 'scan_session', 'timestamp', 'ip_address', 'risk_assessment']
    list_filter = ['action', 'timestamp', 'scan_session__scan_timestamp']
    search_fields = ['action', 'details', 'scan_session__contract_name']
    readonly_fields = ['id', 'timestamp']
    ordering = ['-timestamp']
    
    fieldsets = (
        ('Audit Information', {
            'fields': ('action', 'scan_session', 'timestamp')
        }),
        ('Security Context', {
            'fields': ('user_agent', 'ip_address', 'risk_assessment')
        }),
        ('Details', {
            'fields': ('details',)
        }),
    )

@admin.register(ComplianceFramework)
class ComplianceFrameworkAdmin(admin.ModelAdmin):
    list_display = ['name', 'version', 'description']
    search_fields = ['name', 'description']
    readonly_fields = ['id']
    
    fieldsets = (
        ('Framework Information', {
            'fields': ('name', 'version', 'description')
        }),
        ('Requirements', {
            'fields': ('requirements',)
        }),
    )

@admin.register(ComplianceCheck)
class ComplianceCheckAdmin(admin.ModelAdmin):
    list_display = ['framework', 'requirement', 'status', 'scan_session']
    list_filter = ['status', 'framework', 'scan_session__scan_timestamp']
    search_fields = ['requirement', 'framework__name', 'scan_session__contract_name']
    readonly_fields = ['id']
    
    fieldsets = (
        ('Compliance Information', {
            'fields': ('framework', 'requirement', 'status')
        }),
        ('Assessment', {
            'fields': ('details', 'evidence')
        }),
        ('Session', {
            'fields': ('scan_session',)
        }),
    )

# Custom admin site configuration
admin.site.site_header = "Recur137 Cybersecurity Scanner Admin"
admin.site.site_title = "Recur137 Admin"
admin.site.index_title = "Smart Contract Security Analysis Dashboard"
