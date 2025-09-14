from django.db import models
from django.contrib.auth.models import User
import uuid
import json

class Diagram(models.Model):
    """Interactive Web3 architecture diagram stored as JSON"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    owner = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    data_json = models.TextField()
    security_score = models.FloatField(default=100.0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-updated_at']

    def get_data(self):
        try:
            return json.loads(self.data_json)
        except (json.JSONDecodeError, TypeError):
            return {}

    def set_data(self, payload):
        self.data_json = json.dumps(payload)

class ScanSession(models.Model):
    """Model to track complete scan sessions with cybersecurity metadata"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    session_id = models.CharField(max_length=100, unique=True)
    contract_name = models.CharField(max_length=255)
    contract_hash = models.CharField(max_length=64)  # SHA256 hash of contract
    scan_timestamp = models.DateTimeField(auto_now_add=True)
    scan_duration = models.FloatField(default=0.0)  # in seconds
    risk_score = models.FloatField(default=0.0)  # 0-100 risk assessment
    severity_level = models.CharField(max_length=20, choices=[
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical')
    ], default='LOW')
    status = models.CharField(max_length=20, choices=[
        ('PENDING', 'Pending'),
        ('RUNNING', 'Running'),
        ('COMPLETED', 'Completed'),
        ('FAILED', 'Failed')
    ], default='PENDING')
    
    class Meta:
        ordering = ['-scan_timestamp']

class Vulnerability(models.Model):
    """Model to store detailed vulnerability information"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan_session = models.ForeignKey(ScanSession, on_delete=models.CASCADE, related_name='vulnerabilities')
    vulnerability_type = models.CharField(max_length=100)
    title = models.CharField(max_length=255)
    description = models.TextField()
    severity = models.CharField(max_length=20, choices=[
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical')
    ])
    confidence = models.CharField(max_length=20, choices=[
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High')
    ])
    cwe_id = models.CharField(max_length=20, blank=True)  # Common Weakness Enumeration
    cvss_score = models.FloatField(null=True, blank=True)  # Common Vulnerability Scoring System
    line_number = models.IntegerField(null=True, blank=True)
    code_snippet = models.TextField(blank=True)
    remediation = models.TextField()
    references = models.TextField(blank=True)
    detected_by = models.CharField(max_length=50)  # 'slither', 'custom', 'mythril', etc.
    
    class Meta:
        ordering = ['-severity', '-cvss_score']

class SecurityMetric(models.Model):
    """Model to store comprehensive security metrics"""
    scan_session = models.OneToOneField(ScanSession, on_delete=models.CASCADE, related_name='security_metrics')
    total_vulnerabilities = models.IntegerField(default=0)
    critical_vulnerabilities = models.IntegerField(default=0)
    high_vulnerabilities = models.IntegerField(default=0)
    medium_vulnerabilities = models.IntegerField(default=0)
    low_vulnerabilities = models.IntegerField(default=0)
    code_complexity = models.FloatField(default=0.0)
    cyclomatic_complexity = models.IntegerField(default=0)
    maintainability_index = models.FloatField(default=0.0)
    security_score = models.FloatField(default=0.0)  # 0-100
    gas_optimization_score = models.FloatField(default=0.0)  # 0-100
    compliance_score = models.FloatField(default=0.0)  # 0-100

class AuditTrail(models.Model):
    """Model to maintain comprehensive audit trail for cybersecurity compliance"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan_session = models.ForeignKey(ScanSession, on_delete=models.CASCADE, related_name='audit_trails')
    action = models.CharField(max_length=100)
    timestamp = models.DateTimeField(auto_now_add=True)
    user_agent = models.TextField(blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    details = models.TextField(blank=True)
    risk_assessment = models.TextField(blank=True)

class ComplianceFramework(models.Model):
    """Model to track compliance with various security frameworks"""
    name = models.CharField(max_length=100)  # e.g., 'OWASP Top 10', 'NIST', 'ISO 27001'
    version = models.CharField(max_length=20)
    description = models.TextField()
    requirements = models.TextField()  # Store as JSON string for SQLite compatibility
    
    def get_requirements(self):
        """Get requirements as a Python object"""
        try:
            return json.loads(self.requirements)
        except (json.JSONDecodeError, TypeError):
            return {}
    
    def set_requirements(self, requirements_dict):
        """Set requirements from a Python object"""
        self.requirements = json.dumps(requirements_dict)
    
    def __str__(self):
        return f"{self.name} v{self.version}"

class ComplianceCheck(models.Model):
    """Model to track compliance checks against frameworks"""
    scan_session = models.ForeignKey(ScanSession, on_delete=models.CASCADE, related_name='compliance_checks')
    framework = models.ForeignKey(ComplianceFramework, on_delete=models.CASCADE)
    requirement = models.CharField(max_length=100)
    status = models.CharField(max_length=20, choices=[
        ('PASS', 'Pass'),
        ('FAIL', 'Fail'),
        ('PARTIAL', 'Partial'),
        ('NOT_APPLICABLE', 'Not Applicable')
    ])
    details = models.TextField()
    evidence = models.TextField(blank=True)
