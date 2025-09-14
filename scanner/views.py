from django.shortcuts import render, redirect, get_object_or_404
from django.core.files.storage import FileSystemStorage
from django.conf import settings
from django.contrib import messages
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils import timezone
from django.db import transaction
from django.template.loader import render_to_string
import subprocess
import os
import re
import json
import hashlib
import time
import ast
import logging
from datetime import datetime
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import uuid
from collections import deque
try:
    from eth_utils import keccak
except Exception:
    keccak = None

import networkx as nx

from .models import (
    Diagram,
    ScanSession, Vulnerability, SecurityMetric, 
    AuditTrail, ComplianceFramework, ComplianceCheck
)

# Configure logging
logger = logging.getLogger(__name__)

# Simple in-process rate limiter for Etherscan (2 calls/second)
_ETHERSCAN_LOCK = threading.Lock()
_ETHERSCAN_CALLS = deque()
_ETHERSCAN_RATE = 2
_ETHERSCAN_WINDOW = 1.0


class DiagramAnalyzer:
    """Analyze diagram JSON for insecure patterns using NetworkX and external intel"""

    def __init__(self, forta_api_key: str | None = None, chainalysis_api_key: str | None = None):
        self.forta_api_key = forta_api_key or os.environ.get('FORTA_API_KEY')
        self.chainalysis_api_key = chainalysis_api_key or os.environ.get('CHAINALYSIS_API_KEY')

    def parse_graph(self, diagram: dict) -> nx.DiGraph:
        graph = nx.DiGraph()
        for node in diagram.get('nodes', []):
            node_id = str(node.get('id') or node.get('data', {}).get('id'))
            label = node.get('label') or node.get('data', {}).get('label')
            node_type = node.get('type') or node.get('data', {}).get('type')
            address = node.get('address') or node.get('data', {}).get('address')
            verified = node.get('verified', False) or node.get('data', {}).get('verified', False)
            graph.add_node(node_id, label=label, type=node_type, address=address, verified=bool(verified))
        for edge in diagram.get('edges', []):
            source = str(edge.get('source'))
            target = str(edge.get('target'))
            action = edge.get('label') or edge.get('data', {}).get('label') or edge.get('action')
            graph.add_edge(source, target, label=action)
        return graph

    def run_rules(self, graph: nx.DiGraph) -> list[dict]:
        issues: list[dict] = []

        def add_issue(severity: str, title: str, detail: str, nodes=None, edges=None, rule_id: str = ""):
            issues.append({
                'severity': severity,
                'title': title,
                'detail': detail,
                'nodes': list(nodes or []),
                'edges': list(edges or []),
                'rule_id': rule_id,
            })

        # Phishing Flow: Wallet -> Unverified Contract -> External Wallet
        for u, v in graph.edges:
            u_type = graph.nodes[u].get('type')
            v_type = graph.nodes[v].get('type')
            if u_type == 'Wallet' and v_type in ['Smart Contract', 'Contract'] and not graph.nodes[v].get('verified', False):
                # Check next hop to external wallet
                for _, w in graph.out_edges(v):
                    if graph.nodes[w].get('type') in ['Wallet', 'External Wallet', 'EOA'] and (graph[u][v].get('label') or '').lower() in ['approve', 'transfer', 'call', 'sign']:
                        add_issue('HIGH', 'Potential phishing flow', 'Wallet interacts with unverified contract forwarding to external wallet', [u, v, w], [(u, v), (v, w)], 'RULE_PHISHING_FLOW')

        # Infinite approval loop: detect cycles containing edges labeled 'approve'
        try:
            cycles = list(nx.simple_cycles(graph))
            for cycle in cycles:
                cycle_edges = [(cycle[i], cycle[(i + 1) % len(cycle)]) for i in range(len(cycle))]
                if any(((graph[e[0]][e[1]].get('label') or '').lower() == 'approve') for e in cycle_edges):
                    add_issue('MEDIUM', 'Infinite approval loop', 'Cycle contains approval edges without exits', cycle, cycle_edges, 'RULE_APPROVAL_LOOP')
        except nx.NetworkXNoCycle:
            pass

        # Unchecked bridge transfers: Bridge node with outgoing transfers to multiple chains without verification
        for n, data in graph.nodes(data=True):
            if (data.get('type') or '').lower() == 'bridge':
                outgoing = list(graph.out_edges(n))
                transfer_like = [e for e in outgoing if (graph[e[0]][e[1]].get('label') or '').lower() in ['bridge', 'transfer', 'lock', 'mint']]
                if len(transfer_like) >= 1 and not data.get('verified', False):
                    add_issue('HIGH', 'Unchecked bridge transfers', 'Bridge has transfer flows but is unverified', [n], transfer_like, 'RULE_UNCHECKED_BRIDGE')

        # Centralized SPOF: high betweenness centrality
        if graph.number_of_nodes() >= 3 and graph.number_of_edges() >= 2:
            bc = nx.betweenness_centrality(graph)
            if bc:
                threshold = max(bc.values()) * 0.75
                for node_id, score in bc.items():
                    if score >= threshold and score > 0:
                        add_issue('MEDIUM', 'Single point of failure', f'Node has high betweenness centrality ({score:.2f})', [node_id], [], 'RULE_SPOF')

        # Cyclical fund flows (Ponzi-like): cycles of transfer actions
        try:
            cycles = list(nx.simple_cycles(graph))
            for cycle in cycles:
                cycle_edges = [(cycle[i], cycle[(i + 1) % len(cycle)]) for i in range(len(cycle))]
                if all(((graph[e[0]][e[1]].get('label') or '').lower() in ['transfer', 'swap', 'stake', 'unstake']) for e in cycle_edges):
                    add_issue('HIGH', 'Cyclical fund flow', 'Detected cycle of fund movements', cycle, cycle_edges, 'RULE_CYCLE_FUNDS')
        except nx.NetworkXNoCycle:
            pass

        return issues

    def intel_checks(self, graph: nx.DiGraph, timeout_seconds: int = 5) -> list[dict]:
        findings: list[dict] = []

        addresses = [data.get('address') for _, data in graph.nodes(data=True) if data.get('address')]
        addresses = list({a for a in addresses if a})
        if not addresses:
            return findings

        def forta_lookup(addr: str):
            try:
                if not self.forta_api_key:
                    return None
                headers = { 'Authorization': f'Bearer {self.forta_api_key}' }
                url = 'https://api.forta.network/alerts/for-address'
                params = { 'address': addr, 'chainId': '1', 'limit': 1 }
                resp = requests.get(url, headers=headers, params=params, timeout=timeout_seconds)
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get('alerts'):
                        return { 'address': addr, 'severity': 'HIGH', 'source': 'Forta', 'title': 'Forta alerts found', 'detail': 'Recent alert(s) associated with address' }
            except Exception:
                return None
            return None

        def chainalysis_lookup(addr: str):
            try:
                if not self.chainalysis_api_key:
                    return None
                headers = { 'Token': self.chainalysis_api_key }
                url = f'https://public.chainalysis.com/risk/v2/entity/{addr}'
                resp = requests.get(url, headers=headers, timeout=timeout_seconds)
                if resp.status_code == 200:
                    data = resp.json()
                    risk = (data.get('data') or {}).get('risk', {}).get('severity')
                    if risk in ['Severe', 'High']:
                        sev = 'CRITICAL' if risk == 'Severe' else 'HIGH'
                        return { 'address': addr, 'severity': sev, 'source': 'Chainalysis', 'title': 'High risk address', 'detail': f'Risk severity: {risk}' }
            except Exception:
                return None
            return None

        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = []
            for a in addresses:
                futures.append(executor.submit(forta_lookup, a))
                futures.append(executor.submit(chainalysis_lookup, a))
            for fut in as_completed(futures):
                res = fut.result()
                if res:
                    findings.append(res)
        return findings

    def analyze(self, diagram: dict) -> dict:
        graph = self.parse_graph(diagram)
        rule_issues = self.run_rules(graph)
        intel_issues = self.intel_checks(graph)

        # Optional smart contract analysis if source is attached to nodes
        code_issues: list[dict] = []
        try:
            analyzer = AdvancedSecurityAnalyzer()
            for node in diagram.get('nodes', []):
                source_code = node.get('source_code') or (node.get('data', {}) if isinstance(node.get('data'), dict) else {}).get('source_code')
                source_path = node.get('source_path') or (node.get('data', {}) if isinstance(node.get('data'), dict) else {}).get('source_path')
                if source_code and not source_path:
                    # Write temp solidity file
                    filename = f"diagram-{uuid.uuid4().hex}.sol"
                    file_path = os.path.join(settings.MEDIA_ROOT, filename)
                    try:
                        with open(file_path, 'w', encoding='utf-8') as f:
                            f.write(source_code)
                        source_path = file_path
                    except Exception:
                        source_path = None
                if source_path and os.path.exists(source_path):
                    try:
                        slither_findings, _ = analyzer.run_slither_analysis(source_path)
                    except Exception:
                        slither_findings = []
                    try:
                        mythril_findings = analyzer.run_mythril_analysis(source_path)
                    except Exception:
                        mythril_findings = []
                    try:
                        echidna_findings = analyzer.run_echidna_analysis(source_path)
                    except Exception:
                        echidna_findings = []
                    for fnd in (slither_findings + mythril_findings + echidna_findings):
                        code_issues.append({
                            'severity': fnd.get('severity', 'MEDIUM'),
                            'title': fnd.get('title', 'Contract issue'),
                            'detail': fnd.get('description', ''),
                            'nodes': [str(node.get('id'))],
                            'edges': [],
                            'rule_id': fnd.get('detected_by', 'CODE')
                        })
        except Exception:
            pass

        all_issues = rule_issues + code_issues + [
            {
                'severity': i['severity'],
                'title': i['title'],
                'detail': i['detail'],
                'nodes': [],
                'edges': [],
                'rule_id': i.get('source', 'INTEL')
            } for i in intel_issues
        ]

        severity_weights = { 'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1 }
        if all_issues:
            avg_weight = sum(severity_weights.get(i['severity'], 2) for i in all_issues) / len(all_issues)
            security_score = max(0, 100 - avg_weight * 15)
        else:
            security_score = 100.0

        return { 'issues': all_issues, 'security_score': round(security_score, 1) }

class AdvancedSecurityAnalyzer:
    """Advanced cybersecurity analyzer for smart contracts"""
    
    def __init__(self):
        self.vulnerability_patterns = {
            'reentrancy': {
                'pattern': r'\.call\{value:\s*[^}]*\}\s*\([^)]*\)',
                'severity': 'CRITICAL',
                'cwe_id': 'CWE-841',
                'cvss_score': 9.8,
                'description': 'Reentrancy vulnerability allows external calls before state updates',
                'remediation': 'Implement checks-effects-interactions pattern and use ReentrancyGuard'
            },
            'tx_origin': {
                'pattern': r'\btx\.origin\b',
                'severity': 'HIGH',
                'cwe_id': 'CWE-345',
                'cvss_score': 7.5,
                'description': 'tx.origin can be manipulated by malicious contracts',
                'remediation': 'Use msg.sender instead of tx.origin for authorization'
            },
            'timestamp_dependency': {
                'pattern': r'\b(block\.timestamp|now)\b',
                'severity': 'MEDIUM',
                'cwe_id': 'CWE-367',
                'cvss_score': 5.3,
                'description': 'Block timestamp can be manipulated by miners',
                'remediation': 'Avoid using block.timestamp for critical decisions'
            },
            'unchecked_calls': {
                'pattern': r'\.call\([^)]*\)(?!\s*require)',
                'severity': 'MEDIUM',
                'cwe_id': 'CWE-252',
                'cvss_score': 5.0,
                'description': 'Unchecked external calls may fail silently',
                'remediation': 'Always check return values of external calls'
            },
            'integer_overflow': {
                'pattern': r'(\w+)\s*\+\s*(\w+)',
                'severity': 'HIGH',
                'cwe_id': 'CWE-190',
                'cvss_score': 7.5,
                'description': 'Potential integer overflow in arithmetic operations',
                'remediation': 'Use SafeMath library or Solidity 0.8+ built-in checks'
            },
            'access_control': {
                'pattern': r'function\s+\w+\([^)]*\)\s*(?:public|external)',
                'severity': 'MEDIUM',
                'cwe_id': 'CWE-284',
                'cvss_score': 6.5,
                'description': 'Public functions without access control',
                'remediation': 'Implement proper access control modifiers'
            },
            'gas_limit': {
                'pattern': r'for\s*\([^)]*\)\s*\{[^}]*\}',
                'severity': 'LOW',
                'cwe_id': 'CWE-400',
                'cvss_score': 3.1,
                'description': 'Unbounded loops may exceed gas limit',
                'remediation': 'Limit loop iterations or use pagination'
            }
        }
        
        self.compliance_frameworks = {
            'OWASP_Top_10': {
                'version': '2021',
                'requirements': [
                    'A01:2021 – Broken Access Control',
                    'A02:2021 – Cryptographic Failures',
                    'A03:2021 – Injection',
                    'A04:2021 – Insecure Design',
                    'A05:2021 – Security Misconfiguration',
                    'A06:2021 – Vulnerable Components',
                    'A07:2021 – Authentication Failures',
                    'A08:2021 – Software and Data Integrity Failures',
                    'A09:2021 – Logging Failures',
                    'A10:2021 – Server-Side Request Forgery'
                ]
            },
            'NIST_Cybersecurity': {
                'version': '2.0',
                'requirements': [
                    'Identify',
                    'Protect',
                    'Detect',
                    'Respond',
                    'Recover'
                ]
            }
        }
    
    def calculate_contract_hash(self, source_code):
        """Calculate SHA256 hash of contract source code"""
        return hashlib.sha256(source_code.encode()).hexdigest()
    
    def analyze_code_complexity(self, source_code):
        """Analyze code complexity metrics"""
        try:
            lines = source_code.split('\n')
            total_lines = len(lines)
            comment_lines = len([line for line in lines if line.strip().startswith('//') or line.strip().startswith('/*')])
            code_lines = total_lines - comment_lines
            
            # Simple cyclomatic complexity calculation
            complexity = 1  # Base complexity
            complexity += len(re.findall(r'\b(if|while|for|switch|case|catch|&&|\|\|)\b', source_code))
            
            # Maintainability index (simplified)
            maintainability = max(0, 100 - (complexity * 10) - (total_lines * 0.1))
            
            return {
                'total_lines': total_lines,
                'code_lines': code_lines,
                'comment_lines': comment_lines,
                'cyclomatic_complexity': complexity,
                'maintainability_index': maintainability
            }
        except Exception as e:
            logger.error(f"Error analyzing code complexity: {str(e)}")
            # Return default values if analysis fails
            return {
                'total_lines': 0,
                'code_lines': 0,
                'comment_lines': 0,
                'cyclomatic_complexity': 1,
                'maintainability_index': 100
            }
    
    def detect_vulnerabilities(self, source_code):
        """Advanced vulnerability detection using multiple patterns"""
        vulnerabilities = []
        
        try:
            for vuln_type, config in self.vulnerability_patterns.items():
                matches = re.finditer(config['pattern'], source_code, re.MULTILINE)
                
                for match in matches:
                    line_number = source_code[:match.start()].count('\n') + 1
                    code_snippet = self.extract_code_snippet(source_code, line_number)
                    
                    vulnerability = {
                        'vulnerability_type': vuln_type,
                        'title': f'{vuln_type.title()} Vulnerability',
                        'description': config['description'],
                        'severity': config['severity'],
                        'confidence': 'HIGH' if vuln_type in ['reentrancy', 'tx_origin'] else 'MEDIUM',
                        'cwe_id': config['cwe_id'],
                        'cvss_score': config['cvss_score'],
                        'line_number': line_number,
                        'code_snippet': code_snippet,
                        'remediation': config['remediation'],
                        'references': f'https://cwe.mitre.org/data/definitions/{config["cwe_id"].split("-")[1]}.html',
                        'detected_by': 'custom_analyzer'
                    }
                    vulnerabilities.append(vulnerability)
        except Exception as e:
            logger.error(f"Error detecting vulnerabilities: {str(e)}")
        
        return vulnerabilities
    
    def extract_code_snippet(self, source_code, line_number, context_lines=3):
        """Extract code snippet around the specified line"""
        try:
            lines = source_code.split('\n')
            start = max(0, line_number - context_lines - 1)
            end = min(len(lines), line_number + context_lines)
            
            snippet_lines = []
            for i in range(start, end):
                marker = '>>> ' if i == line_number - 1 else '    '
                snippet_lines.append(f'{marker}{i+1:3d}: {lines[i]}')
            
            return '\n'.join(snippet_lines)
        except Exception as e:
            logger.error(f"Error extracting code snippet: {str(e)}")
            return "Code snippet not available"
    
    def run_slither_analysis(self, file_path):
        """Run Slither analysis with comprehensive output"""
        try:
            # Run Slither with multiple output formats
            slither_json_path = os.path.join(settings.MEDIA_ROOT, f'slither-output-{int(time.time())}.json')
            
            result = subprocess.run([
                'slither', file_path, 
                '--json', slither_json_path,
                '--disable-color',
                '--exclude-informational',
                '--exclude-low'
            ], capture_output=True, text=True, timeout=300)
            
            if os.path.exists(slither_json_path):
                with open(slither_json_path, 'r') as f:
                    slither_data = json.load(f)
                
                # Parse Slither findings
                findings = []
                for detector in slither_data.get('results', {}).get('detectors', []):
                    finding = {
                        'vulnerability_type': detector.get('check', 'unknown'),
                        'title': detector.get('title', 'Unknown Issue'),
                        'description': detector.get('description', ''),
                        'severity': self.map_slither_severity(detector.get('impact', 'Informational')),
                        'confidence': self.map_slither_confidence(detector.get('confidence', 'Medium')),
                        'cwe_id': detector.get('cwe', ''),
                        'cvss_score': self.calculate_cvss_from_slither(detector),
                        'line_number': detector.get('elements', [{}])[0].get('line', None) if detector.get('elements') else None,
                        'code_snippet': self.extract_slither_snippet(detector),
                        'remediation': detector.get('recommendation', ''),
                        'references': detector.get('reference', ''),
                        'detected_by': 'slither'
                    }
                    findings.append(finding)
                
                return findings, result.stdout + result.stderr
            else:
                return [], f"Slither analysis failed: {result.stderr}"
                
        except subprocess.TimeoutExpired:
            return [], "Slither analysis timed out after 5 minutes"
        except Exception as e:
            logger.error(f"Slither analysis error: {str(e)}")
            return [], f"Slither analysis error: {str(e)}"
    
    def map_slither_severity(self, slither_impact):
        """Map Slither impact to our severity levels"""
        mapping = {
            'High': 'HIGH',
            'Medium': 'MEDIUM',
            'Low': 'LOW',
            'Informational': 'LOW'
        }
        return mapping.get(slither_impact, 'MEDIUM')
    
    def map_slither_confidence(self, slither_confidence):
        """Map Slither confidence to our confidence levels"""
        mapping = {
            'High': 'HIGH',
            'Medium': 'MEDIUM',
            'Low': 'LOW'
        }
        return mapping.get(slither_confidence, 'MEDIUM')
    
    def calculate_cvss_from_slither(self, detector):
        """Calculate CVSS score from Slither detector information"""
        base_score = 5.0  # Default medium score
        
        # Adjust based on impact and confidence
        if detector.get('impact') == 'High':
            base_score += 2.0
        elif detector.get('impact') == 'Low':
            base_score -= 2.0
        
        if detector.get('confidence') == 'High':
            base_score += 1.0
        elif detector.get('confidence') == 'Low':
            base_score -= 1.0
        
        return max(0.0, min(10.0, base_score))
    
    def extract_slither_snippet(self, detector):
        """Extract code snippet from Slither detector"""
        if detector.get('elements'):
            element = detector['elements'][0]
            if 'source_mapping' in element:
                # This would require parsing source mapping for exact code extraction
                return f"Function: {element.get('name', 'Unknown')}"
        return "Code snippet not available"
    
    def run_mythril_analysis(self, file_path):
        """Run Mythril analysis for additional security insights"""
        try:
            # Check if mythril is available
            result = subprocess.run(['myth', '--version'], capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                logger.warning("Mythril not available, skipping analysis")
                return []
            
            result = subprocess.run([
                'myth', 'analyze', file_path,
                '--output', 'json'
            ], capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                try:
                    mythril_data = json.loads(result.stdout)
                    findings = []
                    
                    for issue in mythril_data.get('issues', []):
                        finding = {
                            'vulnerability_type': issue.get('swc-id', 'unknown'),
                            'title': issue.get('title', 'Unknown Issue'),
                            'description': issue.get('description', ''),
                            'severity': self.map_mythril_severity(issue.get('severity', 'Medium')),
                            'confidence': 'MEDIUM',
                            'cwe_id': issue.get('swc-id', ''),
                            'cvss_score': self.calculate_cvss_from_mythril(issue),
                            'line_number': None,  # Mythril doesn't always provide line numbers
                            'code_snippet': issue.get('function', ''),
                            'remediation': issue.get('recommendation', ''),
                            'references': f"https://swcregistry.io/docs/SWC-{issue.get('swc-id', '')}",
                            'detected_by': 'mythril'
                        }
                        findings.append(finding)
                    
                    return findings
                except json.JSONDecodeError:
                    return []
            else:
                return []
                
        except subprocess.TimeoutExpired:
            return []
        except FileNotFoundError:
            logger.warning("Mythril command not found, skipping analysis")
            return []
        except Exception as e:
            logger.error(f"Mythril analysis error: {str(e)}")
            return []

    def run_echidna_analysis(self, file_path):
        """Run Echidna fuzzing if available. Returns simplified findings list."""
        try:
            result = subprocess.run(['echidna-test', '--version'], capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                logger.warning("Echidna not available, skipping analysis")
                return []
            result = subprocess.run([
                'echidna-test', file_path,
                '--test-mode', 'assertion',
                '--format', 'json'
            ], capture_output=True, text=True, timeout=600)
            if result.returncode != 0:
                # Echidna returns non-zero on failures found; still parse JSON if present
                pass
            try:
                data = json.loads(result.stdout or '{}')
            except json.JSONDecodeError:
                return []
            findings = []
            tests = data.get('tests', []) if isinstance(data, dict) else []
            for t in tests:
                if t.get('status') == 'failed':
                    findings.append({
                        'vulnerability_type': 'echidna_property_failed',
                        'title': t.get('name', 'Echidna property failed'),
                        'description': t.get('reason', 'A fuzzing test failed'),
                        'severity': 'HIGH',
                        'confidence': 'MEDIUM',
                        'cwe_id': '',
                        'cvss_score': 7.0,
                        'line_number': None,
                        'code_snippet': '',
                        'remediation': 'Investigate failing property and harden logic against edge cases',
                        'references': '',
                        'detected_by': 'echidna'
                    })
            return findings
        except subprocess.TimeoutExpired:
            logger.warning("Echidna analysis timed out")
            return []
        except FileNotFoundError:
            logger.warning("Echidna command not found, skipping analysis")
            return []
        except Exception as e:
            logger.error(f"Echidna analysis error: {str(e)}")
            return []
    
    def map_mythril_severity(self, mythril_severity):
        """Map Mythril severity to our severity levels"""
        mapping = {
            'High': 'HIGH',
            'Medium': 'MEDIUM',
            'Low': 'LOW'
        }
        return mapping.get(mythril_severity, 'MEDIUM')
    
    def calculate_cvss_from_mythril(self, issue):
        """Calculate CVSS score from Mythril issue"""
        base_score = 5.0
        
        if issue.get('severity') == 'High':
            base_score += 3.0
        elif issue.get('severity') == 'Low':
            base_score -= 2.0
        
        return max(0.0, min(10.0, base_score))
    
    def calculate_risk_score(self, vulnerabilities):
        """Calculate comprehensive risk score based on vulnerabilities"""
        if not vulnerabilities:
            return 0.0
        
        try:
            total_score = 0.0
            severity_weights = {
                'CRITICAL': 10.0,
                'HIGH': 7.5,
                'MEDIUM': 5.0,
                'LOW': 2.5
            }
            
            for vuln in vulnerabilities:
                weight = severity_weights.get(vuln['severity'], 5.0)
                cvss = vuln.get('cvss_score', 5.0)
                total_score += (weight * cvss) / 10.0
            
            # Normalize to 0-100 scale
            risk_score = min(100.0, (total_score / len(vulnerabilities)) * 10.0)
            
            return round(risk_score, 2)
        except Exception as e:
            logger.error(f"Error calculating risk score: {str(e)}")
            return 0.0
    
    def assess_compliance(self, vulnerabilities, source_code):
        """Assess compliance with security frameworks"""
        compliance_results = []
        
        try:
            for framework_name, framework in self.compliance_frameworks.items():
                for requirement in framework['requirements']:
                    status = 'PASS'
                    details = 'Requirement met'
                    evidence = ''
                    
                    # Check specific requirements
                    if 'Access Control' in requirement:
                        if any(v['vulnerability_type'] == 'access_control' for v in vulnerabilities):
                            status = 'FAIL'
                            details = 'Access control vulnerabilities detected'
                            evidence = 'Public functions without proper access control found'
                    
                    elif 'Injection' in requirement:
                        if any(v['vulnerability_type'] in ['reentrancy', 'unchecked_calls'] for v in vulnerabilities):
                            status = 'FAIL'
                            details = 'Injection vulnerabilities detected'
                            evidence = 'Reentrancy and unchecked call vulnerabilities found'
                    
                    elif 'Integrity' in requirement:
                        if any(v['vulnerability_type'] in ['timestamp_dependency', 'tx_origin'] for v in vulnerabilities):
                            status = 'PARTIAL'
                            details = 'Data integrity concerns detected'
                            evidence = 'Timestamp dependency and tx.origin usage found'
                    
                    compliance_results.append({
                        'framework_name': framework_name,
                        'framework_version': framework['version'],
                        'requirement': requirement,
                        'status': status,
                        'details': details,
                        'evidence': evidence
                    })
        except Exception as e:
            logger.error(f"Error assessing compliance: {str(e)}")
        
        return compliance_results

def upload_contract(request):
    """Enhanced contract upload with comprehensive security analysis"""
    if request.method == 'POST' and request.FILES.get('contract'):
        start_time = time.time()
        
        try:
            contract = request.FILES['contract']
            
            # Validate file type
            if not contract.name.endswith('.sol'):
                messages.error(request, 'Only Solidity (.sol) files are allowed')
                return render(request, 'scanner/upload.html')
            
            # Save file
            fs = FileSystemStorage()
            filename = fs.save(contract.name, contract)
            file_path = os.path.join(settings.MEDIA_ROOT, filename)
            
            # Read source code
            with open(file_path, 'r') as f:
                source_code = f.read()
            
            # Create scan session
            analyzer = AdvancedSecurityAnalyzer()
            contract_hash = analyzer.calculate_contract_hash(source_code)
            
            scan_session = ScanSession.objects.create(
                session_id=f"scan_{int(time.time())}",
                contract_name=contract.name,
                contract_hash=contract_hash,
                status='RUNNING'
            )
            
            # Run comprehensive analysis
            try:
                with ThreadPoolExecutor(max_workers=2) as executor:
                    # Submit analysis tasks
                    slither_future = executor.submit(analyzer.run_slither_analysis, file_path)
                    mythril_future = executor.submit(analyzer.run_mythril_analysis, file_path)
                    
                    # Get results
                    slither_findings, slither_output = slither_future.result()
                    mythril_findings = mythril_future.result()
            except Exception as e:
                logger.error(f"Error in concurrent analysis: {str(e)}")
                # Fallback to sequential analysis
                slither_findings, slither_output = analyzer.run_slither_analysis(file_path)
                mythril_findings = analyzer.run_mythril_analysis(file_path)
            
            # Run custom analysis
            custom_vulnerabilities = analyzer.detect_vulnerabilities(source_code)
            complexity_metrics = analyzer.analyze_code_complexity(source_code)
            
            # Combine all findings
            all_vulnerabilities = custom_vulnerabilities + slither_findings + mythril_findings
            
            # Calculate risk score
            risk_score = analyzer.calculate_risk_score(all_vulnerabilities)
            
            # Assess compliance
            compliance_results = analyzer.assess_compliance(all_vulnerabilities, source_code)
            
            # Update scan session
            scan_duration = time.time() - start_time
            severity_level = 'LOW'
            if risk_score >= 70:
                severity_level = 'CRITICAL'
            elif risk_score >= 50:
                severity_level = 'HIGH'
            elif risk_score >= 30:
                severity_level = 'MEDIUM'
            
            scan_session.risk_score = risk_score
            scan_session.severity_level = severity_level
            scan_session.status = 'COMPLETED'
            scan_session.scan_duration = scan_duration
            scan_session.save()
            
            # Create security metrics
            security_metrics = SecurityMetric.objects.create(
                scan_session=scan_session,
                total_vulnerabilities=len(all_vulnerabilities),
                critical_vulnerabilities=len([v for v in all_vulnerabilities if v['severity'] == 'CRITICAL']),
                high_vulnerabilities=len([v for v in all_vulnerabilities if v['severity'] == 'HIGH']),
                medium_vulnerabilities=len([v for v in all_vulnerabilities if v['severity'] == 'MEDIUM']),
                low_vulnerabilities=len([v for v in all_vulnerabilities if v['severity'] == 'LOW']),
                code_complexity=complexity_metrics.get('code_complexity', 0.0),
                cyclomatic_complexity=complexity_metrics.get('cyclomatic_complexity', 1),
                maintainability_index=complexity_metrics.get('maintainability_index', 100.0),
                security_score=max(0, 100 - risk_score),
                gas_optimization_score=max(0, 100 - complexity_metrics.get('cyclomatic_complexity', 1) * 5),
                compliance_score=len([c for c in compliance_results if c['status'] == 'PASS']) / len(compliance_results) * 100 if compliance_results else 100
            )
            
            # Store vulnerabilities
            for vuln_data in all_vulnerabilities:
                Vulnerability.objects.create(
                    scan_session=scan_session,
                    **vuln_data
                )
            
            # Store compliance checks
            for compliance_data in compliance_results:
                framework, created = ComplianceFramework.objects.get_or_create(
                    name=compliance_data['framework_name'],
                    defaults={
                        'version': compliance_data['framework_version'],
                        'description': f'Compliance framework: {compliance_data["framework_name"]}',
                        'requirements': '{}'
                    }
                )
                
                ComplianceCheck.objects.create(
                    scan_session=scan_session,
                    framework=framework,
                    requirement=compliance_data['requirement'],
                    status=compliance_data['status'],
                    details=compliance_data['details'],
                    evidence=compliance_data['evidence']
                )
            
            # Create audit trail
            AuditTrail.objects.create(
                scan_session=scan_session,
                action='CONTRACT_SCAN_COMPLETED',
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                ip_address=request.META.get('REMOTE_ADDR', ''),
                details=f'Contract {contract.name} scanned successfully',
                risk_assessment=f'Risk score: {risk_score}, Severity: {severity_level}'
            )
            
            messages.success(request, f'Contract analysis completed successfully. Risk Score: {risk_score}')
            
            return render(request, 'scanner/report.html', {
                'scan_session': scan_session,
                'vulnerabilities': all_vulnerabilities,
                'security_metrics': security_metrics,
                'compliance_results': compliance_results,
                'complexity_metrics': complexity_metrics,
                'slither_output': slither_output,
                'contract_url': fs.url(filename)
            })
            
        except Exception as e:
            logger.error(f"Contract analysis error: {str(e)}")
            messages.error(request, f'Analysis failed: {str(e)}')
            
            if 'scan_session' in locals():
                scan_session.status = 'FAILED'
                scan_session.save()
            
            return render(request, 'scanner/upload.html')
    
    return render(request, 'scanner/upload.html')


def simulator(request):
    """Render the Web3 architecture simulator page"""
    diagrams = Diagram.objects.all().order_by('-updated_at')[:10]
    return render(request, 'scanner/simulator.html', { 'diagrams': diagrams })


@csrf_exempt
def api_diagram_list(request):
    if request.method == 'GET':
        items = [
            {
                'id': str(d.id),
                'title': d.title,
                'description': d.description,
                'updated_at': d.updated_at.isoformat(),
                'security_score': d.security_score,
            } for d in Diagram.objects.all().order_by('-updated_at')
        ]
        return JsonResponse({ 'diagrams': items })
    return JsonResponse({ 'error': 'Method not allowed' }, status=405)


@csrf_exempt
def api_diagram_get(request, diagram_id):
    try:
        d = Diagram.objects.get(id=diagram_id)
        return JsonResponse({
            'id': str(d.id),
            'title': d.title,
            'description': d.description,
            'data': d.get_data(),
            'security_score': d.security_score,
        })
    except Diagram.DoesNotExist:
        return JsonResponse({ 'error': 'Diagram not found' }, status=404)


@csrf_exempt
def api_diagram_save(request):
    if request.method != 'POST':
        return JsonResponse({ 'error': 'Method not allowed' }, status=405)
    try:
        payload = json.loads(request.body.decode('utf-8'))
        diagram_id = payload.get('id')
        title = payload.get('title') or 'Untitled Diagram'
        description = payload.get('description', '')
        data = payload.get('data') or {}

        analyzer = DiagramAnalyzer()
        analysis = analyzer.analyze(data)
        security_score = analysis['security_score']

        if diagram_id:
            d = Diagram.objects.get(id=diagram_id)
            d.title = title
            d.description = description
            d.set_data(data)
            d.security_score = security_score
            d.save()
        else:
            d = Diagram.objects.create(
                owner=request.user if getattr(request, 'user', None) and request.user.is_authenticated else None,
                title=title,
                description=description,
                data_json=json.dumps(data),
                security_score=security_score,
            )
        return JsonResponse({ 'id': str(d.id), 'security_score': security_score, 'analysis': analysis })
    except Diagram.DoesNotExist:
        return JsonResponse({ 'error': 'Diagram not found' }, status=404)
    except Exception as e:
        logger.exception('Failed to save diagram')
        return JsonResponse({ 'error': str(e) }, status=400)


@csrf_exempt
def api_diagram_analyze(request):
    if request.method != 'POST':
        return JsonResponse({ 'error': 'Method not allowed' }, status=405)
    try:
        payload = json.loads(request.body.decode('utf-8'))
        data = payload.get('data') or {}
        analyzer = DiagramAnalyzer()
        result = analyzer.analyze(data)
        return JsonResponse(result)
    except Exception as e:
        logger.exception('Analysis failed')
        return JsonResponse({ 'error': str(e) }, status=400)


def export_diagram_json(request, diagram_id):
    try:
        d = Diagram.objects.get(id=diagram_id)
        response = HttpResponse(json.dumps(d.get_data(), indent=2), content_type='application/json')
        response['Content-Disposition'] = f'attachment; filename="diagram-{diagram_id}.json"'
        return response
    except Diagram.DoesNotExist:
        return HttpResponse(status=404)

def scan_history(request):
    """View scan history and analytics"""
    scan_sessions = ScanSession.objects.all().order_by('-scan_timestamp')
    
    # Calculate statistics
    total_scans = scan_sessions.count()
    completed_scans = scan_sessions.filter(status='COMPLETED').count()
    failed_scans = scan_sessions.filter(status='FAILED').count()
    
    # Risk distribution
    risk_distribution = {
        'LOW': scan_sessions.filter(severity_level='LOW').count(),
        'MEDIUM': scan_sessions.filter(severity_level='MEDIUM').count(),
        'HIGH': scan_sessions.filter(severity_level='HIGH').count(),
        'CRITICAL': scan_sessions.filter(severity_level='CRITICAL').count(),
    }
    
    context = {
        'scan_sessions': scan_sessions,
        'total_scans': total_scans,
        'completed_scans': completed_scans,
        'failed_scans': failed_scans,
        'risk_distribution': risk_distribution,
    }
    
    return render(request, 'scanner/history.html', context)

def scan_detail(request, session_id):
    """View detailed scan results"""
    scan_session = get_object_or_404(ScanSession, session_id=session_id)
    vulnerabilities = Vulnerability.objects.filter(scan_session=scan_session)
    security_metrics = getattr(scan_session, 'security_metrics', None)
    compliance_checks = ComplianceCheck.objects.filter(scan_session=scan_session)
    audit_trails = AuditTrail.objects.filter(scan_session=scan_session)
    
    context = {
        'scan_session': scan_session,
        'vulnerabilities': vulnerabilities,
        'security_metrics': security_metrics,
        'compliance_checks': compliance_checks,
        'audit_trails': audit_trails,
    }
    
    return render(request, 'scanner/detail.html', context)

@csrf_exempt
def api_scan_status(request, session_id):
    """API endpoint to check scan status"""
    try:
        scan_session = ScanSession.objects.get(session_id=session_id)
        return JsonResponse({
            'status': scan_session.status,
            'progress': scan_session.progress if hasattr(scan_session, 'progress') else 0,
            'risk_score': scan_session.risk_score,
            'severity_level': scan_session.severity_level
        })
    except ScanSession.DoesNotExist:
        return JsonResponse({'error': 'Scan session not found'}, status=404)


# ---------------------------------------------
# Token Analyzer (Etherscan + Intel + Heuristics)
# ---------------------------------------------

def _get_env(name: str, default: str | None = None) -> str | None:
    try:
        return os.environ.get(name, default)
    except Exception:
        return default


def _etherscan_get(api_key: str, module: str, action: str, params: dict, timeout_seconds: int = 10):
    base_url = 'https://api.etherscan.io/api'  # Keep v1; throttle to comply with 2 req/s
    q = {'module': module, 'action': action, 'apikey': api_key}
    q.update(params or {})

    def throttle():
        with _ETHERSCAN_LOCK:
            now = time.time()
            # drop old timestamps
            while _ETHERSCAN_CALLS and (now - _ETHERSCAN_CALLS[0]) > _ETHERSCAN_WINDOW:
                _ETHERSCAN_CALLS.popleft()
            if len(_ETHERSCAN_CALLS) >= _ETHERSCAN_RATE:
                wait_for = _ETHERSCAN_WINDOW - (now - _ETHERSCAN_CALLS[0]) + 0.01
            else:
                wait_for = 0.0
        if wait_for > 0:
            time.sleep(max(0.0, wait_for))
        with _ETHERSCAN_LOCK:
            _ETHERSCAN_CALLS.append(time.time())

    attempts = 0
    backoff = 0.6
    while attempts < 3:
        attempts += 1
        try:
            throttle()
            resp = requests.get(base_url, params=q, timeout=timeout_seconds)
            if resp.status_code == 200:
                data = resp.json()
                # Detect rate-limit messages in body
                message = str(data.get('message', '')).lower() if isinstance(data, dict) else ''
                if 'max calls per sec' in message or 'rate limit' in message:
                    time.sleep(backoff)
                    backoff *= 1.5
                    continue
                return data
            if resp.status_code in (403, 429):
                time.sleep(backoff)
                backoff *= 1.5
                continue
        except Exception:
            time.sleep(backoff)
            backoff *= 1.5
            continue
    return None


def _forta_lookup(address: str, api_key: str | None, timeout_seconds: int = 8):
    if not api_key:
        return None
    try:
        headers = {'Authorization': f'Bearer {api_key}'}
        url = 'https://api.forta.network/alerts/for-address'
        params = {'address': address, 'chainId': '1', 'limit': 3}
        r = requests.get(url, headers=headers, params=params, timeout=timeout_seconds)
        if r.status_code == 200:
            return r.json()
    except Exception:
        return None
    return None


def _chainalysis_lookup(address: str, api_key: str | None, timeout_seconds: int = 8):
    if not api_key:
        return None
    try:
        headers = {'Token': api_key}
        url = f'https://public.chainalysis.com/risk/v2/entity/{address}'
        r = requests.get(url, headers=headers, timeout=timeout_seconds)
        if r.status_code == 200:
            return r.json()
    except Exception:
        return None
    return None


def _honeypot_is(address: str, timeout_seconds: int = 8):
    try:
        url = 'https://api.honeypot.is/v2/IsHoneypot'
        params = {'address': address, 'chainID': 1}
        r = requests.get(url, params=params, timeout=timeout_seconds)
        if r.status_code == 200:
            return r.json()
    except Exception:
        return None
    return None


def _analyze_token_risk(token_info: dict, holders: list[dict], source_code: str | None, creator: str | None,
                        verified: bool, intel: dict, slither_findings: list[dict] | None = None) -> dict:
    risks: list[dict] = []

    def add(sev: str, title: str, detail: str):
        risks.append({'severity': sev, 'title': title, 'detail': detail})

    # Contract verification
    if not verified:
        add('HIGH', 'Contract not verified', 'Unverified contracts are high risk.')

    # Top holder concentration
    try:
        total_supply = float(token_info.get('totalSupply', 0)) or 0.0
        if total_supply > 0 and holders:
            holders_sorted = holders[:5]
            top_sum = sum(float(h.get('Balance', 0)) for h in holders_sorted)
            if (top_sum / total_supply) > 0.5:
                add('HIGH', 'Top holder concentration', 'Top 1–5 holders control over 50% of supply.')
    except Exception:
        pass

    # Ownership renounced / privileges in code
    if source_code:
        patterns = {
            'mint': r'function\s+mint\s*\(',
            'blacklist': r'blacklist|isBlacklisted|addToBlacklist',
            'setTax': r'setTax|setFee|updateTax',
            'transferLimit': r'maxTxAmount|maxTransfer|limit',
            'ownerOnly': r'onlyOwner',
            'renounceOwnership': r'renounceOwnership\s*\(',
        }
        found_owner_only = re.search(patterns['ownerOnly'], source_code, re.IGNORECASE)
        found_mint = re.search(patterns['mint'], source_code, re.IGNORECASE)
        found_black = re.search(patterns['blacklist'], source_code, re.IGNORECASE)
        if found_owner_only and (found_mint or found_black):
            add('HIGH', 'Owner retains sensitive powers', 'Deployer/owner can mint or blacklist users.')
        if re.search(patterns['transferLimit'], source_code, re.IGNORECASE):
            add('MEDIUM', 'Transfer limits detected', 'Transfer limit logic present.')
        if re.search(patterns['setTax'], source_code, re.IGNORECASE):
            add('MEDIUM', 'Tax functions detected', 'Tax/fee setters found.')

    # Honeypot / sellability
    hp = intel.get('honeypot')
    if isinstance(hp, dict):
        if hp.get('IsHoneypot') is True or hp.get('Honeypot') is True:
            add('HIGH', 'Honeypot behavior', 'Token appears unsellable or traps buyers.')

    # Forta / Chainalysis intel
    forta = intel.get('forta')
    if isinstance(forta, dict) and forta.get('alerts'):
        add('HIGH', 'Forta alerts', 'Historical alerts on creator/contract.')
    ch = intel.get('chainalysis')
    try:
        severity = ((ch or {}).get('data') or {}).get('risk', {}).get('severity')
        if severity in ['Severe', 'High']:
            add('CRITICAL' if severity == 'Severe' else 'HIGH', 'Chainalysis high-risk entity', f'Risk severity: {severity}')
    except Exception:
        pass

    # Recent deployment detection
    try:
        creation_ts = token_info.get('creationTime')
        if creation_ts:
            ts = int(creation_ts)
            age_days = max(0, (time.time() - ts) / 86400.0)
            if age_days < 7:
                add('MEDIUM', 'Very recent deployment', 'Token deployed within the last 7 days.')
    except Exception:
        pass

    # Suspicious transactions heuristic (large sells from deployer)
    txs = intel.get('txs') or []
    try:
        large_sells = [t for t in txs if t.get('from', '').lower() == (creator or '').lower() and int(t.get('value', '0')) > 0]
        if len(large_sells) >= 3:
            add('MEDIUM', 'Creator selling repeatedly', 'Multiple large transfers from creator wallet.')
    except Exception:
        pass

    # Slither findings
    try:
        if slither_findings:
            has_high = any(f.get('severity') in ['HIGH', 'CRITICAL'] for f in slither_findings)
            if has_high:
                add('HIGH', 'Static analysis findings', 'High severity issues reported by Slither.')
            elif any(f.get('severity') == 'MEDIUM' for f in slither_findings):
                add('MEDIUM', 'Static analysis findings', 'Medium severity issues reported by Slither.')
    except Exception:
        pass

    # Aggregate to score 0-100 (higher is safer)
    weights = {'CRITICAL': 35, 'HIGH': 20, 'MEDIUM': 10, 'LOW': 5}
    penalty = sum(weights.get(r['severity'], 10) for r in risks)
    security_score = max(0, 100 - penalty)

    recommendation = 'Likely Safe'
    if security_score < 30 or any(r['severity'] in ['CRITICAL', 'HIGH'] for r in risks):
        recommendation = 'High Risk / Potential Rug Pull' if security_score < 20 else 'Suspicious'

    return {
        'security_score': security_score,
        'risks': risks,
        'recommendation': recommendation,
    }


def token_analyzer(request):
    if request.method == 'GET':
        return render(request, 'scanner/token_analyzer.html')

    if request.method == 'POST':
        address = (request.POST.get('address') or '').strip()
        if not re.match(r'^0x[a-fA-F0-9]{40}$', address):
            messages.error(request, 'Please enter a valid Ethereum address')
            return render(request, 'scanner/token_analyzer.html')

        etherscan_key = _get_env('ETHERSCAN_API_KEY') or getattr(settings, 'ETHERSCAN_API_KEY', '') or ''
        forta_key = _get_env('FORTA_API_KEY')
        chain_key = _get_env('CHAINALYSIS_API_KEY')

        token_info = {}
        holders = []
        verified = False
        source_code = None
        creator = None
        creation_time = None
        slither_findings = []
        contract_name = None

        # Batched fetches to respect 2 req/s soft limit
        import time

# --- first batch (2 requests) ---
        token_resp = _etherscan_get(
            etherscan_key,
            'token', 'tokeninfo',
            {'contractaddress': address}
        ) or {}
        
        code_resp = _etherscan_get(
            etherscan_key,
            'contract', 'getsourcecode',
            {'address': address}
        ) or {}
        
        time.sleep(0.6)  # stay below 2 req/sec
        
        # --- second batch (2 requests) ---
        create_resp = _etherscan_get(
            etherscan_key,
            'contract', 'getcontractcreation',
            {'contractaddresses': address}
        ) or {}
        
        supply_resp = _etherscan_get(
            etherscan_key,
            'stats', 'tokensupply',
            {'contractaddress': address}
        ) or {}
        
        time.sleep(0.6)
        
        # --- third batch (2 requests) ---
        holder_count_resp = _etherscan_get(
            etherscan_key,
            'token', 'tokenholdercount',
            {'contractaddress': address}
        ) or {}
        
        holders_resp = _etherscan_get(
            etherscan_key,
            'token', 'tokenholderlist',
            {'contractaddress': address, 'page': 1, 'offset': 10}
        ) or {}
        
        time.sleep(0.6)
        
        # --- fourth batch (2 requests) ---
        abi_resp = _etherscan_get(
            etherscan_key,
            'contract', 'getabi',
            {'address': address}
        ) or {}
        
        txs_resp = _etherscan_get(
            etherscan_key,
            'account', 'txlist',
            {'address': address, 'startblock': 0, 'endblock': 99999999, 'sort': 'desc'}
        ) or {}
        
        # Non-Etherscan service separately (not rate limited by Etherscan)
        hp_resp = _honeypot_is(address) or {}

        # Parse Etherscan responses
        try:
            if isinstance(token_resp.get('result'), list) and token_resp['result']:
                token_info = token_resp['result'][0]
        except Exception:
            pass

        try:
            if isinstance(holders_resp.get('result'), list):
                holders = holders_resp['result']
        except Exception:
            holders = []

        compiler_version = None
        license_type = None
        optimization_used = None
        optimization_runs = None
        proxy_flag = None
        implementation_addr = None
        try:
            code_items = code_resp.get('result') or []
            if isinstance(code_items, list) and code_items:
                verified = (code_items[0].get('ABI') or '') not in ['', 'Contract source code not verified']
                source_code = code_items[0].get('SourceCode') or None
                contract_name = code_items[0].get('ContractName') or None
                compiler_version = code_items[0].get('CompilerVersion')
                license_type = code_items[0].get('LicenseType')
                optimization_used = code_items[0].get('OptimizationUsed')
                optimization_runs = code_items[0].get('Runs')
                proxy_flag = code_items[0].get('Proxy')
                implementation_addr = code_items[0].get('Implementation')
        except Exception:
            pass

        try:
            cr = (create_resp.get('result') or [])
            if isinstance(cr, list) and cr:
                creator = cr[0].get('contractCreator') or cr[0].get('contractAddress')
                creation_time = cr[0].get('timeStamp')
                token_info['creationTime'] = creation_time
        except Exception:
            pass
        # Fallback: if proxy and no creator, try implementation contract
        try:
            if (not creator) and implementation_addr:
                impl_resp = _etherscan_get(etherscan_key, 'contract', 'getcontractcreation', {'contractaddresses': implementation_addr}) or {}
                impl_res = impl_resp.get('result') or []
                if isinstance(impl_res, list) and impl_res:
                    creator = impl_res[0].get('contractCreator') or creator
                    creation_time = impl_res[0].get('timeStamp') or creation_time
                    if creation_time:
                        token_info['creationTime'] = creation_time
        except Exception:
            pass

        txs = []
        try:
            if isinstance(txs_resp.get('result'), list):
                txs = txs_resp['result'][:50]
        except Exception:
            pass

        # Fallback 2: if still no creator, infer from first tx sender
        try:
            if not creator and txs:
                first_tx = txs[0]
                inferred_creator = first_tx.get('from')
                if inferred_creator:
                    creator = inferred_creator
        except Exception:
            pass

        # Parse stats: total supply and holder count
        total_supply_raw = None
        holders_count = None
        try:
            sr = supply_resp.get('result')
            total_supply_raw = str(sr) if sr is not None else None
        except Exception:
            total_supply_raw = None
        try:
            hc = holder_count_resp.get('result')
            holders_count = int(hc) if hc is not None else None
        except Exception:
            holders_count = None

        # If verified and source available, optionally run Slither quickly
        try:
            if verified and source_code:
                # Etherscan may wrap source in metadata markers. Strip if needed.
                source_str = source_code
                tmp_name = f"token-{uuid.uuid4().hex}.sol"
                tmp_path = os.path.join(settings.MEDIA_ROOT, tmp_name)
                with open(tmp_path, 'w', encoding='utf-8') as f:
                    f.write(source_str)
                analyzer = AdvancedSecurityAnalyzer()
                slither_findings, _ = analyzer.run_slither_analysis(tmp_path)
        except Exception:
            slither_findings = []

        # External intel
        forta_data = _forta_lookup(creator or address, forta_key)
        chain_data = _chainalysis_lookup(creator or address, chain_key)

        intel = {'honeypot': hp_resp, 'forta': forta_data, 'chainalysis': chain_data, 'txs': txs}

        # Parse ABI for privileged functions
        abi = None
        risky_hits = []
        try:
            abi_str = None
            res_val = abi_resp.get('result') if isinstance(abi_resp, dict) else None
            if isinstance(res_val, str):
                abi_str = res_val
            elif isinstance(code_items, list) and code_items:
                abi_str = code_items[0].get('ABI')
            if abi_str and abi_str not in ['', 'Contract source code not verified']:
                abi = json.loads(abi_str)
        except Exception:
            abi = None

        try:
            abi_risky_names = [
                'mint', 'blacklist', 'addToBlacklist', 'removeFromBlacklist', 'setBlacklist', 'enableTrading',
                'setTrading', 'setMaxTxAmount', 'setMaxWallet', 'setSwapAndLiquifyEnabled', 'setFees', 'setTax',
                'setTaxFeePercent', 'setLiquidityFeePercent', 'setMarketingWallet', 'pause', 'unpause', 'addBot',
                'removeBot', 'setIsBot', 'excludeFromFee', 'includeInFee', 'updateRouter', 'updatePair'
            ]
            if isinstance(abi, list):
                for item in abi:
                    if item.get('type') == 'function':
                        name = item.get('name', '')
                        if any(key.lower() in name.lower() for key in abi_risky_names):
                            risky_hits.append(name)
        except Exception:
            risky_hits = []

        analysis = _analyze_token_risk(token_info, holders, source_code, creator, verified, intel, slither_findings)
        if risky_hits:
            analysis['risks'].append({
                'severity': 'HIGH',
                'title': 'Privileged functions in ABI',
                'detail': f"Sensitive functions exposed: {', '.join(sorted(set(risky_hits)))[:300]}"
            })
            analysis['security_score'] = max(0, analysis['security_score'] - 10)

        # Advanced insights
        total_functions = 0
        top_functions = []
        try:
            if isinstance(abi, list):
                fn_sigs = []
                for item in abi:
                    if item.get('type') == 'function':
                        total_functions += 1
                        name = item.get('name', '')
                        inputs = item.get('inputs', []) or []
                        sig = name + '(' + ','.join([i.get('type', '') for i in inputs]) + ')'
                        selector = ''
                        try:
                            if keccak:
                                selector = keccak(text=sig)[:4].hex()
                        except Exception:
                            selector = ''
                        fn_sigs.append((name or 'unknown', selector))
                priority = {
                    'totalSupply': 3, 'transfer': 3, 'approve': 2, 'transferFrom': 2,
                    'mint': 4, 'burn': 2, 'blacklist': 4, 'setTax': 3, 'setFees': 3,
                }
                fn_sigs.sort(key=lambda x: priority.get(x[0], 0), reverse=True)
                top_functions = fn_sigs[:3]
        except Exception:
            pass

        storage_vars = 0
        mapping_vars = 0
        try:
            if source_code:
                storage_vars = len(re.findall(r'\b(?:uint\d*|int\d*|address|bool|string|bytes\d*)\s+\w+\s*;', source_code))
                mapping_vars = len(re.findall(r'\bmapping\s*\(', source_code))
        except Exception:
            pass

        vuln_summary = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        try:
            analyzer_custom = AdvancedSecurityAnalyzer()
            custom_v = analyzer_custom.detect_vulnerabilities(source_code or '')
            for v in (custom_v + (slither_findings or [])):
                sev = v.get('severity', 'MEDIUM')
                if sev not in vuln_summary:
                    vuln_summary[sev] = 0
                vuln_summary[sev] += 1
        except Exception:
            pass

        smell_score = 100
        try:
            if risky_hits:
                smell_score -= 20
            if not verified:
                smell_score -= 25
            try:
                if holders_display:
                    percents = []
                    for h in holders_display:
                        ptxt = h.get('percent', '0%').replace('%', '')
                        percents.append(float(ptxt) if ptxt not in ['-', ''] else 0.0)
                    top5 = sorted(percents, reverse=True)[:5]
                    if sum(top5) > 50:
                        smell_score -= 20
            except Exception:
                pass
            smell_score = max(0, min(100, smell_score))
        except Exception:
            smell_score = max(0, min(100, smell_score))

        # Normalize display fields
        token_name = (
            (token_info.get('tokenName') if isinstance(token_info, dict) else None)
            or (token_info.get('name') if isinstance(token_info, dict) else None)
            or contract_name
            or '-'
        )
        token_symbol = (
            (token_info.get('symbol') if isinstance(token_info, dict) else None)
            or (token_info.get('tokenSymbol') if isinstance(token_info, dict) else None)
            or '-'
        )
        decimals = None
        try:
            if isinstance(token_info, dict):
                decimals = int(token_info.get('decimals') or token_info.get('divisor') or 18)
        except Exception:
            decimals = 18
        # Adjusted supply text
        def _format_supply(raw: str | None, decimals_val: int | None) -> str:
            if not raw:
                return '-'
            try:
                if decimals_val is None:
                    decimals_val = 18
                val = float(raw) / (10 ** int(decimals_val))
                return f"{val:,.4f}"
            except Exception:
                return raw
        total_supply_disp = _format_supply(total_supply_raw, decimals)
        total_supply_num = None
        try:
            if total_supply_raw is not None:
                d = decimals if isinstance(decimals, int) else 18
                total_supply_num = float(total_supply_raw) / (10 ** d)
        except Exception:
            total_supply_num = None
        creation_time_disp = '-'
        try:
            ct = token_info.get('creationTime') if isinstance(token_info, dict) else None
            if ct:
                ts = int(ct)
                creation_time_disp = datetime.utcfromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S UTC')
        except Exception:
            pass

        # Project links from token_info if present
        project_links = {}
        if isinstance(token_info, dict):
            for k in ['website', 'officialSite', 'email', 'telegram', 'twitter', 'facebook', 'reddit', 'coingecko', 'coinmarketcap']:
                v = token_info.get(k)
                if v:
                    project_links[k] = v

        # Build holders display with human balance and percent
        holders_display = []
        try:
            d = decimals if isinstance(decimals, int) else 18
            for h in holders:
                addr = h.get('Address') or h.get('address')
                raw = h.get('Balance') or h.get('balance')
                bal_h = None
                pct = None
                try:
                    if raw is not None:
                        bal_h = float(raw) / (10 ** d)
                        if total_supply_num and total_supply_num > 0:
                            pct = (bal_h / total_supply_num) * 100.0
                except Exception:
                    pass
                holders_display.append({
                    'address': addr,
                    'balance_h': f"{bal_h:,.4f}" if bal_h is not None else '-',
                    'percent': f"{pct:.2f}%" if pct is not None else '-'
                })
        except Exception:
            holders_display = []

        context = {
            'address': address,
            'token': token_info,
            'holders': holders,
            'verified': verified,
            'source_present': bool(source_code),
            'creator': creator,
            'security_score': analysis['security_score'],
            'risks': analysis['risks'],
            'recommendation': analysis['recommendation'],
            'token_name': token_name,
            'token_symbol': token_symbol,
            'creation_time': creation_time_disp,
            'holders_count': holders_count,
            'total_supply': total_supply_disp,
            'decimals': decimals,
            'project_links': project_links,
            'holders_display': holders_display,
            'compiler_version': compiler_version,
            'license_type': license_type,
            'optimization_used': optimization_used,
            'optimization_runs': optimization_runs,
            'proxy_flag': proxy_flag,
            'implementation_addr': implementation_addr,
            'abi_risky_hits': sorted(set(risky_hits)) if risky_hits else [],
            'total_functions': total_functions,
            'top_functions': top_functions,
            'storage_vars': storage_vars,
            'mapping_vars': mapping_vars,
            'vuln_summary': vuln_summary,
            'smell_score': smell_score,
        }
        return render(request, 'scanner/token_analyzer.html', context)

    return JsonResponse({'error': 'Method not allowed'}, status=405)


def export_token_report_pdf(request, address: str):
    # Lightweight re-run of analysis to populate PDF context
    etherscan_key = _get_env('ETHERSCAN_API_KEY') or getattr(settings, 'ETHERSCAN_API_KEY', '') or ''
    forta_key = _get_env('FORTA_API_KEY')
    chain_key = _get_env('CHAINALYSIS_API_KEY')

    token_info = {}
    holders = []
    verified = False
    source_code = None
    creator = None
    slither_findings = []
    holders_count = None
    total_supply_raw = None
    total_supply_disp = '-'
    decimals = 18
    project_links = {}

    try:
        with ThreadPoolExecutor(max_workers=8) as ex:
            f_token = ex.submit(_etherscan_get, etherscan_key, 'token', 'tokeninfo', {'contractaddress': address})
            f_holders = ex.submit(_etherscan_get, etherscan_key, 'token', 'tokenholderlist', {'contractaddress': address, 'page': 1, 'offset': 5})
            f_code = ex.submit(_etherscan_get, etherscan_key, 'contract', 'getsourcecode', {'address': address})
            f_create = ex.submit(_etherscan_get, etherscan_key, 'contract', 'getcontractcreation', {'contractaddresses': address})
            f_txs = ex.submit(_etherscan_get, etherscan_key, 'account', 'txlist', {'address': address, 'startblock': 0, 'endblock': 99999999, 'sort': 'desc'})
            f_hp = ex.submit(_honeypot_is, address)
            f_supply = ex.submit(_etherscan_get, etherscan_key, 'stats', 'tokensupply', {'contractaddress': address})
            f_holder_count = ex.submit(_etherscan_get, etherscan_key, 'token', 'tokenholdercount', {'contractaddress': address})

            token_resp = f_token.result() or {}
            holders_resp = f_holders.result() or {}
            code_resp = f_code.result() or {}
            create_resp = f_create.result() or {}
            txs_resp = f_txs.result() or {}
            hp_resp = f_hp.result() or {}
            supply_resp = f_supply.result() or {}
            holder_count_resp = f_holder_count.result() or {}

        if isinstance(token_resp.get('result'), list) and token_resp['result']:
            token_info = token_resp['result'][0]
        if isinstance(holders_resp.get('result'), list):
            holders = holders_resp['result']
        code_items = code_resp.get('result') or []
        if isinstance(code_items, list) and code_items:
            verified = (code_items[0].get('ABI') or '') not in ['', 'Contract source code not verified']
            source_code = code_items[0].get('SourceCode') or None
            try:
                decimals = int(token_info.get('decimals') or token_info.get('divisor') or 18)
            except Exception:
                decimals = 18
        cr = (create_resp.get('result') or [])
        if isinstance(cr, list) and cr:
            creator = cr[0].get('contractCreator') or cr[0].get('contractAddress')
            token_info['creationTime'] = cr[0].get('timeStamp')
        txs = txs_resp.get('result') if isinstance(txs_resp.get('result'), list) else []

        # Parse supply and holder count
        try:
            sr = supply_resp.get('result')
            total_supply_raw = str(sr) if sr is not None else None
        except Exception:
            total_supply_raw = None
        try:
            hc = holder_count_resp.get('result')
            holders_count = int(hc) if hc is not None else None
        except Exception:
            holders_count = None
        def _format_supply(raw: str | None, decimals_val: int | None) -> str:
            if not raw:
                return '-'
            try:
                if decimals_val is None:
                    decimals_val = 18
                val = float(raw) / (10 ** int(decimals_val))
                return f"{val:,.4f}"
            except Exception:
                return raw
        total_supply_disp = _format_supply(total_supply_raw, decimals)

        # Project links
        if isinstance(token_info, dict):
            for k in ['website', 'officialSite', 'email', 'telegram', 'twitter', 'facebook', 'reddit', 'coingecko', 'coinmarketcap']:
                v = token_info.get(k)
                if v:
                    project_links[k] = v

        if verified and source_code:
            try:
                tmp_name = f"token-{uuid.uuid4().hex}.sol"
                tmp_path = os.path.join(settings.MEDIA_ROOT, tmp_name)
                with open(tmp_path, 'w', encoding='utf-8') as f:
                    f.write(source_code)
                analyzer = AdvancedSecurityAnalyzer()
                slither_findings, _ = analyzer.run_slither_analysis(tmp_path)
            except Exception:
                slither_findings = []

        forta_data = _forta_lookup(creator or address, forta_key)
        chain_data = _chainalysis_lookup(creator or address, chain_key)
        intel = {'honeypot': hp_resp, 'forta': forta_data, 'chainalysis': chain_data, 'txs': txs[:50]}
        analysis = _analyze_token_risk(token_info, holders, source_code, creator, verified, intel, slither_findings)

        # Normalize display fields
        token_name = (
            (token_info.get('tokenName') if isinstance(token_info, dict) else None)
            or (token_info.get('name') if isinstance(token_info, dict) else None)
            or '-'
        )
        token_symbol = (
            (token_info.get('symbol') if isinstance(token_info, dict) else None)
            or '-'
        )
        creation_time_disp = (
            (token_info.get('creationTime') if isinstance(token_info, dict) else None)
            or '-'
        )

        context = {
            'address': address,
            'token': token_info,
            'holders': holders,
            'verified': verified,
            'source_present': bool(source_code),
            'creator': creator,
            'security_score': analysis['security_score'],
            'risks': analysis['risks'],
            'recommendation': analysis['recommendation'],
            'token_name': token_name,
            'token_symbol': token_symbol,
            'creation_time': creation_time_disp,
            'holders_count': holders_count,
            'total_supply': total_supply_disp,
            'decimals': decimals,
            'project_links': project_links,
        }
    except Exception:
        context = {'address': address}

    html = render_to_string('scanner/token_analyzer_pdf.html', context)
    response = HttpResponse(html, content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="token-report-{address}.pdf"'
    return response
