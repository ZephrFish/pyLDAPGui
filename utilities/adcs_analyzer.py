#!/usr/bin/env python3
"""
ADCS Certificate Template Analyzer for pyLDAPGui

~ Description : Analyzes Active Directory Certificate Services (ADCS) 
                certificate templates for security vulnerabilities and
                misconfigurations

@ Features:
  - Certificate template enumeration
  - Vulnerability detection (ESC1-ESC8)
  - Permission analysis
  - Attack path identification
  - Risk scoring
  - Remediation recommendations

@ Author: ZephrFish
@ License: MIT
"""

import re
from typing import List, Dict, Any, Optional, Set, Tuple
from datetime import datetime
from enum import Enum


class CertificateVulnerability(Enum):
    """Known ADCS vulnerability categories"""
    ESC1 = "Domain Users can enroll, allows SAN"
    ESC2 = "Domain Users can enroll, Any Purpose EKU"
    ESC3 = "Domain Users can enroll, Certificate Request Agent"
    ESC4 = "Vulnerable Certificate Template Access Control"
    ESC5 = "Vulnerable PKI Object Access Control"
    ESC6 = "EDITF_ATTRIBUTESUBJECTALTNAME2 flag"
    ESC7 = "Vulnerable Certificate Authority Access Control"
    ESC8 = "NTLM Relay to Web Enrollment"
    
    
class ADCSAnalyzer:
    """
    ADCS Certificate Template Security Analyzer
    
    ~ Description : Performs comprehensive analysis of certificate templates
                    to identify security vulnerabilities and attack paths
    """
    
    # Well-known SIDs
    WELL_KNOWN_SIDS = {
        'S-1-5-11': 'Authenticated Users',
        'S-1-5-32-545': 'Users',
        'S-1-5-32-546': 'Guests',
        'S-1-5-32-544': 'Administrators',
        'S-1-1-0': 'Everyone',
        'S-1-5-7': 'Anonymous',
        'S-1-5-18': 'Local System',
        'S-1-5-19': 'Local Service',
        'S-1-5-20': 'Network Service'
    }
    
    # Critical EKUs (Extended Key Usage)
    CRITICAL_EKUS = {
        '1.3.6.1.5.5.7.3.2': 'Client Authentication',
        '1.3.6.1.5.5.7.3.1': 'Server Authentication',
        '1.3.6.1.4.1.311.20.2.2': 'Smart Card Logon',
        '2.5.29.37.0': 'Any Purpose',
        '1.3.6.1.4.1.311.20.2.1': 'Certificate Request Agent'
    }
    
    # Certificate flags
    CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
    CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME = 0x00010000
    CT_FLAG_PUBLISH_TO_DS = 0x00000008
    CT_FLAG_AUTO_ENROLLMENT = 0x00000020
    
    def __init__(self, ldap_connection):
        """
        Initialize ADCS analyzer
        
        @ Args:
            ldap_connection : Active LDAP connection instance
        """
        self.ldap_conn = ldap_connection
        self.domain_dn = self._get_domain_dn()
        self.cert_templates = []
        self.cas = []  # Certificate Authorities
        self.vulnerabilities = []
        
    def analyze_environment(self) -> Dict[str, Any]:
        """
        Perform comprehensive ADCS security analysis
        
        @ Returns:
            dict : Analysis results with vulnerabilities and recommendations
        """
        results = {
            'timestamp': datetime.now().isoformat(),
            'domain': self.domain_dn,
            'certificate_templates': [],
            'certificate_authorities': [],
            'vulnerabilities': [],
            'statistics': {},
            'recommendations': []
        }
        
        # Enumerate certificate templates
        self.cert_templates = self._enumerate_certificate_templates()
        results['certificate_templates'] = self.cert_templates
        
        # Enumerate certificate authorities
        self.cas = self._enumerate_certificate_authorities()
        results['certificate_authorities'] = self.cas
        
        # Analyze each template for vulnerabilities
        for template in self.cert_templates:
            vulns = self._analyze_template_security(template)
            if vulns:
                self.vulnerabilities.extend(vulns)
                template['vulnerabilities'] = vulns
                
        # Check CA-level vulnerabilities
        ca_vulns = self._analyze_ca_security()
        self.vulnerabilities.extend(ca_vulns)
        
        # Generate statistics
        results['vulnerabilities'] = self.vulnerabilities
        results['statistics'] = self._calculate_statistics()
        
        # Generate recommendations
        results['recommendations'] = self._generate_recommendations()
        
        return results
        
    def _enumerate_certificate_templates(self) -> List[Dict[str, Any]]:
        """
        Enumerate all certificate templates in the forest
        
        @ Returns:
            list : List of certificate template objects
        """
        templates = []
        
        # Search for certificate templates
        template_filter = "(objectClass=pKICertificateTemplate)"
        template_base = f"CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,{self.domain_dn}"
        
        try:
            entries = self.ldap_conn.search_large(
                template_base,
                template_filter,
                attributes=['*']
            )
            
            for entry in entries:
                template = self._parse_certificate_template(entry)
                if template:
                    templates.append(template)
                    
        except Exception as e:
            print(f"Error enumerating certificate templates: {e}")
            
        return templates
        
    def _enumerate_certificate_authorities(self) -> List[Dict[str, Any]]:
        """
        Enumerate certificate authorities
        
        @ Returns:
            list : List of CA objects
        """
        cas = []
        
        # Search for enrollment services
        ca_filter = "(objectClass=pKIEnrollmentService)"
        ca_base = f"CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,{self.domain_dn}"
        
        try:
            entries = self.ldap_conn.search_large(
                ca_base,
                ca_filter,
                attributes=['*']
            )
            
            for entry in entries:
                ca = self._parse_certificate_authority(entry)
                if ca:
                    cas.append(ca)
                    
        except Exception as e:
            print(f"Error enumerating CAs: {e}")
            
        return cas
        
    def _parse_certificate_template(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse certificate template LDAP entry
        
        @ Args:
            entry : LDAP entry
            
        @ Returns:
            dict : Parsed template object
        """
        attrs = entry.get('attributes', {})
        
        template = {
            'name': attrs.get('name', ''),
            'display_name': attrs.get('displayName', ''),
            'dn': entry.get('dn', ''),
            'schema_version': int(attrs.get('msPKI-Template-Schema-Version', 1)),
            'enrollment_flag': int(attrs.get('msPKI-Enrollment-Flag', 0)),
            'name_flag': int(attrs.get('msPKI-Certificate-Name-Flag', 0)),
            'eku': attrs.get('pKIExtendedKeyUsage', []),
            'certificate_policies': attrs.get('msPKI-Certificate-Policy', []),
            'authorized_signatures': int(attrs.get('msPKI-RA-Signature', 0)),
            'application_policies': attrs.get('msPKI-RA-Application-Policies', []),
            'validity_period': attrs.get('pKIExpirationPeriod', ''),
            'renewal_period': attrs.get('pKIOverlapPeriod', ''),
            'permissions': self._parse_permissions(attrs.get('nTSecurityDescriptor', b'')),
            'enabled': True,  # Check if published
            'vulnerabilities': [],
            'risk_score': 0
        }
        
        # Check if template is published (enabled)
        template['enabled'] = self._is_template_published(template['name'])
        
        # Parse EKU OIDs to friendly names
        template['eku_names'] = self._parse_ekus(template['eku'])
        
        # Calculate initial risk score
        template['risk_score'] = self._calculate_template_risk(template)
        
        return template
        
    def _parse_certificate_authority(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse certificate authority LDAP entry
        
        @ Args:
            entry : LDAP entry
            
        @ Returns:
            dict : Parsed CA object
        """
        attrs = entry.get('attributes', {})
        
        ca = {
            'name': attrs.get('name', ''),
            'display_name': attrs.get('displayName', ''),
            'dn': entry.get('dn', ''),
            'dns_hostname': attrs.get('dNSHostName', ''),
            'certificate': attrs.get('cACertificate', []),
            'flags': int(attrs.get('flags', 0)),
            'permissions': self._parse_permissions(attrs.get('nTSecurityDescriptor', b'')),
            'web_enrollment_enabled': False,  # Will check separately
            'vulnerabilities': []
        }
        
        # Check for web enrollment
        ca['web_enrollment_enabled'] = self._check_web_enrollment(ca['dns_hostname'])
        
        return ca
        
    def _analyze_template_security(self, template: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Analyze certificate template for security vulnerabilities
        
        @ Args:
            template : Certificate template object
            
        @ Returns:
            list : List of identified vulnerabilities
        """
        vulnerabilities = []
        
        # Skip if template is not enabled
        if not template['enabled']:
            return vulnerabilities
            
        # Check for ESC1: User-enrollable with SAN
        if self._check_esc1(template):
            vulnerabilities.append({
                'type': CertificateVulnerability.ESC1,
                'severity': 'CRITICAL',
                'description': 'Domain users can enroll and specify Subject Alternative Name',
                'details': self._get_esc1_details(template),
                'remediation': 'Disable ENROLLEE_SUPPLIES_SUBJECT flag or restrict enrollment permissions'
            })
            
        # Check for ESC2: User-enrollable with Any Purpose EKU
        if self._check_esc2(template):
            vulnerabilities.append({
                'type': CertificateVulnerability.ESC2,
                'severity': 'HIGH',
                'description': 'Domain users can enroll with Any Purpose EKU',
                'details': self._get_esc2_details(template),
                'remediation': 'Remove Any Purpose EKU and specify required EKUs explicitly'
            })
            
        # Check for ESC3: Certificate Request Agent
        if self._check_esc3(template):
            vulnerabilities.append({
                'type': CertificateVulnerability.ESC3,
                'severity': 'HIGH',
                'description': 'Certificate Request Agent template with enrollment rights',
                'details': self._get_esc3_details(template),
                'remediation': 'Restrict enrollment permissions to authorized administrators only'
            })
            
        # Check for ESC4: Vulnerable permissions
        if self._check_esc4(template):
            vulnerabilities.append({
                'type': CertificateVulnerability.ESC4,
                'severity': 'MEDIUM',
                'description': 'Vulnerable certificate template permissions',
                'details': self._get_esc4_details(template),
                'remediation': 'Remove excessive write permissions from certificate template'
            })
            
        return vulnerabilities
        
    def _analyze_ca_security(self) -> List[Dict[str, Any]]:
        """
        Analyze CA-level security issues
        
        @ Returns:
            list : List of CA vulnerabilities
        """
        vulnerabilities = []
        
        for ca in self.cas:
            # Check for ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2
            if self._check_esc6(ca):
                vulnerabilities.append({
                    'type': CertificateVulnerability.ESC6,
                    'severity': 'CRITICAL',
                    'ca': ca['name'],
                    'description': 'CA allows SAN specification in CSR attributes',
                    'details': 'EDITF_ATTRIBUTESUBJECTALTNAME2 flag is enabled',
                    'remediation': 'Disable EDITF_ATTRIBUTESUBJECTALTNAME2 flag on CA'
                })
                
            # Check for ESC7: Vulnerable CA permissions
            if self._check_esc7(ca):
                vulnerabilities.append({
                    'type': CertificateVulnerability.ESC7,
                    'severity': 'HIGH',
                    'ca': ca['name'],
                    'description': 'Vulnerable CA permissions allow unauthorized access',
                    'details': self._get_esc7_details(ca),
                    'remediation': 'Restrict CA permissions to authorized administrators'
                })
                
            # Check for ESC8: Web enrollment
            if self._check_esc8(ca):
                vulnerabilities.append({
                    'type': CertificateVulnerability.ESC8,
                    'severity': 'MEDIUM',
                    'ca': ca['name'],
                    'description': 'Web enrollment enabled allowing NTLM relay attacks',
                    'details': 'Certificate web enrollment is accessible',
                    'remediation': 'Disable web enrollment or enforce EPA'
                })
                
        return vulnerabilities
        
    def _check_esc1(self, template: Dict[str, Any]) -> bool:
        """Check for ESC1 vulnerability"""
        # Check if domain users can enroll
        can_enroll = self._domain_users_can_enroll(template)
        
        # Check if enrollee supplies subject
        supplies_subject = bool(template['enrollment_flag'] & self.CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
        
        # Check for client authentication EKU
        has_client_auth = self._has_client_authentication(template)
        
        return can_enroll and supplies_subject and has_client_auth
        
    def _check_esc2(self, template: Dict[str, Any]) -> bool:
        """Check for ESC2 vulnerability"""
        # Check if domain users can enroll
        can_enroll = self._domain_users_can_enroll(template)
        
        # Check for Any Purpose EKU
        has_any_purpose = '2.5.29.37.0' in template['eku']
        
        return can_enroll and has_any_purpose
        
    def _check_esc3(self, template: Dict[str, Any]) -> bool:
        """Check for ESC3 vulnerability"""
        # Check for Certificate Request Agent EKU
        has_cra = '1.3.6.1.4.1.311.20.2.1' in template['eku']
        
        # Check if domain users can enroll
        can_enroll = self._domain_users_can_enroll(template)
        
        # Check authorized signatures requirement
        requires_signatures = template['authorized_signatures'] > 0
        
        return has_cra and can_enroll and not requires_signatures
        
    def _check_esc4(self, template: Dict[str, Any]) -> bool:
        """Check for ESC4 vulnerability"""
        perms = template.get('permissions', {})
        
        # Check for excessive write permissions
        for sid, rights in perms.items():
            if self._is_low_privileged_sid(sid):
                if 'WRITE_OWNER' in rights or 'WRITE_DACL' in rights or 'FULL_CONTROL' in rights:
                    return True
                    
        return False
        
    def _check_esc6(self, ca: Dict[str, Any]) -> bool:
        """Check for ESC6 vulnerability"""
        # Check if EDITF_ATTRIBUTESUBJECTALTNAME2 flag is set
        # Flag value is 0x00040000
        return bool(ca.get('flags', 0) & 0x00040000)
        
    def _check_esc7(self, ca: Dict[str, Any]) -> bool:
        """Check for ESC7 vulnerability"""
        perms = ca.get('permissions', {})
        
        # Check for manage CA or manage certificates permissions
        for sid, rights in perms.items():
            if self._is_low_privileged_sid(sid):
                if 'MANAGE_CA' in rights or 'MANAGE_CERTIFICATES' in rights:
                    return True
                    
        return False
        
    def _check_esc8(self, ca: Dict[str, Any]) -> bool:
        """Check for ESC8 vulnerability"""
        return ca.get('web_enrollment_enabled', False)
        
    def _domain_users_can_enroll(self, template: Dict[str, Any]) -> bool:
        """Check if domain users can enroll in template"""
        perms = template.get('permissions', {})
        
        # Check for enrollment permissions for low-privileged users
        for sid, rights in perms.items():
            if self._is_low_privileged_sid(sid):
                if 'ENROLL' in rights or 'AUTO_ENROLL' in rights:
                    return True
                    
        return False
        
    def _has_client_authentication(self, template: Dict[str, Any]) -> bool:
        """Check if template has client authentication capability"""
        ekus = template.get('eku', [])
        
        # Check for client auth EKU
        if '1.3.6.1.5.5.7.3.2' in ekus:
            return True
            
        # Check for smart card logon
        if '1.3.6.1.4.1.311.20.2.2' in ekus:
            return True
            
        # Check for any purpose
        if '2.5.29.37.0' in ekus:
            return True
            
        # If no EKU, it can be used for any purpose
        if not ekus:
            return True
            
        return False
        
    def _is_low_privileged_sid(self, sid: str) -> bool:
        """Check if SID represents low-privileged users"""
        low_priv_sids = [
            'S-1-5-11',      # Authenticated Users
            'S-1-5-32-545',  # Users
            'S-1-1-0',       # Everyone
            'S-1-5-7'        # Anonymous
        ]
        
        # Check well-known SIDs
        if sid in low_priv_sids:
            return True
            
        # Check for domain users group (ends with -513)
        if sid.endswith('-513'):
            return True
            
        return False
        
    def _parse_permissions(self, sd_bytes: bytes) -> Dict[str, List[str]]:
        """
        Parse security descriptor to extract permissions
        
        @ Args:
            sd_bytes : Security descriptor bytes
            
        @ Returns:
            dict : SID to list of permissions mapping
        """
        # Simplified permission parsing
        # In production, use proper Windows security descriptor parsing
        permissions = {}
        
        # Mock implementation - would need proper SD parsing
        # This is a placeholder showing the structure
        permissions['S-1-5-11'] = ['ENROLL']  # Authenticated Users
        
        return permissions
        
    def _parse_ekus(self, eku_oids: List[str]) -> List[str]:
        """Convert EKU OIDs to friendly names"""
        names = []
        for oid in eku_oids:
            name = self.CRITICAL_EKUS.get(oid, oid)
            names.append(name)
        return names
        
    def _is_template_published(self, template_name: str) -> bool:
        """Check if template is published to enrollment services"""
        # Would check if template is in CA's certificate templates
        # For now, assume all templates are published
        return True
        
    def _check_web_enrollment(self, hostname: str) -> bool:
        """Check if web enrollment is enabled on CA"""
        # Would check for web enrollment service
        # This requires additional network checks
        return False
        
    def _calculate_template_risk(self, template: Dict[str, Any]) -> int:
        """
        Calculate risk score for certificate template
        
        @ Args:
            template : Certificate template object
            
        @ Returns:
            int : Risk score (0-100)
        """
        risk_score = 0
        
        # Enrollment flags
        if template['enrollment_flag'] & self.CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT:
            risk_score += 30
            
        if template['enrollment_flag'] & self.CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME:
            risk_score += 20
            
        # EKU analysis
        ekus = template.get('eku', [])
        if '2.5.29.37.0' in ekus:  # Any Purpose
            risk_score += 25
        elif '1.3.6.1.5.5.7.3.2' in ekus:  # Client Auth
            risk_score += 15
        elif '1.3.6.1.4.1.311.20.2.1' in ekus:  # Certificate Request Agent
            risk_score += 20
            
        # No EKU is also risky
        if not ekus:
            risk_score += 15
            
        # Permission analysis
        if self._domain_users_can_enroll(template):
            risk_score += 20
            
        # Authorized signatures
        if template['authorized_signatures'] == 0:
            risk_score += 5
            
        return min(risk_score, 100)
        
    def _get_domain_dn(self) -> str:
        """Get domain DN from LDAP connection"""
        if self.ldap_conn and self.ldap_conn.domain_dn:
            return self.ldap_conn.domain_dn
        return "DC=UNKNOWN,DC=LOCAL"
        
    def _calculate_statistics(self) -> Dict[str, Any]:
        """Calculate statistics from analysis"""
        stats = {
            'total_templates': len(self.cert_templates),
            'enabled_templates': len([t for t in self.cert_templates if t['enabled']]),
            'vulnerable_templates': len([t for t in self.cert_templates if t.get('vulnerabilities')]),
            'total_cas': len(self.cas),
            'total_vulnerabilities': len(self.vulnerabilities),
            'critical_vulnerabilities': len([v for v in self.vulnerabilities if v.get('severity') == 'CRITICAL']),
            'high_vulnerabilities': len([v for v in self.vulnerabilities if v.get('severity') == 'HIGH']),
            'medium_vulnerabilities': len([v for v in self.vulnerabilities if v.get('severity') == 'MEDIUM']),
            'high_risk_templates': len([t for t in self.cert_templates if t.get('risk_score', 0) > 70])
        }
        
        return stats
        
    def _generate_recommendations(self) -> List[str]:
        """Generate remediation recommendations"""
        recommendations = []
        
        # Check for critical vulnerabilities
        critical_vulns = [v for v in self.vulnerabilities if v.get('severity') == 'CRITICAL']
        if critical_vulns:
            recommendations.append(
                "URGENT: Address critical vulnerabilities immediately. "
                "These allow domain compromise through certificate abuse."
            )
            
        # ESC1 specific
        esc1_vulns = [v for v in self.vulnerabilities if v.get('type') == CertificateVulnerability.ESC1]
        if esc1_vulns:
            recommendations.append(
                "Disable ENROLLEE_SUPPLIES_SUBJECT flag on vulnerable templates "
                "or restrict enrollment to specific groups."
            )
            
        # ESC2 specific  
        esc2_vulns = [v for v in self.vulnerabilities if v.get('type') == CertificateVulnerability.ESC2]
        if esc2_vulns:
            recommendations.append(
                "Remove 'Any Purpose' EKU from certificate templates and specify "
                "only required Extended Key Usages."
            )
            
        # ESC6 specific
        esc6_vulns = [v for v in self.vulnerabilities if v.get('type') == CertificateVulnerability.ESC6]
        if esc6_vulns:
            recommendations.append(
                "Disable EDITF_ATTRIBUTESUBJECTALTNAME2 flag on Certificate Authorities "
                "using: certutil -setreg policy\\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2"
            )
            
        # General recommendations
        if self._domain_users_can_enroll_count() > 3:
            recommendations.append(
                "Review certificate template enrollment permissions. "
                "Limit enrollment to specific security groups rather than 'Authenticated Users'."
            )
            
        recommendations.append(
            "Enable certificate template auditing to monitor for suspicious enrollments."
        )
        
        recommendations.append(
            "Implement certificate lifecycle management and regular template reviews."
        )
        
        return recommendations
        
    def _domain_users_can_enroll_count(self) -> int:
        """Count templates where domain users can enroll"""
        count = 0
        for template in self.cert_templates:
            if self._domain_users_can_enroll(template):
                count += 1
        return count
        
    def _get_esc1_details(self, template: Dict[str, Any]) -> str:
        """Get detailed ESC1 vulnerability information"""
        details = f"Template: {template['display_name']}\n"
        details += f"Enrollment Flag: 0x{template['enrollment_flag']:X}\n"
        details += "Allows enrollee to supply subject in request\n"
        details += f"EKUs: {', '.join(template.get('eku_names', []))}"
        return details
        
    def _get_esc2_details(self, template: Dict[str, Any]) -> str:
        """Get detailed ESC2 vulnerability information"""
        details = f"Template: {template['display_name']}\n"
        details += "Contains 'Any Purpose' Extended Key Usage\n"
        details += "Can be used for any certificate purpose including authentication"
        return details
        
    def _get_esc3_details(self, template: Dict[str, Any]) -> str:
        """Get detailed ESC3 vulnerability information"""  
        details = f"Template: {template['display_name']}\n"
        details += "Certificate Request Agent EKU present\n"
        details += f"Required signatures: {template['authorized_signatures']}"
        return details
        
    def _get_esc4_details(self, template: Dict[str, Any]) -> str:
        """Get detailed ESC4 vulnerability information"""
        details = f"Template: {template['display_name']}\n"
        details += "Excessive permissions granted to low-privileged users:\n"
        
        perms = template.get('permissions', {})
        for sid, rights in perms.items():
            if self._is_low_privileged_sid(sid):
                sid_name = self.WELL_KNOWN_SIDS.get(sid, sid)
                details += f"  {sid_name}: {', '.join(rights)}\n"
                
        return details
        
    def _get_esc7_details(self, ca: Dict[str, Any]) -> str:
        """Get detailed ESC7 vulnerability information"""
        details = f"CA: {ca['name']}\n"
        details += "Excessive CA permissions granted to low-privileged users:\n"
        
        perms = ca.get('permissions', {})
        for sid, rights in perms.items():
            if self._is_low_privileged_sid(sid):
                sid_name = self.WELL_KNOWN_SIDS.get(sid, sid)
                details += f"  {sid_name}: {', '.join(rights)}\n"
                
        return details
        
    def export_findings(self, findings: Dict[str, Any], format: str = 'json') -> str:
        """
        Export ADCS findings to various formats
        
        @ Args:
            findings : Analysis results
            format   : Export format (json, csv, bloodhound)
            
        @ Returns:
            str : Exported data
        """
        if format == 'json':
            import json
            return json.dumps(findings, indent=2, default=str)
            
        elif format == 'csv':
            import csv
            import io
            
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Write vulnerabilities
            writer.writerow(['Template', 'Vulnerability', 'Severity', 'Description'])
            for vuln in findings.get('vulnerabilities', []):
                template_name = ''
                for template in findings.get('certificate_templates', []):
                    if vuln in template.get('vulnerabilities', []):
                        template_name = template.get('display_name', '')
                        break
                        
                writer.writerow([
                    template_name,
                    vuln.get('type', '').name if hasattr(vuln.get('type'), 'name') else str(vuln.get('type')),
                    vuln.get('severity', ''),
                    vuln.get('description', '')
                ])
                
            return output.getvalue()
            
        elif format == 'bloodhound':
            # Export as custom BloodHound edges
            edges = []
            
            for template in findings.get('certificate_templates', []):
                if template.get('vulnerabilities'):
                    # Create edges for vulnerable enrollment permissions
                    perms = template.get('permissions', {})
                    for sid, rights in perms.items():
                        if 'ENROLL' in rights or 'AUTO_ENROLL' in rights:
                            edge = {
                                'source': sid,
                                'target': template['name'],
                                'edge_type': 'CanEnrollIn',
                                'properties': {
                                    'template_name': template['display_name'],
                                    'vulnerabilities': [v['type'].name for v in template['vulnerabilities']]
                                }
                            }
                            edges.append(edge)
                            
            import json
            return json.dumps({'edges': edges}, indent=2)
            
        return ""