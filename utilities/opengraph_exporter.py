#!/usr/bin/env python3
# WIP - Not done yet but taken the standard and written some handlers for it 
"""
OpenGraph Exporter Module for pyLDAPGui

~ Description : Exports LDAP data to BloodHound OpenGraph format
                Supports the new schema format with enhanced metadata
                and relationship types

@ Features:
  - OpenGraph schema compliance
  - Enhanced metadata support
  - Typed relationships with properties
  - Session and temporal data support
  - Backward compatibility flags

@ Author: ZephrFish
@ License: MIT
"""

import json
import zipfile
import uuid
from typing import List, Dict, Any, Optional, Set
from datetime import datetime
import hashlib
import os


class OpenGraphExporter:
    """
    Export LDAP data to BloodHound OpenGraph format
    
    ~ Description : Implements the new OpenGraph schema with enhanced
                    type safety and metadata support
    """
    
    # OpenGraph schema version
    SCHEMA_VERSION = "5.0"
    
    # Object type mappings for OpenGraph
    OBJECT_TYPES = {
        'user': 'User',
        'computer': 'Computer', 
        'group': 'Group',
        'domain': 'Domain',
        'ou': 'OrganizationalUnit',
        'gpo': 'GroupPolicyObject',
        'container': 'Container',
        'foreignsecurityprincipal': 'ForeignSecurityPrincipal',
        'trustdomain': 'TrustDomain'
    }
    
    # Relationship types in OpenGraph
    RELATIONSHIP_TYPES = {
        'MemberOf': {'source': ['User', 'Computer', 'Group'], 'target': ['Group']},
        'AdminTo': {'source': ['User', 'Group'], 'target': ['Computer']},
        'CanRDP': {'source': ['User', 'Group'], 'target': ['Computer']},
        'CanPSRemote': {'source': ['User', 'Group'], 'target': ['Computer']},
        'ExecuteDCOM': {'source': ['User', 'Group'], 'target': ['Computer']},
        'HasSession': {'source': ['Computer'], 'target': ['User']},
        'Contains': {'source': ['Domain', 'OrganizationalUnit', 'Container'], 'target': ['*']},
        'TrustedBy': {'source': ['Domain'], 'target': ['Domain']},
        'GPLink': {'source': ['OrganizationalUnit', 'Domain'], 'target': ['GroupPolicyObject']},
        'Owns': {'source': ['User', 'Group'], 'target': ['*']},
        'GenericAll': {'source': ['*'], 'target': ['*']},
        'GenericWrite': {'source': ['*'], 'target': ['*']},
        'WriteOwner': {'source': ['*'], 'target': ['*']},
        'WriteDacl': {'source': ['*'], 'target': ['*']},
        'AddMember': {'source': ['*'], 'target': ['Group']},
        'ForceChangePassword': {'source': ['*'], 'target': ['User']},
        'ExtendedRight': {'source': ['*'], 'target': ['*']},
        'DCSync': {'source': ['*'], 'target': ['Domain']},
        'GetChanges': {'source': ['*'], 'target': ['Domain']},
        'GetChangesAll': {'source': ['*'], 'target': ['Domain']},
        'AllExtendedRights': {'source': ['*'], 'target': ['*']}
    }
    
    def __init__(self):
        """Initialize OpenGraph exporter"""
        self.timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        self.session_id = str(uuid.uuid4())
        self.collection_method = "LDAP"
        
    def export_to_opengraph(self, entries: List[Dict[str, Any]], 
                           filename: str, 
                           include_session_data: bool = False) -> str:
        """
        Export LDAP entries to OpenGraph format
        
        @ Args:
            entries              : List of LDAP entries
            filename             : Output filename
            include_session_data : Include session and temporal data
            
        @ Returns:
            str : Path to created ZIP file
            
        @ Raises:
            ValueError : If no entries provided
        """
        if not entries:
            raise ValueError("No entries to export")
            
        # Detect domain
        domain_name = self._find_domain_name(entries)
        
        # Process entries by type with enhanced metadata
        processed_data = {
            'nodes': {},
            'relationships': [],
            'metadata': {
                'version': self.SCHEMA_VERSION,
                'collection_method': self.collection_method,
                'collection_timestamp': datetime.now().isoformat(),
                'session_id': self.session_id,
                'domain': domain_name,
                'total_objects': len(entries)
            }
        }
        
        # Initialize node type containers
        for obj_type in self.OBJECT_TYPES.values():
            processed_data['nodes'][obj_type] = []
            
        # Process each entry
        for entry in entries:
            node = self._create_opengraph_node(entry, domain_name, include_session_data)
            if node:
                obj_type = node['type']
                if obj_type in processed_data['nodes']:
                    processed_data['nodes'][obj_type].append(node)
                    
        # Create relationships
        relationships = self._extract_relationships(entries, domain_name)
        processed_data['relationships'] = relationships
        
        # Add statistics
        processed_data['metadata']['statistics'] = self._calculate_statistics(processed_data)
        
        # Create ZIP file
        zip_filename = self._create_opengraph_zip(filename, processed_data)
        
        return zip_filename
        
    def _create_opengraph_node(self, entry: Dict[str, Any], 
                              domain: str,
                              include_session_data: bool) -> Optional[Dict[str, Any]]:
        """
        Create OpenGraph node from LDAP entry
        
        @ Args:
            entry                : LDAP entry
            domain               : Domain name
            include_session_data : Include session data
            
        @ Returns:
            dict : OpenGraph node or None
        """
        attrs = entry.get('attributes', {})
        obj_type = self._classify_entry_type(entry)
        
        if obj_type == 'unknown':
            return None
            
        # Extract common properties
        sid = self._extract_sid(attrs)
        if not sid and obj_type not in ['ou', 'container']:
            return None
            
        node_id = sid or self._generate_guid_from_dn(entry['dn'])
        
        # Base node structure
        node = {
            'id': node_id,
            'type': self.OBJECT_TYPES.get(obj_type, 'Unknown'),
            'label': self._extract_label(entry, domain),
            'properties': {
                'name': self._extract_name(entry, domain),
                'domain': domain,
                'distinguishedname': entry['dn'],
                'objectid': node_id,
                'lastseen': datetime.now().isoformat()
            }
        }
        
        # Add type-specific properties
        if obj_type == 'user':
            self._add_user_properties(node, attrs, include_session_data)
        elif obj_type == 'computer':
            self._add_computer_properties(node, attrs, include_session_data)
        elif obj_type == 'group':
            self._add_group_properties(node, attrs)
        elif obj_type == 'domain':
            self._add_domain_properties(node, attrs)
        elif obj_type == 'ou':
            self._add_ou_properties(node, attrs)
            
        # Add metadata
        node['metadata'] = {
            'collected': datetime.now().isoformat(),
            'collection_method': self.collection_method,
            'session_id': self.session_id if include_session_data else None
        }
        
        return node
        
    def _add_user_properties(self, node: Dict[str, Any], 
                           attrs: Dict[str, Any],
                           include_session_data: bool):
        """Add user-specific properties to node"""
        props = node['properties']
        
        # Basic properties
        props['samaccountname'] = attrs.get('sAMAccountName', '')
        props['userprincipalname'] = attrs.get('userPrincipalName')
        props['displayname'] = attrs.get('displayName')
        props['description'] = self._get_single_value(attrs.get('description'))
        props['email'] = attrs.get('mail')
        props['title'] = attrs.get('title')
        props['department'] = attrs.get('department')
        
        # Security properties
        props['enabled'] = True
        props['pwdlastset'] = self._convert_timestamp(attrs.get('pwdLastSet', 0))
        props['lastlogon'] = self._convert_timestamp(attrs.get('lastLogon', 0))
        props['lastlogontimestamp'] = self._convert_timestamp(attrs.get('lastLogonTimestamp', 0))
        props['admincount'] = bool(attrs.get('adminCount', 0))
        props['sensitive'] = False
        props['dontreqpreauth'] = False
        props['passwordnotreqd'] = False
        props['unconstraineddelegation'] = False
        props['trustedtoauth'] = False
        props['isdelegate'] = False
        
        # Parse userAccountControl
        if 'userAccountControl' in attrs:
            try:
                uac = int(attrs['userAccountControl'])
                props['enabled'] = not bool(uac & 0x2)
                props['passwordnotreqd'] = bool(uac & 0x20)
                props['sensitive'] = bool(uac & 0x100000)
                props['dontreqpreauth'] = bool(uac & 0x400000)
                props['unconstraineddelegation'] = bool(uac & 0x80000)
                props['trustedtoauth'] = bool(uac & 0x1000000)
            except (ValueError, TypeError):
                pass
                
        # Service Principal Names
        spns = attrs.get('servicePrincipalName', [])
        if spns:
            if isinstance(spns, str):
                spns = [spns]
            props['serviceprincipalnames'] = spns
            props['hasspn'] = True
        else:
            props['serviceprincipalnames'] = []
            props['hasspn'] = False
            
        # Session data (if requested)
        if include_session_data:
            props['sessions'] = []
            props['loggedon'] = []
            
        # Risk score calculation
        risk_score = 0
        if props['admincount']:
            risk_score += 30
        if props['unconstraineddelegation']:
            risk_score += 40
        if props['dontreqpreauth']:
            risk_score += 20
        if props['passwordnotreqd']:
            risk_score += 15
        if props['hasspn'] and not props['admincount']:
            risk_score += 10
            
        props['risk_score'] = min(risk_score, 100)
        
    def _add_computer_properties(self, node: Dict[str, Any], 
                                attrs: Dict[str, Any],
                                include_session_data: bool):
        """Add computer-specific properties to node"""
        props = node['properties']
        
        # Basic properties
        props['samaccountname'] = attrs.get('sAMAccountName', '')
        props['operatingsystem'] = attrs.get('operatingSystem')
        props['operatingsystemversion'] = attrs.get('operatingSystemVersion')
        props['description'] = self._get_single_value(attrs.get('description'))
        props['dnshostname'] = attrs.get('dNSHostName')
        
        # Security properties
        props['enabled'] = True
        props['unconstraineddelegation'] = False
        props['trustedtoauth'] = False
        props['isdc'] = self._is_domain_controller(attrs)
        props['lastlogon'] = self._convert_timestamp(attrs.get('lastLogon', 0))
        props['lastlogontimestamp'] = self._convert_timestamp(attrs.get('lastLogonTimestamp', 0))
        props['laps_installed'] = 'ms-Mcs-AdmPwd' in attrs
        props['admincount'] = bool(attrs.get('adminCount', 0))
        
        # Parse userAccountControl
        if 'userAccountControl' in attrs:
            try:
                uac = int(attrs['userAccountControl'])
                props['enabled'] = not bool(uac & 0x2)
                props['unconstraineddelegation'] = bool(uac & 0x80000)
                props['trustedtoauth'] = bool(uac & 0x1000000)
            except (ValueError, TypeError):
                pass
                
        # Service Principal Names
        spns = attrs.get('servicePrincipalName', [])
        if spns:
            if isinstance(spns, str):
                spns = [spns]
            props['serviceprincipalnames'] = spns
        else:
            props['serviceprincipalnames'] = []
            
        # Session data (if requested)
        if include_session_data:
            props['sessions'] = []
            props['privilegedsessions'] = []
            props['registrysessions'] = []
            props['localadmins'] = []
            props['remotedesktopusers'] = []
            props['dcomusers'] = []
            props['psremoteusers'] = []
            
        # Risk score calculation
        risk_score = 0
        if props['isdc']:
            risk_score += 50
        if props['unconstraineddelegation']:
            risk_score += 40
        if not props['enabled']:
            risk_score -= 20
        if props['laps_installed']:
            risk_score -= 10
            
        props['risk_score'] = max(0, min(risk_score, 100))
        
    def _add_group_properties(self, node: Dict[str, Any], attrs: Dict[str, Any]):
        """Add group-specific properties to node"""
        props = node['properties']
        
        props['samaccountname'] = attrs.get('sAMAccountName', '')
        props['description'] = self._get_single_value(attrs.get('description'))
        props['admincount'] = bool(attrs.get('adminCount', 0))
        props['member_count'] = len(attrs.get('member', []))
        
        # Determine if high value group
        sam = props['samaccountname'].lower()
        high_value_groups = [
            'domain admins', 'enterprise admins', 'schema admins',
            'administrators', 'account operators', 'backup operators',
            'server operators', 'print operators', 'domain controllers',
            'read-only domain controllers', 'group policy creator owners',
            'cryptographic operators', 'distributed com users'
        ]
        
        props['highvalue'] = any(hvg in sam for hvg in high_value_groups)
        
        # Risk score
        risk_score = 0
        if props['highvalue']:
            risk_score += 50
        if props['admincount']:
            risk_score += 30
        
        props['risk_score'] = min(risk_score, 100)
        
    def _add_domain_properties(self, node: Dict[str, Any], attrs: Dict[str, Any]):
        """Add domain-specific properties to node"""
        props = node['properties']
        
        props['description'] = self._get_single_value(attrs.get('description'))
        props['functionallevel'] = self._extract_functional_level(attrs)
        props['trusts'] = 0  # Will be populated from trust relationships
        props['children'] = 0  # Will be calculated from Contains relationships
        
    def _add_ou_properties(self, node: Dict[str, Any], attrs: Dict[str, Any]):
        """Add OU-specific properties to node"""
        props = node['properties']
        
        props['description'] = self._get_single_value(attrs.get('description'))
        props['blocksinheritance'] = attrs.get('gPOptions', '0') == '1'
        props['highvalue'] = False  # Can be updated based on contents
        
    def _extract_relationships(self, entries: List[Dict[str, Any]], 
                             domain: str) -> List[Dict[str, Any]]:
        """
        Extract relationships from LDAP entries
        
        @ Args:
            entries : List of LDAP entries
            domain  : Domain name
            
        @ Returns:
            list : List of OpenGraph relationships
        """
        relationships = []
        
        # Build lookup maps
        dn_to_id = {}
        id_to_type = {}
        
        for entry in entries:
            attrs = entry.get('attributes', {})
            sid = self._extract_sid(attrs)
            obj_id = sid or self._generate_guid_from_dn(entry['dn'])
            obj_type = self._classify_entry_type(entry)
            
            dn_to_id[entry['dn'].upper()] = obj_id
            id_to_type[obj_id] = self.OBJECT_TYPES.get(obj_type, 'Unknown')
            
        # Extract group memberships
        for entry in entries:
            attrs = entry.get('attributes', {})
            obj_type = self._classify_entry_type(entry)
            
            if obj_type == 'group':
                group_id = self._extract_sid(attrs) or self._generate_guid_from_dn(entry['dn'])
                members = attrs.get('member', [])
                
                if isinstance(members, str):
                    members = [members]
                    
                for member_dn in members:
                    member_id = dn_to_id.get(member_dn.upper())
                    if member_id and member_id in id_to_type:
                        rel = {
                            'type': 'MemberOf',
                            'source': member_id,
                            'target': group_id,
                            'properties': {
                                'isacl': False,
                                'isinherited': False
                            }
                        }
                        relationships.append(rel)
                        
        # Extract container relationships
        for entry in entries:
            dn = entry['dn']
            parent_dn = self._get_parent_dn(dn)
            
            if parent_dn and parent_dn.upper() in dn_to_id:
                obj_id = dn_to_id.get(dn.upper())
                parent_id = dn_to_id.get(parent_dn.upper())
                
                if obj_id and parent_id:
                    rel = {
                        'type': 'Contains',
                        'source': parent_id,
                        'target': obj_id,
                        'properties': {
                            'isacl': False,
                            'isinherited': True
                        }
                    }
                    relationships.append(rel)
                    
        return relationships
        
    def _create_opengraph_zip(self, filename: str, 
                            data: Dict[str, Any]) -> str:
        """
        Create OpenGraph ZIP file
        
        @ Args:
            filename : Base filename
            data     : Processed OpenGraph data
            
        @ Returns:
            str : Path to created ZIP file
        """
        base_name = os.path.splitext(filename)[0]
        zip_filename = f"{base_name}_{self.timestamp}_OpenGraph.zip"
        
        with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as zf:
            # Write metadata file
            metadata_content = {
                'version': self.SCHEMA_VERSION,
                'type': 'openGraph',
                'metadata': data['metadata']
            }
            zf.writestr('metadata.json', 
                       json.dumps(metadata_content, indent=2))
            
            # Write nodes by type
            for node_type, nodes in data['nodes'].items():
                if nodes:
                    node_content = {
                        'type': node_type,
                        'count': len(nodes),
                        'nodes': nodes
                    }
                    json_filename = f"nodes_{node_type.lower()}.json"
                    zf.writestr(json_filename,
                               json.dumps(node_content, indent=2))
                    
            # Write relationships
            if data['relationships']:
                rel_content = {
                    'count': len(data['relationships']),
                    'relationships': data['relationships']
                }
                zf.writestr('relationships.json',
                           json.dumps(rel_content, indent=2))
                           
        return zip_filename
        
    def _classify_entry_type(self, entry: Dict[str, Any]) -> str:
        """Classify LDAP entry type"""
        attrs = entry.get('attributes', {})
        classes = attrs.get('objectClass', [])
        if isinstance(classes, str):
            classes = [classes]
        classes_lower = [c.lower() for c in classes]
        
        sam = attrs.get('sAMAccountName', '')
        
        # Check specific object classes
        if 'computer' in classes_lower:
            return 'computer'
        elif 'group' in classes_lower:
            return 'group'
        elif 'organizationalunit' in classes_lower:
            return 'ou'
        elif 'domaindns' in classes_lower:
            return 'domain'
        elif 'foreignsecurityprincipal' in classes_lower:
            return 'foreignsecurityprincipal'
        elif 'grouppolicycontainer' in classes_lower:
            return 'gpo'
        elif 'container' in classes_lower:
            return 'container'
        elif 'trusteddomain' in classes_lower:
            return 'trustdomain'
        elif ('user' in classes_lower or 'person' in classes_lower) and \
             sam and not sam.endswith('$'):
            return 'user'
            
        return 'unknown'
        
    def _extract_sid(self, attrs: Dict[str, Any]) -> Optional[str]:
        """Extract SID from objectSid attribute"""
        if 'objectSid' not in attrs:
            return None
            
        sid_data = attrs['objectSid']
        if isinstance(sid_data, str):
            return sid_data
            
        try:
            # Parse binary SID
            if isinstance(sid_data, bytes) and len(sid_data) >= 8:
                revision = sid_data[0]
                sub_authority_count = sid_data[1]
                identifier_authority = int.from_bytes(sid_data[2:8], 
                                                     byteorder='big')
                
                sid = f"S-{revision}-{identifier_authority}"
                
                for i in range(sub_authority_count):
                    offset = 8 + (i * 4)
                    if offset + 4 <= len(sid_data):
                        sub_authority = int.from_bytes(
                            sid_data[offset:offset + 4], byteorder='little'
                        )
                        sid += f"-{sub_authority}"
                
                return sid
        except Exception:
            pass
            
        return None
        
    def _extract_name(self, entry: Dict[str, Any], domain: str) -> str:
        """Extract name for object"""
        attrs = entry.get('attributes', {})
        sam = attrs.get('sAMAccountName', '')
        
        if sam:
            obj_type = self._classify_entry_type(entry)
            if obj_type == 'computer':
                return f"{sam.rstrip('$').upper()}.{domain}"
            else:
                return f"{sam.upper()}@{domain}"
                
        # For OUs and containers
        dn = entry['dn']
        if '=' in dn:
            name = dn.split(',')[0].split('=')[1]
            return f"{name.upper()}@{domain}"
            
        return f"UNKNOWN@{domain}"
        
    def _extract_label(self, entry: Dict[str, Any], domain: str) -> str:
        """Extract display label for object"""
        attrs = entry.get('attributes', {})
        
        # Try display name first
        display_name = attrs.get('displayName')
        if display_name:
            return display_name
            
        # Fall back to name
        return self._extract_name(entry, domain)
        
    def _find_domain_name(self, entries: List[Dict[str, Any]]) -> str:
        """Extract domain name from entries"""
        for entry in entries:
            domain = self._extract_domain_from_dn(entry.get('dn', ''))
            if domain and domain != 'UNKNOWN':
                return domain.upper()
        return 'UNKNOWN.LOCAL'
        
    def _extract_domain_from_dn(self, dn: str) -> str:
        """Extract domain from DN"""
        parts = []
        for component in dn.split(','):
            component = component.strip()
            if component.upper().startswith('DC='):
                parts.append(component[3:])
        return '.'.join(parts) if parts else 'UNKNOWN'
        
    def _generate_guid_from_dn(self, dn: str) -> str:
        """Generate GUID from DN"""
        hash_obj = hashlib.md5(dn.encode()).hexdigest()
        return (f"{hash_obj[0:8]}-{hash_obj[8:12]}-{hash_obj[12:16]}-"
                f"{hash_obj[16:20]}-{hash_obj[20:32]}").upper()
                
    def _get_single_value(self, value: Any) -> Optional[str]:
        """Extract single value from attribute"""
        if isinstance(value, list):
            return value[0] if value else None
        return value
        
    def _convert_timestamp(self, timestamp: Any) -> int:
        """Convert LDAP timestamp to Unix timestamp"""
        if not timestamp:
            return -1
            
        try:
            if isinstance(timestamp, str):
                timestamp = int(timestamp)
            if timestamp > 0:
                # LDAP timestamps are in 100-nanosecond intervals since 1601
                return int((timestamp / 10000000) - 11644473600)
        except:
            pass
            
        return -1
        
    def _is_domain_controller(self, attrs: Dict[str, Any]) -> bool:
        """Check if computer is a domain controller"""
        uac = attrs.get('userAccountControl', 0)
        try:
            uac = int(uac)
            return bool(uac & 0x2000)  # SERVER_TRUST_ACCOUNT
        except:
            return False
            
    def _extract_functional_level(self, attrs: Dict[str, Any]) -> str:
        """Extract domain functional level"""
        level = attrs.get('msDS-Behavior-Version', '10')
        
        level_map = {
            '0': '2000',
            '1': '2003',
            '2': '2003',
            '3': '2008',
            '4': '2008 R2',
            '5': '2012',
            '6': '2012 R2',
            '7': '2016',
            '10': '2019'
        }
        
        return level_map.get(str(level), '2016')
        
    def _get_parent_dn(self, dn: str) -> Optional[str]:
        """Get parent DN from DN"""
        parts = dn.split(',', 1)
        return parts[1] if len(parts) > 1 else None
        
    def _calculate_statistics(self, data: Dict[str, Any]) -> Dict[str, int]:
        """Calculate statistics for the export"""
        stats = {
            'total_nodes': 0,
            'total_relationships': len(data['relationships'])
        }
        
        for node_type, nodes in data['nodes'].items():
            count = len(nodes)
            stats[f'{node_type.lower()}_count'] = count
            stats['total_nodes'] += count
            
        # Calculate high-value statistics
        high_value_count = 0
        high_risk_count = 0
        
        for node_type, nodes in data['nodes'].items():
            for node in nodes:
                props = node.get('properties', {})
                if props.get('highvalue'):
                    high_value_count += 1
                if props.get('risk_score', 0) > 50:
                    high_risk_count += 1
                    
        stats['high_value_count'] = high_value_count
        stats['high_risk_count'] = high_risk_count
        
        return stats