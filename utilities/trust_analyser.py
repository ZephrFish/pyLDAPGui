import ldap3
from typing import List, Dict, Any, Optional
from datetime import datetime


class TrustAnalyser:
    """
    Analyse and enumerate domain trusts from LDAP
    """
    
    # Trust type flags
    TRUST_TYPE_MIT = 0x00000001  # MIT Kerberos trust
    TRUST_TYPE_WINDOWS = 0x00000002  # Windows trust
    TRUST_TYPE_DCE = 0x00000004  # DCE trust
    
    # Trust attribute flags
    TRUST_ATTRIBUTE_NON_TRANSITIVE = 0x00000001
    TRUST_ATTRIBUTE_UPLEVEL_ONLY = 0x00000002
    TRUST_ATTRIBUTE_QUARANTINED_DOMAIN = 0x00000004
    TRUST_ATTRIBUTE_FOREST_TRANSITIVE = 0x00000008
    TRUST_ATTRIBUTE_CROSS_ORGANIZATION = 0x00000010
    TRUST_ATTRIBUTE_WITHIN_FOREST = 0x00000020
    TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL = 0x00000040
    
    # Trust direction
    TRUST_DIRECTION_DISABLED = 0x00000000
    TRUST_DIRECTION_INBOUND = 0x00000001
    TRUST_DIRECTION_OUTBOUND = 0x00000002
    TRUST_DIRECTION_BIDIRECTIONAL = 0x00000003
    
    def __init__(self, ldap_connection):
        self.ldap_conn = ldap_connection
        
    def get_domain_trusts(self) -> List[Dict[str, Any]]:
        """
        Enumerate all domain trusts
        """
        if not self.ldap_conn or not self.ldap_conn.connection:
            return []
            
        trusts = []
        
        # Search for trustedDomain objects
        trust_filter = "(objectClass=trustedDomain)"
        attributes = [
            'cn', 'name', 'trustPartner', 'flatName',
            'trustDirection', 'trustType', 'trustAttributes',
            'whenCreated', 'whenChanged', 'securityIdentifier',
            'trustAuthIncoming', 'trustAuthOutgoing',
            'msDS-TrustForestTrustInfo'
        ]
        
        try:
            results = self.ldap_conn.search(
                search_filter=trust_filter,
                attributes=attributes,
                scope=ldap3.SUBTREE
            )
            
            for entry in results:
                trust_info = self._parse_trust_entry(entry)
                trusts.append(trust_info)
                
        except Exception as e:
            print(f"Error enumerating trusts: {str(e)}")
            
        return trusts
        
    def get_forest_trusts(self) -> List[Dict[str, Any]]:
        """
        Get forest trust information
        """
        forest_trusts = []
        
        # Search for forest trust info in configuration partition
        config_dn = self._get_configuration_dn()
        if not config_dn:
            return forest_trusts
            
        filter_str = "(objectClass=crossRef)"
        attributes = ['dnsRoot', 'nETBIOSName', 'nCName', 'trustParent']
        
        try:
            results = self.ldap_conn.search(
                base_dn=f"CN=Partitions,{config_dn}",
                search_filter=filter_str,
                attributes=attributes,
                scope=ldap3.SUBTREE
            )
            
            for entry in results:
                attrs = entry['attributes']
                forest_trusts.append({
                    'dn': entry['dn'],
                    'dnsRoot': attrs.get('dnsRoot', ''),
                    'netbiosName': attrs.get('nETBIOSName', ''),
                    'ncName': attrs.get('nCName', ''),
                    'trustParent': attrs.get('trustParent', '')
                })
                
        except Exception as e:
            print(f"Error getting forest trusts: {str(e)}")
            
        return forest_trusts
        
    def _parse_trust_entry(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse a trust entry and extract relevant information
        """
        attrs = entry['attributes']
        
        trust_info = {
            'dn': entry['dn'],
            'name': attrs.get('cn', attrs.get('name', '')),
            'trustPartner': attrs.get('trustPartner', ''),
            'flatName': attrs.get('flatName', ''),
            'whenCreated': self._convert_timestamp(attrs.get('whenCreated', '')),
            'whenChanged': self._convert_timestamp(attrs.get('whenChanged', '')),
        }
        
        # Parse trust direction
        direction = int(attrs.get('trustDirection', 0))
        trust_info['trustDirection'] = direction
        trust_info['trustDirectionText'] = self._get_trust_direction_text(direction)
        
        # Parse trust type
        trust_type = int(attrs.get('trustType', 0))
        trust_info['trustType'] = trust_type
        trust_info['trustTypeText'] = self._get_trust_type_text(trust_type)
        
        # Parse trust attributes
        attributes = int(attrs.get('trustAttributes', 0))
        trust_info['trustAttributes'] = attributes
        trust_info['trustAttributesList'] = self._get_trust_attributes_list(attributes)
        
        # Parse SID if available
        if 'securityIdentifier' in attrs:
            trust_info['sid'] = self._convert_sid(attrs['securityIdentifier'])
            
        return trust_info
        
    def _get_trust_direction_text(self, direction: int) -> str:
        """
        Convert trust direction to readable text
        """
        if direction == self.TRUST_DIRECTION_DISABLED:
            return "Disabled"
        elif direction == self.TRUST_DIRECTION_INBOUND:
            return "Inbound"
        elif direction == self.TRUST_DIRECTION_OUTBOUND:
            return "Outbound"
        elif direction == self.TRUST_DIRECTION_BIDIRECTIONAL:
            return "Bidirectional"
        else:
            return f"Unknown ({direction})"
            
    def _get_trust_type_text(self, trust_type: int) -> str:
        """
        Convert trust type to readable text
        """
        types = []
        if trust_type & self.TRUST_TYPE_MIT:
            types.append("MIT Kerberos")
        if trust_type & self.TRUST_TYPE_WINDOWS:
            types.append("Windows")
        if trust_type & self.TRUST_TYPE_DCE:
            types.append("DCE")
            
        return ", ".join(types) if types else f"Unknown ({trust_type})"
        
    def _get_trust_attributes_list(self, attributes: int) -> List[str]:
        """
        Parse trust attributes flags
        """
        attrs = []
        
        if attributes & self.TRUST_ATTRIBUTE_NON_TRANSITIVE:
            attrs.append("Non-Transitive")
        if attributes & self.TRUST_ATTRIBUTE_UPLEVEL_ONLY:
            attrs.append("Uplevel Only")
        if attributes & self.TRUST_ATTRIBUTE_QUARANTINED_DOMAIN:
            attrs.append("Quarantined")
        if attributes & self.TRUST_ATTRIBUTE_FOREST_TRANSITIVE:
            attrs.append("Forest Transitive")
        if attributes & self.TRUST_ATTRIBUTE_CROSS_ORGANIZATION:
            attrs.append("Cross Organization")
        if attributes & self.TRUST_ATTRIBUTE_WITHIN_FOREST:
            attrs.append("Within Forest")
        if attributes & self.TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL:
            attrs.append("Treat as External")
            
        return attrs
        
    def _get_configuration_dn(self) -> Optional[str]:
        """
        Get the configuration naming context
        """
        if not self.ldap_conn.server:
            return None
            
        try:
            if self.ldap_conn.server.info.other.get('configurationNamingContext'):
                return str(self.ldap_conn.server.info.other['configurationNamingContext'][0])
        except:
            pass
            
        # Try to construct it from base DN
        if self.ldap_conn.base_dn:
            parts = self.ldap_conn.base_dn.split(',')
            dc_parts = [p for p in parts if p.strip().upper().startswith('DC=')]
            if dc_parts:
                return f"CN=Configuration,{','.join(dc_parts)}"
                
        return None
        
    def _convert_sid(self, sid_value: Any) -> str:
        """
        Convert binary SID to string format
        """
        if isinstance(sid_value, str):
            return sid_value
            
        try:
            if isinstance(sid_value, bytes):
                revision = struct.unpack('B', sid_value[0:1])[0]
                sub_auth_count = struct.unpack('B', sid_value[1:2])[0]
                identifier_authority = struct.unpack('>Q', b'\x00\x00' + sid_value[2:8])[0]
                
                sub_authorities = []
                for i in range(sub_auth_count):
                    offset = 8 + (i * 4)
                    sub_auth = struct.unpack('<I', sid_value[offset:offset+4])[0]
                    sub_authorities.append(str(sub_auth))
                    
                return f"S-{revision}-{identifier_authority}-{'-'.join(sub_authorities)}"
        except:
            return str(sid_value)
            
    def _convert_timestamp(self, timestamp: Any) -> str:
        """
        Convert timestamp to readable format
        """
        if not timestamp:
            return ""
            
        try:
            if isinstance(timestamp, str):
                # Parse LDAP generalized time format
                if timestamp.endswith('Z'):
                    timestamp = timestamp[:-1]
                if '.' in timestamp:
                    timestamp = timestamp.split('.')[0]
                    
                for fmt in ['%Y%m%d%H%M%S', '%Y-%m-%d %H:%M:%S']:
                    try:
                        dt = datetime.strptime(timestamp, fmt)
                        return dt.strftime('%Y-%m-%d %H:%M:%S')
                    except:
                        continue
                        
            return str(timestamp)
        except:
            return str(timestamp)