import random
import re
from typing import Dict, List, Tuple, Optional

# This util works 50% of the time every time, it's very much something I wanted to play about with so it may be stealthy but it might also be a chaotic blast
class LDAPObfuscator:
    """
    Obfuscate LDAP queries to try to at least be a bit different
    """
    
    def __init__(self):
        # Common LDAP attributes and their variations
        self.attribute_variations = {
            'samaccountname': ['sAMAccountName', 'samAccountName', 'SAMACCOUNTNAME', 'sAmAcCoUnTnAmE'],
            'objectclass': ['objectClass', 'OBJECTCLASS', 'ObjectClass', 'oBjEcTcLaSs'],
            'memberof': ['memberOf', 'MEMBEROF', 'MemberOf', 'mEmBeRoF'],
            'serviceprincipalname': ['servicePrincipalName', 'SERVICEPRINCIPALNAME', 'ServicePrincipalName'],
            'useraccountcontrol': ['userAccountControl', 'USERACCOUNTCONTROL', 'UserAccountControl'],
            'objectcategory': ['objectCategory', 'OBJECTCATEGORY', 'ObjectCategory'],
            'cn': ['CN', 'cn', 'Cn', 'cN'],
            'ou': ['OU', 'ou', 'Ou', 'oU'],
            'dc': ['DC', 'dc', 'Dc', 'dC'],
            'distinguishedname': ['distinguishedName', 'DISTINGUISHEDNAME', 'DistinguishedName'],
            'name': ['name', 'NAME', 'Name', 'nAmE'],
            'description': ['description', 'DESCRIPTION', 'Description', 'dEsCrIpTiOn'],
            'mail': ['mail', 'MAIL', 'Mail', 'mAiL'],
            'givenname': ['givenName', 'GIVENNAME', 'GivenName', 'gIvEnNaMe'],
            'sn': ['sn', 'SN', 'Sn', 'sN'],
            'displayname': ['displayName', 'DISPLAYNAME', 'DisplayName', 'dIsPlAyNaMe'],
            'pwdlastset': ['pwdLastSet', 'PWDLASTSET', 'PwdLastSet', 'pWdLaStSeT'],
            'lastlogon': ['lastLogon', 'LASTLOGON', 'LastLogon', 'lAsTlOgOn'],
            'admincount': ['adminCount', 'ADMINCOUNT', 'AdminCount', 'aDmInCoUnT'],
            'primarygroupid': ['primaryGroupID', 'PRIMARYGROUPID', 'PrimaryGroupID'],
        }
        
        # Common object classes and their variations
        self.objectclass_variations = {
            'user': ['user', 'USER', 'User', 'uSeR'],
            'computer': ['computer', 'COMPUTER', 'Computer', 'cOmPuTeR'],
            'group': ['group', 'GROUP', 'Group', 'gRoUp'],
            'person': ['person', 'PERSON', 'Person', 'pErSoN'],
            'organizationalunit': ['organizationalUnit', 'ORGANIZATIONALUNIT', 'OrganizationalUnit'],
            'container': ['container', 'CONTAINER', 'Container', 'cOnTaInEr'],
            'domain': ['domain', 'DOMAIN', 'Domain', 'dOmAiN'],
        }
        
    def obfuscate_filter(self, ldap_filter: str, techniques: List[str] = None) -> str:
        """
        Obfuscate an LDAP filter using various techniques
        """
        if not techniques:
            techniques = ['case_variation', 'whitespace', 'wildcards', 'oid_substitution']
            
        obfuscated = ldap_filter
        
        if 'case_variation' in techniques:
            obfuscated = self._apply_case_variation(obfuscated)
            
        if 'whitespace' in techniques:
            obfuscated = self._add_whitespace(obfuscated)
            
        if 'wildcards' in techniques:
            obfuscated = self._add_wildcards(obfuscated)
            
        if 'oid_substitution' in techniques:
            obfuscated = self._substitute_oids(obfuscated)
            
        if 'encoding' in techniques:
            obfuscated = self._apply_encoding(obfuscated)
            
        return obfuscated
        
    def _apply_case_variation(self, filter_str: str) -> str:
        """
        Randomly vary the case of attributes
        """
        result = filter_str
        
        # Replace known attributes with random case variations
        for attr, variations in self.attribute_variations.items():
            pattern = re.compile(re.escape(attr), re.IGNORECASE)
            matches = pattern.finditer(result)
            
            for match in reversed(list(matches)):
                variation = random.choice(variations)
                result = result[:match.start()] + variation + result[match.end():]
                
        return result
        
    def _add_whitespace(self, filter_str: str) -> str:
        """
        Add random whitespace in valid positions
        """
        # Add spaces around operators
        result = filter_str
        
        # Add random spaces around = (but not in :=)
        result = re.sub(r'(?<!:)=', lambda m: f" {m.group()} " if random.random() > 0.5 else m.group(), result)
        
        # Add spaces around parentheses randomly
        result = re.sub(r'\(', lambda m: f"( " if random.random() > 0.7 else m.group(), result)
        result = re.sub(r'\)', lambda m: f" )" if random.random() > 0.7 else m.group(), result)
        
        # Clean up multiple spaces
        result = re.sub(r'\s+', ' ', result)
        
        return result
        
    def _add_wildcards(self, filter_str: str) -> str:
        """
        Add wildcards to attribute values where possible
        """
        # Pattern to find attribute=value pairs (not for special operators like :=)
        pattern = r'(\w+)=([^)&|!]+?)(?=\)|&|\|)'
        
        def add_wildcard(match):
            attr = match.group(1)
            value = match.group(2)
            
            # Don't add wildcards to certain attributes or numeric values
            if attr.lower() in ['objectguid', 'objectsid'] or value.isdigit():
                return match.group(0)
                
            # Don't modify if already has wildcards
            if '*' in value:
                return match.group(0)
                
            # Randomly add wildcards
            if random.random() > 0.6:
                # Add wildcard at random position
                if len(value) > 2 and random.random() > 0.5:
                    pos = random.randint(1, len(value) - 1)
                    value = value[:pos] + '*' + value[pos:]
                else:
                    # Add at beginning or end
                    if random.random() > 0.5:
                        value = '*' + value
                    else:
                        value = value + '*'
                        
            return f"{attr}={value}"
            
        return re.sub(pattern, add_wildcard, filter_str)
        
    def _substitute_oids(self, filter_str: str) -> str:
        """
        Substitute common attributes with their OIDs
        """
        oid_mappings = {
            'cn': '2.5.4.3',
            'sn': '2.5.4.4',
            'c': '2.5.4.6',
            'l': '2.5.4.7',
            'st': '2.5.4.8',
            'o': '2.5.4.10',
            'ou': '2.5.4.11',
            'title': '2.5.4.12',
            'description': '2.5.4.13',
            'mail': '0.9.2342.19200300.100.1.3',
            'givenName': '2.5.4.42',
            'distinguishedName': '2.5.4.49',
            'memberOf': '1.2.840.113556.1.4.1941',  # LDAP_MATCHING_RULE_IN_CHAIN
            'userAccountControl': '1.2.840.113556.1.4.8',
            'sAMAccountName': '1.2.840.113556.1.4.221',
            'objectClass': '2.5.4.0',
            'objectCategory': '1.2.840.113556.1.4.782',
        }
        
        result = filter_str
        
        # Randomly substitute some attributes with OIDs
        for attr, oid in oid_mappings.items():
            if random.random() > 0.7 and attr.lower() in result.lower():
                pattern = re.compile(re.escape(attr), re.IGNORECASE)
                result = pattern.sub(oid, result)
                
        return result
        
    def _apply_encoding(self, filter_str: str) -> str:
        """
        Apply hex encoding to certain values
        """
        # Pattern to find string values
        pattern = r'=([^)&|!*]+?)(?=\)|&|\|)'
        
        def encode_value(match):
            value = match.group(1)
            
            # Skip if numeric or already encoded
            if value.isdigit() or value.startswith('\\'):
                return match.group(0)
                
            # Randomly encode some characters
            if random.random() > 0.7:
                encoded = ''
                for char in value:
                    if random.random() > 0.5 and char.isalpha():
                        # Hex encode the character
                        encoded += f"\\{ord(char):02x}"
                    else:
                        encoded += char
                return f"={encoded}"
                
            return match.group(0)
            
        return re.sub(pattern, encode_value, filter_str)
        
    def generate_equivalent_filter(self, filter_str: str) -> List[str]:
        """
        Generate multiple equivalent versions of a filter
        """
        equivalents = []
        
        # Original
        equivalents.append(filter_str)
        
        # Different obfuscation techniques
        techniques_combinations = [
            ['case_variation'],
            ['whitespace'],
            ['wildcards'],
            ['oid_substitution'],
            ['case_variation', 'whitespace'],
            ['case_variation', 'wildcards'],
            ['case_variation', 'whitespace', 'wildcards'],
            ['oid_substitution', 'case_variation'],
            ['encoding'],
        ]
        
        for techniques in techniques_combinations:
            obfuscated = self.obfuscate_filter(filter_str, techniques)
            if obfuscated not in equivalents:
                equivalents.append(obfuscated)
                
        return equivalents
        
    def obfuscate_dn(self, dn: str) -> str:
        """
        Obfuscate a distinguished name
        """
        # Vary case of RDN types
        parts = dn.split(',')
        obfuscated_parts = []
        
        for part in parts:
            if '=' in part:
                rdn_type, rdn_value = part.split('=', 1)
                rdn_type = rdn_type.strip()
                
                # Vary case of RDN type
                if rdn_type.upper() in ['CN', 'OU', 'DC', 'O', 'C', 'L', 'ST']:
                    if random.random() > 0.5:
                        rdn_type = rdn_type.upper() if random.random() > 0.5 else rdn_type.lower()
                    else:
                        # Mix case
                        rdn_type = ''.join(random.choice([c.upper(), c.lower()]) for c in rdn_type)
                        
                obfuscated_parts.append(f"{rdn_type}={rdn_value}")
            else:
                obfuscated_parts.append(part)
                
        # Randomly add spaces
        if random.random() > 0.5:
            return ', '.join(obfuscated_parts)
        else:
            return ','.join(obfuscated_parts)