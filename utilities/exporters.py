#!/usr/bin/env python3
"""
Exporters Module for pyLDAPGui

~ Description : Consolidated module containing all data export functionality.
                Handles exporting LDAP data to various formats including CSV,
                Bloodhound, and Neo4j.

@ Module Structure:
  - BloodhoundExporter : Export to Bloodhound 4.3 Legacy format
  - OpenGraphExporter  : Export to Bloodhound OpenGraph format
  - CSVExporter        : Export to CSV with full attribute data
  - Neo4jConnector     : Direct ingestion to Neo4j database

@ Dependencies:
  - json               : JSON file handling
  - csv                : CSV file operations
  - zipfile            : ZIP archive creation
  - neo4j              : Neo4j database connectivity (optional)
  
@ Author: ZephrFish
@ License: MIT
"""

import json
import csv
import zipfile
import hashlib
from typing import List, Dict, Any, Optional, Callable
from datetime import datetime
import os


"""
# Bloodhound Exporter
~ Description : Exports LDAP data to Bloodhound 4.3 Legacy format

@ Features:
  - Compatible with Bloodhound 4.3 Legacy (not CE)
  - Proper object type mapping
  - Security flags and attributes parsing
  - SID conversion from binary to string
  - Support for 50,000+ objects
"""


class BloodhoundExporter:
    """
    Export LDAP data to Bloodhound 4.3 Legacy format
    
    ~ Description : Handles the complex format requirements for Bloodhound
                    including proper object mapping and attribute conversion
    
    @ Attributes:
        timestamp : Unique timestamp for export files
    """
    
    def __init__(self):
        """
        Initialize exporter
        
        ~ Description : Sets up timestamp for unique file naming
        """
        # Timestamp for unique filenames - helps avoid overwriting
        self.timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        
    def export_to_bloodhound(self, entries: List[Dict[str, Any]], 
                           filename: str) -> str:
        """
        Export LDAP entries to Bloodhound format
        
        ~ Description : Main export function that processes entries and creates
                        ZIP file with separate JSON files per object type
        
        @ Args:
            entries  : List of LDAP entries with dn and attributes
            filename : Output filename (will add timestamp and .zip)
            
        @ Returns:
            str : Path to created ZIP file
            
        @ Raises:
            ValueError : If no entries provided
        """
        if not entries:
            raise ValueError("No entries to export")
            
        # Detect domain
        domain_name = self._find_domain_name(entries)
        
        # Process entries by type
        users = []
        computers = []
        groups = []
        domains = []
        ous = []
        
        for entry in entries:
            obj_type = self._classify_entry(entry)
            
            if obj_type == 'user':
                user_obj = self._create_user(entry, domain_name)
                if user_obj:
                    users.append(user_obj)
            elif obj_type == 'computer':
                comp_obj = self._create_computer(entry, domain_name)
                if comp_obj:
                    computers.append(comp_obj)
            elif obj_type == 'group':
                group_obj = self._create_group(entry, domain_name)
                if group_obj:
                    groups.append(group_obj)
            elif obj_type == 'domain':
                domain_obj = self._create_domain(entry, domain_name)
                if domain_obj:
                    domains.append(domain_obj)
            elif obj_type == 'ou':
                ou_obj = self._create_ou(entry, domain_name)
                if ou_obj:
                    ous.append(ou_obj)
        
        # Create ZIP file with separate JSON files
        zip_filename = self._create_zip_export(
            filename, users, computers, groups, domains, ous
        )
        
        return zip_filename
    
    def _find_domain_name(self, entries: List[Dict[str, Any]]) -> str:
        """
        Extract domain name from entries
        
        @ Args:
            entries : List of LDAP entries
            
        @ Returns:
            str : Domain name in uppercase
        """
        for entry in entries:
            domain = self._extract_domain_from_dn(entry.get('dn', ''))
            if domain and domain != 'UNKNOWN':
                return domain.upper()
        return 'UNKNOWN.LOCAL'
    
    def _classify_entry(self, entry: Dict[str, Any]) -> str:
        """
        Determine entry type from objectClass attributes
        
        @ Args:
            entry : LDAP entry dictionary
            
        @ Returns:
            str : Object type (user, computer, group, ou, domain, unknown)
        """
        attrs = entry.get('attributes', {})
        classes = attrs.get('objectClass', [])
        if isinstance(classes, str):
            classes = [classes]
        classes_lower = [c.lower() for c in classes]
        
        sam = attrs.get('sAMAccountName', '')
        
        # Computers have $ at end of sAMAccountName
        if 'computer' in classes_lower:
            return 'computer'
        elif ('user' in classes_lower or 'person' in classes_lower) and \
             sam and not sam.endswith('$'):
            return 'user'
        elif 'group' in classes_lower:
            return 'group'
        elif 'organizationalunit' in classes_lower:
            return 'ou'
        elif 'domain' in classes_lower or 'domaindns' in classes_lower:
            return 'domain'
        
        return 'unknown'
    
    def _create_user(self, entry: Dict[str, Any], domain: str) -> Dict[str, Any]:
        """
        Create Bloodhound user object
        
        ~ Description : Converts LDAP user entry to Bloodhound format with
                        all required fields and security attributes
        
        @ Args:
            entry  : LDAP entry
            domain : Domain name
            
        @ Returns:
            dict : Bloodhound user object or None if invalid
        """
        attrs = entry['attributes']
        sam = attrs.get('sAMAccountName', '')
        if not sam:
            return None
            
        sid = self._extract_sid(attrs)
        if not sid:
            return None
        
        # Complete user object structure with ALL required fields
        user_obj = {
            "AllowedToDelegate": [],
            "ObjectIdentifier": sid,
            "PrimaryGroupSID": None,  # Will be set below
            "Properties": {
                "domain": domain,
                "name": f"{sam.upper()}@{domain}",
                "distinguishedname": entry['dn'].upper(),
                "unconstraineddelegation": False,
                "trustedtoauth": False,
                "passwordnotreqd": False,
                "enabled": True,
                "lastlogon": -1,
                "lastlogontimestamp": -1,
                "pwdlastset": -1,
                "dontreqpreauth": False,
                "sensitive": False,
                "serviceprincipalnames": [],
                "hasspn": False,
                "displayname": attrs.get('displayName', sam) if attrs.get('displayName') else None,
                "email": attrs.get('mail') if attrs.get('mail') else None,
                "title": attrs.get('title') if attrs.get('title') else None,
                "homedirectory": attrs.get('homeDirectory') if attrs.get('homeDirectory') else None,
                "description": self._get_single_value(attrs.get('description')),
                "userpassword": None,
                "admincount": bool(attrs.get('adminCount', 0)),
                "whencreated": -1,
                "samaccountname": sam,
                "highvalue": False
            },
            "Aces": [],
            "SPNTargets": [],
            "HasSIDHistory": []
        }
        
        # Parse userAccountControl flags
        if 'userAccountControl' in attrs:
            try:
                uac = int(attrs['userAccountControl'])
                user_obj["Properties"]["enabled"] = not bool(uac & 0x2)
                user_obj["Properties"]["passwordnotreqd"] = bool(uac & 0x20)
                user_obj["Properties"]["dontreqpreauth"] = bool(uac & 0x400000)
                user_obj["Properties"]["unconstraineddelegation"] = bool(uac & 0x80000)
                user_obj["Properties"]["sensitive"] = bool(uac & 0x100000)
                user_obj["Properties"]["trustedtoauth"] = bool(uac & 0x1000000)
            except (ValueError, TypeError):
                pass
        
        # Service principal names
        spns = attrs.get('servicePrincipalName', [])
        if spns:
            if isinstance(spns, str):
                spns = [spns]
            user_obj["Properties"]["serviceprincipalnames"] = spns
            user_obj["Properties"]["hasspn"] = True
        
        # Primary group SID (typically Domain Users = 513)
        if 'primaryGroupID' in attrs:
            domain_sid = sid.rsplit('-', 1)[0] if '-' in sid else sid
            primary_group_id = int(attrs['primaryGroupID'])
            user_obj["PrimaryGroupSID"] = f"{domain_sid}-{primary_group_id}"
        else:
            # Default to Domain Users
            domain_sid = sid.rsplit('-', 1)[0] if '-' in sid else sid
            user_obj["PrimaryGroupSID"] = f"{domain_sid}-513"
        
        return user_obj
    
    def _create_computer(self, entry: Dict[str, Any], 
                        domain: str) -> Dict[str, Any]:
        """
        Create Bloodhound computer object
        
        @ Args:
            entry  : LDAP entry
            domain : Domain name
            
        @ Returns:
            dict : Bloodhound computer object or None if invalid
        """
        attrs = entry['attributes']
        sam = attrs.get('sAMAccountName', '').rstrip('$')
        if not sam:
            return None
            
        sid = self._extract_sid(attrs)
        if not sid:
            return None
        
        computer_obj = {
            "AllowedToDelegate": [],
            "ObjectIdentifier": sid,
            "PrimaryGroupSID": None,  # Will be set below
            "Properties": {
                "domain": domain,
                "name": f"{sam.upper()}.{domain}",
                "distinguishedname": entry['dn'].upper(),
                "unconstraineddelegation": False,
                "enabled": True,
                "trustedtoauth": False,
                "samaccountname": attrs.get('sAMAccountName', ''),
                "haslaps": False,
                "lastlogon": -1,
                "lastlogontimestamp": -1,
                "pwdlastset": -1,
                "serviceprincipalnames": [],
                "operatingsystem": attrs.get('operatingSystem') if attrs.get('operatingSystem') else None,
                "description": self._get_single_value(attrs.get('description')),
                "whencreated": -1,
                "highvalue": False
            },
            "AllowedToAct": [],
            "HasSIDHistory": [],
            "Sessions": [],
            "PrivilegedSessions": [],
            "RegistryValues": [],
            "LocalAdmins": [],
            "RemoteDesktopUsers": [],
            "DcomUsers": [],
            "PSRemoteUsers": [],
            "Status": None,
            "Aces": []
        }
        
        # Parse userAccountControl flags
        if 'userAccountControl' in attrs:
            try:
                uac = int(attrs['userAccountControl'])
                computer_obj["Properties"]["enabled"] = not bool(uac & 0x2)
                computer_obj["Properties"]["unconstraineddelegation"] = bool(uac & 0x80000)
                computer_obj["Properties"]["trustedtoauth"] = bool(uac & 0x1000000)
            except (ValueError, TypeError):
                pass
        
        # Service principal names
        spns = attrs.get('servicePrincipalName', [])
        if spns:
            if isinstance(spns, str):
                spns = [spns]
            computer_obj["Properties"]["serviceprincipalnames"] = spns
        
        # Primary group SID (typically Domain Computers = 515)
        if 'primaryGroupID' in attrs:
            domain_sid = sid.rsplit('-', 1)[0] if '-' in sid else sid
            primary_group_id = int(attrs['primaryGroupID'])
            computer_obj["PrimaryGroupSID"] = f"{domain_sid}-{primary_group_id}"
        else:
            # Default to Domain Computers
            domain_sid = sid.rsplit('-', 1)[0] if '-' in sid else sid
            computer_obj["PrimaryGroupSID"] = f"{domain_sid}-515"
        
        return computer_obj
    
    def _create_group(self, entry: Dict[str, Any], 
                     domain: str) -> Dict[str, Any]:
        """
        Create Bloodhound group object
        
        @ Args:
            entry  : LDAP entry
            domain : Domain name
            
        @ Returns:
            dict : Bloodhound group object or None if invalid
        """
        attrs = entry['attributes']
        sam = attrs.get('sAMAccountName', '')
        if not sam:
            return None
            
        sid = self._extract_sid(attrs)
        if not sid:
            return None
        
        group_obj = {
            "ObjectIdentifier": sid,
            "Properties": {
                "domain": domain,
                "name": f"{sam.upper()}@{domain}",
                "distinguishedname": entry['dn'].upper(),
                "samaccountname": sam,
                "admincount": bool(attrs.get('adminCount', 0)),
                "description": self._get_single_value(attrs.get('description')),
                "whencreated": -1
            },
            "Members": [],
            "Aces": []
        }
        
        # Process group members if present
        if 'member' in attrs:
            members = attrs['member']
            if isinstance(members, str):
                members = [members]
            
            for member_dn in members:
                # Create member object (we don't have SID here, so use DN)
                member_obj = {
                    "ObjectIdentifier": member_dn.upper(),
                    "ObjectType": "User"  # Could be User, Computer, or Group
                }
                group_obj["Members"].append(member_obj)
        
        # Mark high-value groups
        high_value_groups = [
            'domain admins', 'enterprise admins', 'schema admins',
            'administrators', 'account operators', 'backup operators',
            'server operators', 'print operators'
        ]
        if any(hvg in sam.lower() for hvg in high_value_groups):
            group_obj["Properties"]["highvalue"] = True
        else:
            group_obj["Properties"]["highvalue"] = False
        
        return group_obj
    
    def _create_domain(self, entry: Dict[str, Any], 
                      domain: str) -> Dict[str, Any]:
        """
        Create Bloodhound domain object
        
        @ Args:
            entry  : LDAP entry
            domain : Domain name
            
        @ Returns:
            dict : Bloodhound domain object or None if invalid
        """
        attrs = entry['attributes']
        sid = self._extract_sid(attrs)
        if not sid:
            return None
        
        domain_obj = {
            "ObjectIdentifier": sid,
            "Properties": {
                "domain": domain,
                "name": domain,
                "distinguishedname": entry['dn'].upper(),
                "description": self._get_single_value(attrs.get('description')),
                "functionallevel": "2016",
                "whencreated": -1
            },
            "Links": [],
            "Trusts": [],
            "ChildObjects": [],
            "Aces": []
        }
        
        return domain_obj
    
    def _create_ou(self, entry: Dict[str, Any], domain: str) -> Dict[str, Any]:
        """
        Create Bloodhound OU object
        
        @ Args:
            entry  : LDAP entry
            domain : Domain name
            
        @ Returns:
            dict : Bloodhound OU object
        """
        attrs = entry['attributes']
        dn = entry['dn']
        
        # Extract OU name
        ou_name = dn.split(',')[0].split('=')[1] if '=' in dn else "Unknown"
        
        # Generate GUID for OU
        guid = self._generate_guid_from_dn(dn)
        
        ou_obj = {
            "ObjectIdentifier": guid,
            "Properties": {
                "domain": domain,
                "name": f"{ou_name.upper()}@{domain}",
                "distinguishedname": dn.upper(),
                "description": self._get_single_value(attrs.get('description')),
                "whencreated": -1,
                "blocksinheritance": False
            },
            "Links": [],
            "ChildObjects": [],
            "Aces": []
        }
        
        return ou_obj
    
    def _create_zip_export(self, filename: str, users: List, computers: List, 
                          groups: List, domains: List, 
                          ous: List) -> str:
        """
        Create ZIP file with separate JSON files for each object type
        
        @ Args:
            filename  : Base filename
            users     : List of user objects
            computers : List of computer objects
            groups    : List of group objects
            domains   : List of domain objects
            ous       : List of OU objects
            
        @ Returns:
            str : Path to created ZIP file
        """
        base_name = os.path.splitext(filename)[0]
        zip_filename = f"{base_name}_{self.timestamp}_BloodHound.zip"
        
        with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as zf:
            # Write each object type to separate file
            object_types = [
                ('users', users),
                ('computers', computers),
                ('groups', groups),
                ('domains', domains),
                ('ous', ous)
            ]
            
            for obj_type, objects in object_types:
                if objects:
                    content = {
                        obj_type: objects,
                        "meta": {
                            "count": len(objects),
                            "type": obj_type,
                            "version": 4
                        }
                    }
                    json_filename = f"{self.timestamp}_{obj_type}.json"
                    zf.writestr(json_filename, 
                               json.dumps(content, separators=(',', ':')))
        
        return zip_filename
    
    def _extract_sid(self, attrs: Dict[str, Any]) -> Optional[str]:
        """
        Extract SID from objectSid attribute
        
        ~ Description : Converts binary SID to string format
        
        @ Args:
            attrs : Attribute dictionary
            
        @ Returns:
            str : SID string or None
        """
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
    
    def _extract_domain_from_dn(self, dn: str) -> str:
        """
        Extract domain name from distinguished name
        
        @ Args:
            dn : Distinguished name
            
        @ Returns:
            str : Domain name
        """
        parts = []
        for component in dn.split(','):
            component = component.strip()
            if component.upper().startswith('DC='):
                parts.append(component[3:])
        return '.'.join(parts) if parts else 'UNKNOWN'
    
    def _generate_guid_from_dn(self, dn: str) -> str:
        """
        Generate GUID-like identifier from DN
        
        @ Args:
            dn : Distinguished name
            
        @ Returns:
            str : GUID string
        """
        hash_obj = hashlib.md5(dn.encode()).hexdigest()
        return (f"{hash_obj[0:8]}-{hash_obj[8:12]}-{hash_obj[12:16]}-"
                f"{hash_obj[16:20]}-{hash_obj[20:32]}").upper()
    
    def _get_single_value(self, value: Any) -> Optional[str]:
        """
        Extract single value from LDAP attribute
        
        @ Args:
            value : Attribute value (may be list)
            
        @ Returns:
            str : Single value or None
        """
        if isinstance(value, list):
            return value[0] if value else None
        return value


"""
# CSV Exporter
~ Description : Exports LDAP data to CSV format

@ Features:
  - Full attribute export
  - Multi-valued attribute handling
  - UTF-8 encoding support
  - Customizable delimiter
"""


class CSVExporter:
    """
    Export LDAP data to CSV format
    
    ~ Description : Handles CSV export with proper encoding and multi-value
                    attribute handling
    """
    
    def __init__(self, delimiter: str = ',', multival_separator: str = '|'):
        """
        Initialize CSV exporter
        
        @ Args:
            delimiter          : Field delimiter (default: comma)
            multival_separator : Separator for multi-valued attributes
        """
        self.delimiter = delimiter
        self.multival_separator = multival_separator
        
    def export_to_csv(self, entries: List[Dict[str, Any]], 
                     filename: str) -> str:
        """
        Export LDAP entries to CSV
        
        ~ Description : Exports all entries with all attributes to CSV file
        
        @ Args:
            entries  : List of LDAP entries
            filename : Output filename
            
        @ Returns:
            str : Path to created CSV file
            
        @ Raises:
            ValueError : If no entries provided
        """
        if not entries:
            raise ValueError("No entries to export")
            
        # Collect all unique attributes
        all_attributes = set()
        for entry in entries:
            attrs = entry.get('attributes', {})
            all_attributes.update(attrs.keys())
            
        # Sort attributes for consistent output
        fieldnames = ['dn'] + sorted(list(all_attributes))
        
        # Write CSV
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames, 
                                   delimiter=self.delimiter)
            writer.writeheader()
            
            for entry in entries:
                row = {'dn': entry.get('dn', '')}
                attrs = entry.get('attributes', {})
                
                for attr_name in all_attributes:
                    if attr_name in attrs:
                        value = attrs[attr_name]
                        if isinstance(value, list):
                            # Join multi-valued attributes
                            row[attr_name] = self.multival_separator.join(
                                str(v) for v in value
                            )
                        else:
                            row[attr_name] = str(value)
                    else:
                        row[attr_name] = ''
                        
                writer.writerow(row)
                
        return filename


"""
# Neo4j Connector
~ Description : Direct ingestion to Neo4j database

@ Features:
  - Direct database connection
  - Node and relationship creation
  - Progress tracking
  - Batch processing
"""


class Neo4jConnector:
    """
    Neo4j database connector for LDAP data ingestion
    
    ~ Description : Manages connection to Neo4j and ingests LDAP data as
                    nodes and relationships
    
    @ Attributes:
        uri      : Neo4j connection URI
        username : Database username
        password : Database password
        driver   : Neo4j driver instance
    """
    
    def __init__(self, uri: str, username: str, password: str):
        """
        Initialize Neo4j connector
        
        @ Args:
            uri      : Neo4j connection URI (e.g., bolt://localhost:7687)
            username : Database username
            password : Database password
        """
        self.uri = uri
        self.username = username
        self.password = password
        self.driver = None
        self.neo4j = None
        
        # Try to import neo4j module
        try:
            from neo4j import GraphDatabase
            self.neo4j = GraphDatabase
        except ImportError:
            # Will handle this when connect() is called
            pass
        
    def connect(self):
        """
        Establish connection to Neo4j
        
        @ Raises:
            ImportError : If neo4j package not installed
            Exception : If connection fails
        """
        if self.neo4j is None:
            raise ImportError(
                "Neo4j driver not installed. Run: pip install neo4j"
            )
            
        self.driver = self.neo4j.driver(
            self.uri, 
            auth=(self.username, self.password)
        )
        
    def test_connection(self) -> bool:
        """
        Test database connection
        
        @ Returns:
            bool : True if connection successful
        """
        try:
            if self.neo4j is None:
                return False
                
            if not self.driver:
                self.connect()
                
            with self.driver.session() as session:
                result = session.run("RETURN 1")
                return result.single()[0] == 1
        except Exception:
            return False
            
    def close(self):
        """Close database connection"""
        if self.driver:
            self.driver.close()
            self.driver = None
            
    def ingest_ldap_data(self, ldap_data: Dict[str, List[Dict[str, Any]]], 
                        progress_callback: Optional[Callable] = None) -> Dict[str, int]:
        """
        Ingest LDAP data to Neo4j
        
        ~ Description : Creates nodes and relationships in Neo4j from LDAP data
        
        @ Args:
            ldap_data         : Dictionary of object types to lists of objects
            progress_callback : Optional callback for progress updates
            
        @ Returns:
            dict : Statistics about ingestion (nodes_created, relationships_created)
            
        @ Raises:
            ImportError : If neo4j package not installed
        """
        if self.neo4j is None:
            raise ImportError(
                "Neo4j driver not installed. Run: pip install neo4j"
            )
            
        if not self.driver:
            self.connect()
            
        stats = {
            'nodes_created': 0,
            'relationships_created': 0
        }
        
        # Calculate total objects
        total_objects = sum(len(objects) for objects in ldap_data.values())
        processed = 0
        
        with self.driver.session() as session:
            # Clear existing data (optional - comment out to append)
            # session.run("MATCH (n) DETACH DELETE n")
            
            # Process each object type
            for obj_type, objects in ldap_data.items():
                for obj in objects:
                    if obj_type == 'users':
                        stats['nodes_created'] += self._create_user_node(
                            session, obj
                        )
                    elif obj_type == 'computers':
                        stats['nodes_created'] += self._create_computer_node(
                            session, obj
                        )
                    elif obj_type == 'groups':
                        stats['nodes_created'] += self._create_group_node(
                            session, obj
                        )
                    elif obj_type == 'domains':
                        stats['nodes_created'] += self._create_domain_node(
                            session, obj
                        )
                    elif obj_type == 'ous':
                        stats['nodes_created'] += self._create_ou_node(
                            session, obj
                        )
                        
                    processed += 1
                    if progress_callback:
                        progress_callback(processed, total_objects)
                        
            # Create relationships
            stats['relationships_created'] = self._create_relationships(
                session, ldap_data
            )
            
        return stats
        
    def _create_user_node(self, session, user: Dict[str, Any]) -> int:
        """
        Create user node in Neo4j
        
        @ Args:
            session : Neo4j session
            user    : User object
            
        @ Returns:
            int : Number of nodes created (1 or 0)
        """
        query = """
        MERGE (u:User {objectid: $objectid})
        SET u.name = $name,
            u.domain = $domain,
            u.enabled = $enabled,
            u.pwdlastset = $pwdlastset,
            u.lastlogon = $lastlogon,
            u.hasspn = $hasspn,
            u.admincount = $admincount,
            u.description = $description
        """
        
        props = user.get('Properties', {})
        session.run(query, 
                   objectid=user.get('ObjectIdentifier'),
                   name=props.get('name'),
                   domain=props.get('domain'),
                   enabled=props.get('enabled'),
                   pwdlastset=props.get('pwdlastset'),
                   lastlogon=props.get('lastlogon'),
                   hasspn=props.get('hasspn'),
                   admincount=props.get('admincount'),
                   description=props.get('description'))
        return 1
        
    def _create_computer_node(self, session, computer: Dict[str, Any]) -> int:
        """
        Create computer node in Neo4j
        
        @ Args:
            session  : Neo4j session
            computer : Computer object
            
        @ Returns:
            int : Number of nodes created (1 or 0)
        """
        query = """
        MERGE (c:Computer {objectid: $objectid})
        SET c.name = $name,
            c.domain = $domain,
            c.enabled = $enabled,
            c.operatingsystem = $os,
            c.unconstraineddelegation = $unconstrained,
            c.description = $description
        """
        
        props = computer.get('Properties', {})
        session.run(query,
                   objectid=computer.get('ObjectIdentifier'),
                   name=props.get('name'),
                   domain=props.get('domain'),
                   enabled=props.get('enabled'),
                   os=props.get('operatingsystem'),
                   unconstrained=props.get('unconstraineddelegation'),
                   description=props.get('description'))
        return 1
        
    def _create_group_node(self, session, group: Dict[str, Any]) -> int:
        """
        Create group node in Neo4j
        
        @ Args:
            session : Neo4j session
            group   : Group object
            
        @ Returns:
            int : Number of nodes created (1 or 0)
        """
        query = """
        MERGE (g:Group {objectid: $objectid})
        SET g.name = $name,
            g.domain = $domain,
            g.highvalue = $highvalue,
            g.admincount = $admincount,
            g.description = $description
        """
        
        props = group.get('Properties', {})
        session.run(query,
                   objectid=group.get('ObjectIdentifier'),
                   name=props.get('name'),
                   domain=props.get('domain'),
                   highvalue=props.get('highvalue'),
                   admincount=props.get('admincount'),
                   description=props.get('description'))
        return 1
        
    def _create_domain_node(self, session, domain: Dict[str, Any]) -> int:
        """
        Create domain node in Neo4j
        
        @ Args:
            session : Neo4j session
            domain  : Domain object
            
        @ Returns:
            int : Number of nodes created (1 or 0)
        """
        query = """
        MERGE (d:Domain {objectid: $objectid})
        SET d.name = $name,
            d.functionallevel = $functionallevel,
            d.description = $description
        """
        
        props = domain.get('Properties', {})
        session.run(query,
                   objectid=domain.get('ObjectIdentifier'),
                   name=props.get('name'),
                   functionallevel=props.get('functionallevel'),
                   description=props.get('description'))
        return 1
        
    def _create_ou_node(self, session, ou: Dict[str, Any]) -> int:
        """
        Create OU node in Neo4j
        
        @ Args:
            session : Neo4j session
            ou      : OU object
            
        @ Returns:
            int : Number of nodes created (1 or 0)
        """
        query = """
        MERGE (o:OU {objectid: $objectid})
        SET o.name = $name,
            o.domain = $domain,
            o.blocksinheritance = $blocksinheritance,
            o.description = $description
        """
        
        props = ou.get('Properties', {})
        session.run(query,
                   objectid=ou.get('ObjectIdentifier'),
                   name=props.get('name'),
                   domain=props.get('domain'),
                   blocksinheritance=props.get('blocksinheritance'),
                   description=props.get('description'))
        return 1
        
    def _create_relationships(self, session, 
                            ldap_data: Dict[str, List[Dict[str, Any]]]) -> int:
        """
        Create relationships between nodes
        
        ~ Description : Creates MemberOf and other relationships based on
                        group memberships and other LDAP relationships
        
        @ Args:
            session   : Neo4j session
            ldap_data : Complete LDAP data
            
        @ Returns:
            int : Number of relationships created
        """
        rel_count = 0
        
        # Process group memberships
        groups = ldap_data.get('groups', [])
        for group in groups:
            group_id = group.get('ObjectIdentifier')
            members = group.get('Members', [])
            
            for member in members:
                member_id = member.get('ObjectIdentifier')
                
                # Create MemberOf relationship
                query = """
                MATCH (m {objectid: $member_id})
                MATCH (g:Group {objectid: $group_id})
                MERGE (m)-[:MemberOf]->(g)
                """
                
                result = session.run(query,
                                   member_id=member_id,
                                   group_id=group_id)
                rel_count += result.consume().counters.relationships_created
                
        # Process primary groups
        for obj_type in ['users', 'computers']:
            objects = ldap_data.get(obj_type, [])
            for obj in objects:
                obj_id = obj.get('ObjectIdentifier')
                primary_group = obj.get('PrimaryGroupSID')
                
                if primary_group:
                    query = """
                    MATCH (o {objectid: $obj_id})
                    MATCH (g:Group {objectid: $group_id})
                    MERGE (o)-[:MemberOf]->(g)
                    """
                    
                    result = session.run(query,
                                       obj_id=obj_id,
                                       group_id=primary_group)
                    rel_count += result.consume().counters.relationships_created
                    
        return rel_count