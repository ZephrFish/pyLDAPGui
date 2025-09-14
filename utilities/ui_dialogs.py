#!/usr/bin/env python3
"""
UI Dialogs Module for pyLDAPGui

~ Description : Consolidated module containing all dialog windows for the application.
                This includes search, trust browser, obfuscation, Neo4j connection,
                and debug dialogs.

@ Module Structure:
  - SearchDialog        : Advanced LDAP search functionality
  - TrustBrowserDialog  : Domain trust analysis and browsing
  - ObfuscationDialog   : LDAP query obfuscation tools
  - Neo4jConnectionDialog : Neo4j database connection and ingestion
  - DebugDialog         : Query debug console

@ Dependencies:
  - PyQt6              : GUI framework
  - ldap3              : LDAP operations
  - neo4j              : Neo4j database connectivity
  
@ Author: ZephrFish
@ License: MIT
"""

import sys
import json
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QLineEdit, QComboBox, QTextEdit, QTableWidget, QTableWidgetItem,
    QGroupBox, QCheckBox, QSpinBox, QHeaderView, QSplitter,
    QListWidget, QListWidgetItem, QFormLayout, QGridLayout,
    QProgressDialog, QMessageBox, QFileDialog, QDialogButtonBox,
    QTabWidget, QWidget, QProgressBar
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont

# Local imports
from .ldap_obfuscator import LDAPObfuscator
from .trust_analyser import TrustAnalyser


"""
# Search Dialog
~ Description : Advanced LDAP search dialog with pre-built filters and custom search capabilities

@ Functionality:
  - Pre-built common searches (users, computers, groups, etc.)
  - Custom LDAP filter input
  - Attribute selection for targeted searches
  - Search scope control (Base, One Level, Subtree)
  - Export results directly to CSV or Bloodhound
"""


class SearchDialog(QDialog):
    """
    Advanced LDAP search dialog
    
    ~ Description : Provides interface for complex LDAP searches with pre-built
                    filters and export capabilities
    
    @ Attributes:
        search_requested : pyqtSignal emitting search parameters
        ldap_connection  : Active LDAP connection instance
    """
    
    search_requested = pyqtSignal(dict)
    
    def __init__(self, parent=None, ldap_connection=None):
        """
        Initialize search dialog
        
        @ Args:
            parent         : Parent widget
            ldap_connection: Active LDAP connection
        """
        super().__init__(parent)
        self.ldap_conn = ldap_connection
        self.setWindowTitle("Advanced LDAP Search")
        self.setModal(True)
        self.resize(800, 600)
        
        self._init_ui()
        self._load_presets()
        
    def _init_ui(self):
        """
        Initialize user interface
        
        ~ Description : Creates the search dialog layout with filter input,
                        scope selection, and results display
        """
        layout = QVBoxLayout()
        
        # Filter section
        filter_group = QGroupBox("Search Filter")
        filter_layout = QVBoxLayout()
        
        # Pre-built filters
        preset_layout = QHBoxLayout()
        preset_layout.addWidget(QLabel("Common Searches:"))
        
        self.preset_combo = QComboBox()
        self.preset_combo.currentTextChanged.connect(self._on_preset_selected)
        preset_layout.addWidget(self.preset_combo, 1)
        
        filter_layout.addLayout(preset_layout)
        
        # Custom filter
        self.filter_input = QTextEdit()
        self.filter_input.setPlaceholderText(
            "Enter LDAP filter, e.g., (&(objectClass=user)(sAMAccountName=admin*))"
        )
        self.filter_input.setMaximumHeight(100)
        filter_layout.addWidget(self.filter_input)
        
        filter_group.setLayout(filter_layout)
        layout.addWidget(filter_group)
        
        # Search options
        options_group = QGroupBox("Search Options")
        options_layout = QFormLayout()
        
        # Base DN
        self.base_dn_input = QLineEdit()
        if self.ldap_conn and self.ldap_conn.base_dn:
            self.base_dn_input.setText(self.ldap_conn.base_dn)
        options_layout.addRow("Base DN:", self.base_dn_input)
        
        # Scope
        self.scope_combo = QComboBox()
        self.scope_combo.addItems(["Subtree", "One Level", "Base"])
        options_layout.addRow("Scope:", self.scope_combo)
        
        # Size limit
        self.size_limit_spin = QSpinBox()
        self.size_limit_spin.setRange(1, 50000)
        self.size_limit_spin.setValue(1000)
        self.size_limit_spin.setSuffix(" entries")
        options_layout.addRow("Size Limit:", self.size_limit_spin)
        
        # Attributes
        self.attributes_input = QLineEdit()
        self.attributes_input.setPlaceholderText("Leave empty for all attributes")
        options_layout.addRow("Attributes:", self.attributes_input)
        
        options_group.setLayout(options_layout)
        layout.addWidget(options_group)
        
        # Results preview
        self.results_table = QTableWidget()
        self.results_table.setAlternatingRowColors(True)
        layout.addWidget(self.results_table)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        self.search_btn = QPushButton("Search")
        self.search_btn.clicked.connect(self._perform_search)
        self.search_btn.setDefault(True)
        button_layout.addWidget(self.search_btn)
        
        self.export_csv_btn = QPushButton("Export to CSV")
        self.export_csv_btn.clicked.connect(self._export_csv)
        self.export_csv_btn.setEnabled(False)
        button_layout.addWidget(self.export_csv_btn)
        
        self.export_bh_btn = QPushButton("Export to Bloodhound")
        self.export_bh_btn.clicked.connect(self._export_bloodhound)
        self.export_bh_btn.setEnabled(False)
        button_layout.addWidget(self.export_bh_btn)
        
        button_layout.addStretch()
        
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.reject)
        button_layout.addWidget(close_btn)
        
        layout.addLayout(button_layout)
        self.setLayout(layout)
        
    def _load_presets(self):
        """
        Load pre-built search filters
        
        ~ Description : Populates the preset combo box with common LDAP searches
        """
        presets = {
            "-- Select Preset --": "",
            "All Users": "(&(objectCategory=person)(objectClass=user))",
            "All Computers": "(objectClass=computer)",
            "All Groups": "(objectClass=group)",
            "Domain Admins": "(&(objectClass=group)(cn=Domain Admins))",
            "Active Users": "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
            "Disabled Users": "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))",
            "Users with SPNs": "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))",
            "Kerberoastable Users": "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
            "ASREPRoastable Users": "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
            "Unconstrained Delegation": "(userAccountControl:1.2.840.113556.1.4.803:=524288)",
            "Constrained Delegation": "(msDS-AllowedToDelegateTo=*)",
            "LAPS Enabled Computers": "(ms-Mcs-AdmPwd=*)",
            "Domain Controllers": "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
            "Exchange Servers": "(&(objectClass=computer)(servicePrincipalName=*Exchange*))",
            "SQL Servers": "(&(objectClass=computer)(servicePrincipalName=*sql*))",
            "Certificate Templates": "(objectClass=pKICertificateTemplate)",
            "GPOs": "(objectClass=groupPolicyContainer)",
            "Privileged Groups": "(adminCount=1)",
            "Users Never Expire": "(&(objectCategory=person)(objectClass=user)(|(accountExpires=0)(accountExpires=9223372036854775807)))",
            "Empty Groups": "(&(objectClass=group)(!(member=*)))",
            "Organizational Units": "(objectClass=organizationalUnit)",
            "Trust Objects": "(objectClass=trustedDomain)",
            "Service Accounts": "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))",
            "Machine Accounts": "(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
            "User Must Change Password": "(&(objectCategory=person)(objectClass=user)(pwdLastSet=0))",
            "Password Never Expires": "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))",
            "Recently Created Objects": "(whenCreated>=20240101000000.0Z)",
            "High Privilege Users": "(&(objectCategory=person)(objectClass=user)(adminCount=1))"
        }
        
        for name, filter_str in presets.items():
            self.preset_combo.addItem(name, filter_str)
            
    def _on_preset_selected(self, text):
        """
        Handle preset selection
        
        @ Args:
            text : Selected preset name
        """
        filter_str = self.preset_combo.currentData()
        if filter_str:
            self.filter_input.setPlainText(filter_str)
            
    def _perform_search(self):
        """
        Execute LDAP search
        
        ~ Description : Validates inputs and emits search_requested signal
                        with search parameters
        """
        search_filter = self.filter_input.toPlainText().strip()
        if not search_filter:
            QMessageBox.warning(self, "Invalid Filter", "Please enter a search filter")
            return
            
        # Build search parameters
        params = {
            'base_dn': self.base_dn_input.text().strip(),
            'search_filter': search_filter,
            'scope': self.scope_combo.currentText(),
            'size_limit': self.size_limit_spin.value(),
            'attributes': []
        }
        
        # Parse attributes
        attrs_text = self.attributes_input.text().strip()
        if attrs_text:
            params['attributes'] = [a.strip() for a in attrs_text.split(',')]
            
        # Emit search request
        self.search_requested.emit(params)
        
        # Close dialog
        self.accept()
        
    def _export_csv(self):
        """Export search results to CSV"""
        # Implementation would export current results
        pass
        
    def _export_bloodhound(self):
        """Export search results to Bloodhound format"""
        # Implementation would export current results
        pass


"""
# Trust Browser Dialog
~ Description : Domain trust analysis and visualization dialog

@ Functionality:
  - Enumerate domain trusts
  - Display trust relationships with direction and type
  - Security risk assessment
  - Export trust data for Bloodhound
"""


class TrustBrowserDialog(QDialog):
    """
    Domain trust browser dialog
    
    ~ Description : Analyzes and displays Active Directory trust relationships
                    with security risk assessment
    
    @ Attributes:
        ldap_connection : Active LDAP connection instance
        trust_analyser  : Trust analysis engine
    """
    
    def __init__(self, parent=None, ldap_connection=None):
        """
        Initialize trust browser
        
        @ Args:
            parent         : Parent widget
            ldap_connection: Active LDAP connection
        """
        super().__init__(parent)
        self.ldap_conn = ldap_connection
        self.trust_analyser = TrustAnalyser(ldap_connection)
        self.trusts = []
        
        self.setWindowTitle("Domain Trust Browser")
        self.setModal(True)
        self.resize(900, 600)
        
        self._init_ui()
        
    def _init_ui(self):
        """
        Initialize user interface
        
        ~ Description : Creates the trust browser layout with trust list,
                        details panel, and export options
        """
        layout = QVBoxLayout()
        
        # Header
        header_layout = QHBoxLayout()
        header_label = QLabel("Domain Trust Relationships")
        header_label.setStyleSheet("font-size: 14px; font-weight: bold;")
        header_layout.addWidget(header_label)
        
        header_layout.addStretch()
        
        # Refresh button
        refresh_btn = QPushButton("Refresh Trusts")
        refresh_btn.clicked.connect(self._load_trusts)
        header_layout.addWidget(refresh_btn)
        
        layout.addLayout(header_layout)
        
        # Splitter for trust list and details
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Trust list
        self.trust_list = QListWidget()
        self.trust_list.itemSelectionChanged.connect(self._on_trust_selected)
        splitter.addWidget(self.trust_list)
        
        # Details panel
        details_widget = QWidget()
        details_layout = QVBoxLayout()
        
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        details_layout.addWidget(self.details_text)
        
        details_widget.setLayout(details_layout)
        splitter.addWidget(details_widget)
        
        # Set splitter sizes (40% list, 60% details)
        splitter.setSizes([360, 540])
        
        layout.addWidget(splitter)
        
        # Export buttons
        export_layout = QHBoxLayout()
        
        export_csv_btn = QPushButton("Export to CSV")
        export_csv_btn.clicked.connect(self._export_csv)
        export_layout.addWidget(export_csv_btn)
        
        export_bh_btn = QPushButton("Export to Bloodhound")
        export_bh_btn.clicked.connect(self._export_bloodhound)
        export_layout.addWidget(export_bh_btn)
        
        export_layout.addStretch()
        
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        export_layout.addWidget(close_btn)
        
        layout.addLayout(export_layout)
        self.setLayout(layout)
        
        # Load trusts on init
        QTimer.singleShot(100, self._load_trusts)
        
    def _load_trusts(self):
        """
        Load domain trusts from LDAP
        
        ~ Description : Queries LDAP for trust objects and analyzes them
        """
        if not self.ldap_conn:
            QMessageBox.warning(self, "No Connection", "No LDAP connection available")
            return
            
        # Clear current list
        self.trust_list.clear()
        self.trusts = []
        
        # Show progress
        progress = QProgressDialog("Loading domain trusts...", "Cancel", 0, 0, self)
        progress.setWindowTitle("Loading")
        progress.setWindowModality(Qt.WindowModality.WindowModal)
        progress.show()
        
        try:
            # Get trusts
            self.trusts = self.trust_analyser.get_domain_trusts()
            
            # Populate list
            for trust in self.trusts:
                item = QListWidgetItem(trust.get('name', 'Unknown Trust'))
                
                # Color code by trust type
                trust_type = trust.get('trust_type', 'Unknown')
                if trust_type == 'FOREST':
                    item.setForeground(Qt.GlobalColor.darkGreen)
                elif trust_type == 'EXTERNAL':
                    item.setForeground(Qt.GlobalColor.darkBlue)
                elif 'DANGEROUS' in str(trust.get('security_risks', [])):
                    item.setForeground(Qt.GlobalColor.red)
                    
                self.trust_list.addItem(item)
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load trusts: {str(e)}")
        finally:
            progress.close()
            
        if not self.trusts:
            self.details_text.setText("No domain trusts found.")
            
    def _on_trust_selected(self):
        """
        Handle trust selection
        
        ~ Description : Displays detailed information about selected trust
        """
        current_item = self.trust_list.currentItem()
        if not current_item:
            return
            
        index = self.trust_list.row(current_item)
        if index < len(self.trusts):
            trust = self.trusts[index]
            self._display_trust_details(trust)
            
    def _display_trust_details(self, trust):
        """
        Display trust details
        
        @ Args:
            trust : Trust object dictionary
        """
        details = []
        details.append(f"Trust Name: {trust.get('name', 'Unknown')}")
        details.append(f"DN: {trust.get('dn', 'Unknown')}")
        details.append("")
        
        # Trust properties
        details.append("Trust Properties:")
        details.append(f"  Type: {trust.get('trust_type', 'Unknown')}")
        details.append(f"  Direction: {trust.get('trust_direction', 'Unknown')}")
        details.append(f"  Transitive: {trust.get('is_transitive', False)}")
        details.append(f"  SID Filtering: {trust.get('sid_filtering', 'Unknown')}")
        details.append("")
        
        # Security risks
        risks = trust.get('security_risks', [])
        if risks:
            details.append("Security Risks:")
            for risk in risks:
                details.append(f"  WARNING: {risk}")
            details.append("")
            
        # Attributes
        details.append("Attributes:")
        attrs = trust.get('attributes', {})
        for key, value in attrs.items():
            if key not in ['dn', 'objectClass']:
                details.append(f"  {key}: {value}")
                
        self.details_text.setText('\n'.join(details))
        
    def _export_csv(self):
        """Export trusts to CSV"""
        if not self.trusts:
            QMessageBox.warning(self, "No Data", "No trust data to export")
            return
            
        filename, _ = QFileDialog.getSaveFileName(
            self, "Export Trusts", "domain_trusts.csv", "CSV Files (*.csv)"
        )
        
        if filename:
            try:
                import csv
                with open(filename, 'w', newline='', encoding='utf-8') as f:
                    fieldnames = ['name', 'dn', 'trust_type', 'trust_direction', 
                                  'is_transitive', 'sid_filtering', 'security_risks']
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    
                    for trust in self.trusts:
                        row = {k: trust.get(k, '') for k in fieldnames}
                        row['security_risks'] = ', '.join(trust.get('security_risks', []))
                        writer.writerow(row)
                        
                QMessageBox.information(self, "Export Complete", 
                                        f"Trusts exported to {filename}")
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to export: {str(e)}")
                
    def _export_bloodhound(self):
        """Export trusts to Bloodhound format"""
        # Implementation would export trust data in Bloodhound format
        QMessageBox.information(self, "Export", 
                                "Trust export to Bloodhound format - Coming soon!")


"""
# Obfuscation Dialog
~ Description : LDAP query obfuscation tools for security testing

@ Functionality:
  - Multiple obfuscation techniques
  - Case variation, whitespace injection
  - Wildcard addition, OID substitution
  - Hex encoding for evasion
"""


class ObfuscationDialog(QDialog):
    """
    LDAP query obfuscation dialog
    
    ~ Description : Provides tools to obfuscate LDAP queries for security
                    testing and evasion techniques
    
    @ Attributes:
        obfuscator : LDAP obfuscation engine
    """
    
    def __init__(self, parent=None):
        """
        Initialize obfuscation dialog
        
        @ Args:
            parent : Parent widget
        """
        super().__init__(parent)
        self.obfuscator = LDAPObfuscator()
        
        self.setWindowTitle("LDAP Query Obfuscation")
        self.setModal(True)
        self.resize(800, 600)
        
        self._init_ui()
        self._load_examples()
        
    def _init_ui(self):
        """
        Initialize user interface
        
        ~ Description : Creates the obfuscation dialog layout with input,
                        technique selection, and output display
        """
        layout = QVBoxLayout()
        
        # Input section
        input_group = QGroupBox("Input Query")
        input_layout = QVBoxLayout()
        
        self.input_text = QTextEdit()
        self.input_text.setPlaceholderText(
            "Enter LDAP query to obfuscate, e.g., (sAMAccountName=admin)"
        )
        self.input_text.setMaximumHeight(100)
        input_layout.addWidget(self.input_text)
        
        # Example queries
        example_layout = QHBoxLayout()
        example_layout.addWidget(QLabel("Examples:"))
        
        self.example_combo = QComboBox()
        self.example_combo.currentTextChanged.connect(self._on_example_selected)
        example_layout.addWidget(self.example_combo, 1)
        
        input_layout.addLayout(example_layout)
        input_group.setLayout(input_layout)
        layout.addWidget(input_group)
        
        # Obfuscation techniques
        tech_group = QGroupBox("Obfuscation Techniques")
        tech_layout = QVBoxLayout()
        
        self.tech_checkboxes = {}
        techniques = [
            ("case_variation", "Case Variation - Mix upper and lower case"),
            ("whitespace", "Whitespace Injection - Add spaces in queries"),
            ("wildcards", "Wildcard Addition - Add wildcards to values"),
            ("oid_substitution", "OID Substitution - Replace attributes with OIDs"),
            ("hex_encoding", "Hex Encoding - Encode values in hexadecimal"),
            ("dn_manipulation", "DN Manipulation - Obfuscate distinguished names"),
            ("unicode_bypass", "Unicode Bypass - Use unicode equivalents"),
            ("comment_injection", "Comment Injection - Add LDAP comments")
        ]
        
        for key, label in techniques:
            checkbox = QCheckBox(label)
            checkbox.setChecked(True)
            self.tech_checkboxes[key] = checkbox
            tech_layout.addWidget(checkbox)
            
        tech_group.setLayout(tech_layout)
        layout.addWidget(tech_group)
        
        # Output section
        output_group = QGroupBox("Obfuscated Query")
        output_layout = QVBoxLayout()
        
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        
        # Use monospace font for output
        font = QFont()
        font.setFamily("Consolas" if sys.platform == "win32" else 
                      "Monaco" if sys.platform == "darwin" else "monospace")
        font.setPointSize(10)
        font.setStyleHint(QFont.StyleHint.Monospace)
        self.output_text.setFont(font)
        
        output_layout.addWidget(self.output_text)
        output_group.setLayout(output_layout)
        layout.addWidget(output_group)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        obfuscate_btn = QPushButton("Obfuscate")
        obfuscate_btn.clicked.connect(self._obfuscate_query)
        obfuscate_btn.setDefault(True)
        button_layout.addWidget(obfuscate_btn)
        
        copy_btn = QPushButton("Copy to Clipboard")
        copy_btn.clicked.connect(self._copy_output)
        button_layout.addWidget(copy_btn)
        
        button_layout.addStretch()
        
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        button_layout.addWidget(close_btn)
        
        layout.addLayout(button_layout)
        self.setLayout(layout)
        
    def _load_examples(self):
        """
        Load example queries
        
        ~ Description : Populates the example combo box with common queries
        """
        examples = {
            "-- Select Example --": "",
            "Find Admin User": "(sAMAccountName=admin)",
            "All Domain Admins": "(&(objectClass=user)(memberOf=CN=Domain Admins,CN=Users,DC=example,DC=com))",
            "Service Accounts": "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))",
            "Computers by OS": "(&(objectClass=computer)(operatingSystem=*Server*))",
            "Users with Email": "(&(objectClass=user)(mail=*))",
            "Privileged Groups": "(adminCount=1)",
            "Password Never Expires": "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))",
            "Kerberoastable": "(&(objectClass=user)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        }
        
        for name, query in examples.items():
            self.example_combo.addItem(name, query)
            
    def _on_example_selected(self, text):
        """
        Handle example selection
        
        @ Args:
            text : Selected example name
        """
        query = self.example_combo.currentData()
        if query:
            self.input_text.setPlainText(query)
            
    def _obfuscate_query(self):
        """
        Obfuscate the input query
        
        ~ Description : Applies selected obfuscation techniques to the input
        """
        input_query = self.input_text.toPlainText().strip()
        if not input_query:
            QMessageBox.warning(self, "No Input", "Please enter a query to obfuscate")
            return
            
        # Get selected techniques
        techniques = [key for key, checkbox in self.tech_checkboxes.items() 
                      if checkbox.isChecked()]
        
        if not techniques:
            QMessageBox.warning(self, "No Techniques", 
                                "Please select at least one obfuscation technique")
            return
            
        try:
            # Obfuscate
            obfuscated = self.obfuscator.obfuscate_filter(input_query, techniques)
            
            # Display result
            self.output_text.setPlainText(obfuscated)
            
            # Show info about what was done
            info = f"Original: {input_query}\n"
            info += f"Techniques applied: {', '.join(techniques)}\n"
            info += f"Result: {obfuscated}"
            
        except Exception as e:
            QMessageBox.critical(self, "Obfuscation Error", 
                                 f"Failed to obfuscate query: {str(e)}")
            
    def _copy_output(self):
        """Copy obfuscated query to clipboard"""
        output = self.output_text.toPlainText()
        if output:
            clipboard = QApplication.clipboard()
            clipboard.setText(output)
            QMessageBox.information(self, "Copied", 
                                    "Obfuscated query copied to clipboard")


"""
# Neo4j Connection Dialog
~ Description : Neo4j database connection and data ingestion dialog

@ Functionality:
  - Connect to Neo4j database
  - Ingest LDAP data directly
  - Progress tracking
  - Error handling
"""


class Neo4jIngestionThread(QThread):
    """
    Neo4j ingestion worker thread
    
    ~ Description : Handles data ingestion to Neo4j in background thread
    
    @ Signals:
        progress_updated : Emits current progress percentage
        status_updated   : Emits status messages
        error_occurred   : Emits error messages
        finished         : Emits when ingestion completes
    """
    
    progress_updated = pyqtSignal(int)
    status_updated = pyqtSignal(str)
    error_occurred = pyqtSignal(str)
    finished = pyqtSignal()
    
    def __init__(self, uri, username, password, ldap_data):
        """
        Initialize ingestion thread
        
        @ Args:
            uri       : Neo4j connection URI
            username  : Neo4j username
            password  : Neo4j password
            ldap_data : LDAP data to ingest
        """
        super().__init__()
        self.uri = uri
        self.username = username
        self.password = password
        self.ldap_data = ldap_data
        
    def run(self):
        """Run ingestion process"""
        try:
            # Import and create connector
            from .exporters import Neo4jConnector
            
            # Create connector
            connector = Neo4jConnector(self.uri, self.username, self.password)
            
            # Test connection
            self.status_updated.emit("Testing connection...")
            if not connector.test_connection():
                self.error_occurred.emit("Failed to connect to Neo4j")
                return
                
            # Ingest data
            self.status_updated.emit("Starting data ingestion...")
            
            # Progress callback
            def progress_callback(current, total):
                if total > 0:
                    percent = int((current / total) * 100)
                    self.progress_updated.emit(percent)
                    
            # Ingest with progress tracking
            stats = connector.ingest_ldap_data(self.ldap_data, progress_callback)
            
            # Close connection
            connector.close()
            
            # Report results
            self.status_updated.emit(
                f"Ingestion complete: {stats['nodes_created']} nodes, "
                f"{stats['relationships_created']} relationships"
            )
            
        except Exception as e:
            self.error_occurred.emit(f"Ingestion error: {str(e)}")
        finally:
            self.finished.emit()


class Neo4jConnectionDialog(QDialog):
    """
    Neo4j connection and ingestion dialog
    
    ~ Description : Manages connection to Neo4j database and data ingestion
    
    @ Attributes:
        ldap_data : LDAP data to ingest
    """
    
    def __init__(self, parent=None, ldap_data=None):
        """
        Initialize Neo4j dialog
        
        @ Args:
            parent    : Parent widget
            ldap_data : LDAP data dictionary
        """
        super().__init__(parent)
        self.ldap_data = ldap_data
        self.ingestion_thread = None
        
        self.setWindowTitle("Neo4j Connection")
        self.setModal(True)
        self.resize(500, 400)
        
        self._init_ui()
        
    def _init_ui(self):
        """
        Initialize user interface
        
        ~ Description : Creates the Neo4j connection form and progress display
        """
        layout = QVBoxLayout()
        
        # Connection settings
        conn_group = QGroupBox("Neo4j Connection Settings")
        conn_layout = QFormLayout()
        
        # URI
        self.uri_input = QLineEdit()
        self.uri_input.setText("bolt://localhost:7687")
        conn_layout.addRow("URI:", self.uri_input)
        
        # Username
        self.username_input = QLineEdit()
        self.username_input.setText("neo4j")
        conn_layout.addRow("Username:", self.username_input)
        
        # Password
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        conn_layout.addRow("Password:", self.password_input)
        
        conn_group.setLayout(conn_layout)
        layout.addWidget(conn_group)
        
        # Data info
        if self.ldap_data:
            info_group = QGroupBox("Data to Ingest")
            info_layout = QFormLayout()
            
            total_objects = sum(len(v) for v in self.ldap_data.values())
            info_layout.addRow("Total Objects:", QLabel(str(total_objects)))
            
            for obj_type, objects in self.ldap_data.items():
                info_layout.addRow(f"{obj_type.title()}:", 
                                  QLabel(str(len(objects))))
                
            info_group.setLayout(info_layout)
            layout.addWidget(info_group)
            
        # Progress
        self.progress_label = QLabel("Ready to connect")
        layout.addWidget(self.progress_label)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # Log
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setMaximumHeight(100)
        layout.addWidget(self.log_text)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        self.test_btn = QPushButton("Test Connection")
        self.test_btn.clicked.connect(self._test_connection)
        button_layout.addWidget(self.test_btn)
        
        self.ingest_btn = QPushButton("Start Ingestion")
        self.ingest_btn.clicked.connect(self._start_ingestion)
        self.ingest_btn.setEnabled(bool(self.ldap_data))
        button_layout.addWidget(self.ingest_btn)
        
        button_layout.addStretch()
        
        self.close_btn = QPushButton("Close")
        self.close_btn.clicked.connect(self.accept)
        button_layout.addWidget(self.close_btn)
        
        layout.addLayout(button_layout)
        self.setLayout(layout)
        
    def _test_connection(self):
        """Test Neo4j connection"""
        from .exporters import Neo4jConnector
            
        uri = self.uri_input.text().strip()
        username = self.username_input.text().strip()
        password = self.password_input.text()
        
        if not all([uri, username, password]):
            QMessageBox.warning(self, "Missing Information", 
                                "Please fill in all connection fields")
            return
            
        try:
            connector = Neo4jConnector(uri, username, password)
            if connector.test_connection():
                self.log_text.append("Connection successful")
                QMessageBox.information(self, "Success", 
                                        "Successfully connected to Neo4j")
            else:
                self.log_text.append("Connection failed")
                QMessageBox.critical(self, "Connection Failed", 
                                     "Failed to connect to Neo4j")
            connector.close()
        except Exception as e:
            self.log_text.append(f"Error: {str(e)}")
            QMessageBox.critical(self, "Connection Error", str(e))
            
    def _start_ingestion(self):
        """Start data ingestion to Neo4j"""
        if not self.ldap_data:
            QMessageBox.warning(self, "No Data", "No LDAP data to ingest")
            return
            
        uri = self.uri_input.text().strip()
        username = self.username_input.text().strip()
        password = self.password_input.text()
        
        if not all([uri, username, password]):
            QMessageBox.warning(self, "Missing Information", 
                                "Please fill in all connection fields")
            return
            
        # Disable controls
        self.test_btn.setEnabled(False)
        self.ingest_btn.setEnabled(False)
        self.uri_input.setEnabled(False)
        self.username_input.setEnabled(False)
        self.password_input.setEnabled(False)
        
        # Show progress
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        
        # Create and start thread
        self.ingestion_thread = Neo4jIngestionThread(
            uri, username, password, self.ldap_data
        )
        self.ingestion_thread.progress_updated.connect(self._update_progress)
        self.ingestion_thread.status_updated.connect(self._update_status)
        self.ingestion_thread.error_occurred.connect(self._handle_error)
        self.ingestion_thread.finished.connect(self._ingestion_finished)
        
        self.ingestion_thread.start()
        
    def _update_progress(self, value):
        """Update progress bar"""
        self.progress_bar.setValue(value)
        
    def _update_status(self, message):
        """Update status message"""
        self.progress_label.setText(message)
        self.log_text.append(message)
        
    def _handle_error(self, error):
        """Handle ingestion error"""
        self.log_text.append(f"Error: {error}")
        QMessageBox.critical(self, "Ingestion Error", error)
        
    def _ingestion_finished(self):
        """Handle ingestion completion"""
        # Re-enable controls
        self.test_btn.setEnabled(True)
        self.ingest_btn.setEnabled(True)
        self.uri_input.setEnabled(True)
        self.username_input.setEnabled(True)
        self.password_input.setEnabled(True)
        
        # Update UI
        self.progress_bar.setVisible(False)
        self.progress_label.setText("Ingestion complete")
        
        # Show completion message
        if "Error" not in self.log_text.toPlainText():
            QMessageBox.information(self, "Success", 
                                    "Data successfully ingested to Neo4j")


"""
# Debug Dialog
~ Description : Query debug console for performance analysis

@ Functionality:
  - Real-time query logging
  - Performance metrics
  - Cache hit/miss tracking
  - Export query logs
"""


class DebugDialog(QDialog):
    """
    LDAP query debug console
    
    ~ Description : Displays query history and performance metrics for
                    debugging and optimization
    
    @ Attributes:
        ldap_conn : Active LDAP connection with debug capabilities
    """
    
    def __init__(self, parent=None, ldap_connection=None):
        """
        Initialize debug dialog
        
        @ Args:
            parent         : Parent widget
            ldap_connection: Active LDAP connection
        """
        super().__init__(parent)
        self.ldap_conn = ldap_connection
        
        self.setWindowTitle("LDAP Query Debug Console")
        self.setGeometry(200, 200, 1200, 800)
        
        # Auto-refresh timer
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self._refresh_query_log)
        
        self._init_ui()
        self._load_query_log()
        
    def _init_ui(self):
        """
        Initialize user interface
        
        ~ Description : Creates the debug console layout with query table,
                        details panel, and statistics
        """
        layout = QVBoxLayout()
        
        # Control panel
        control_layout = QHBoxLayout()
        
        # Debug mode toggle
        self.debug_checkbox = QCheckBox("Enable Query Logging")
        self.debug_checkbox.setChecked(
            self.ldap_conn.debug_mode if self.ldap_conn else False
        )
        self.debug_checkbox.stateChanged.connect(self._toggle_debug_mode)
        control_layout.addWidget(self.debug_checkbox)
        
        # Auto-refresh toggle
        self.auto_refresh = QCheckBox("Auto-refresh (2s)")
        self.auto_refresh.stateChanged.connect(self._toggle_auto_refresh)
        control_layout.addWidget(self.auto_refresh)
        
        control_layout.addStretch()
        
        # Buttons
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self._refresh_query_log)
        control_layout.addWidget(refresh_btn)
        
        clear_btn = QPushButton("Clear Log")
        clear_btn.clicked.connect(self._clear_log)
        control_layout.addWidget(clear_btn)
        
        export_btn = QPushButton("Export Log")
        export_btn.clicked.connect(self._export_log)
        control_layout.addWidget(export_btn)
        
        layout.addLayout(control_layout)
        
        # Create splitter for table and details
        splitter = QSplitter(Qt.Orientation.Vertical)
        
        # Query table
        self.query_table = QTableWidget()
        self.query_table.setColumnCount(7)
        self.query_table.setHorizontalHeaderLabels([
            "Timestamp", "Type", "Filter", "Base DN", 
            "Results", "Duration (ms)", "Cache"
        ])
        self.query_table.setAlternatingRowColors(True)
        self.query_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self.query_table.itemSelectionChanged.connect(self._show_query_details)
        
        # Set column widths
        header = self.query_table.horizontalHeader()
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        
        splitter.addWidget(self.query_table)
        
        # Details panel
        details_group = QGroupBox("Query Details")
        details_layout = QVBoxLayout()
        
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        
        # Use monospace font
        font = QFont()
        font.setFamily("Consolas" if sys.platform == "win32" else 
                      "Monaco" if sys.platform == "darwin" else "monospace")
        font.setPointSize(10)
        font.setStyleHint(QFont.StyleHint.Monospace)
        self.details_text.setFont(font)
        
        details_layout.addWidget(self.details_text)
        details_group.setLayout(details_layout)
        splitter.addWidget(details_group)
        
        # Set splitter sizes (70% table, 30% details)
        splitter.setSizes([560, 240])
        
        layout.addWidget(splitter)
        
        # Statistics panel
        stats_layout = QHBoxLayout()
        self.stats_label = QLabel()
        self._update_statistics()
        stats_layout.addWidget(self.stats_label)
        layout.addLayout(stats_layout)
        
        self.setLayout(layout)
        
    def _toggle_debug_mode(self, state):
        """Toggle debug mode on/off"""
        if self.ldap_conn:
            enabled = state == Qt.CheckState.Checked.value
            self.ldap_conn.set_debug_mode(enabled)
            
    def _toggle_auto_refresh(self, state):
        """Toggle auto-refresh on/off"""
        if state == Qt.CheckState.Checked.value:
            self.refresh_timer.start(2000)  # Refresh every 2 seconds
        else:
            self.refresh_timer.stop()
            
    def _refresh_query_log(self):
        """Refresh the query log display"""
        self._load_query_log()
        self._update_statistics()
        
    def _load_query_log(self):
        """Load queries from LDAP connection into table"""
        if not self.ldap_conn:
            return
            
        queries = self.ldap_conn.get_query_log()
        self.query_table.setRowCount(len(queries))
        
        for row, query in enumerate(queries):
            # Timestamp
            timestamp = query.get('timestamp', '')
            self.query_table.setItem(row, 0, QTableWidgetItem(timestamp))
            
            # Type
            query_type = query.get('type', 'unknown')
            self.query_table.setItem(row, 1, QTableWidgetItem(query_type))
            
            # Filter
            params = query.get('params', {})
            filter_text = params.get('filter', '')
            self.query_table.setItem(row, 2, QTableWidgetItem(filter_text))
            
            # Base DN
            base_dn = params.get('base_dn', '')
            self.query_table.setItem(row, 3, QTableWidgetItem(base_dn))
            
            # Results
            result_count = str(query.get('result_count', 0))
            self.query_table.setItem(row, 4, QTableWidgetItem(result_count))
            
            # Duration
            duration = str(query.get('duration_ms', 0))
            self.query_table.setItem(row, 5, QTableWidgetItem(duration))
            
            # Cache
            cache_hit = "HIT" if query.get('cache_hit', False) else "MISS"
            self.query_table.setItem(row, 6, QTableWidgetItem(cache_hit))
            
            # Color code based on performance
            self._color_code_row(row, query)
            
    def _color_code_row(self, row, query):
        """
        Color code table row based on performance
        
        @ Args:
            row   : Row index
            query : Query data dictionary
        """
        duration_ms = query.get('duration_ms', 0)
        
        if duration_ms > 1000:
            # Slow queries in red
            for col in range(7):
                item = self.query_table.item(row, col)
                if item:
                    item.setBackground(Qt.GlobalColor.red)
                    item.setForeground(Qt.GlobalColor.white)
        elif duration_ms > 500:
            # Medium queries in yellow
            for col in range(7):
                item = self.query_table.item(row, col)
                if item:
                    item.setBackground(Qt.GlobalColor.yellow)
                    
    def _show_query_details(self):
        """Show detailed information for selected query"""
        current_row = self.query_table.currentRow()
        if current_row < 0:
            return
            
        queries = self.ldap_conn.get_query_log()
        if current_row < len(queries):
            query = queries[current_row]
            
            # Format query details
            details = []
            details.append("Query Details")
            details.append("=" * 50)
            details.append("")
            details.append(f"Timestamp: {query.get('timestamp', 'N/A')}")
            details.append(f"Type: {query.get('type', 'N/A')}")
            details.append(f"Duration: {query.get('duration_ms', 0)} ms")
            details.append(f"Result Count: {query.get('result_count', 0)}")
            details.append(f"Cache Hit: {'Yes' if query.get('cache_hit', False) else 'No'}")
            details.append("")
            details.append("Parameters:")
            details.append("-" * 30)
            
            params = query.get('params', {})
            for key, value in params.items():
                if isinstance(value, list):
                    details.append(f"{key}:")
                    for item in value:
                        details.append(f"  - {item}")
                else:
                    details.append(f"{key}: {value}")
                    
            self.details_text.setText('\n'.join(details))
            
    def _update_statistics(self):
        """Update statistics label"""
        if not self.ldap_conn:
            return
            
        queries = self.ldap_conn.get_query_log()
        total_queries = len(queries)
        
        if total_queries > 0:
            # Calculate statistics
            total_duration = sum(q.get('duration_ms', 0) for q in queries)
            avg_duration = total_duration / total_queries
            
            cache_hits = sum(1 for q in queries if q.get('cache_hit', False))
            cache_rate = (cache_hits / total_queries) * 100
            
            total_results = sum(q.get('result_count', 0) for q in queries)
            
            # Find slowest query
            slowest = max(queries, key=lambda q: q.get('duration_ms', 0))
            slowest_duration = slowest.get('duration_ms', 0)
            
            stats_text = (
                f"Total Queries: {total_queries} | "
                f"Avg Duration: {avg_duration:.1f}ms | "
                f"Cache Hit Rate: {cache_rate:.1f}% | "
                f"Total Results: {total_results} | "
                f"Slowest Query: {slowest_duration}ms"
            )
        else:
            stats_text = "No queries logged yet"
            
        self.stats_label.setText(stats_text)
        
    def _clear_log(self):
        """Clear the query log"""
        reply = QMessageBox.question(
            self, "Clear Log",
            "Are you sure you want to clear the query log?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            if self.ldap_conn:
                self.ldap_conn.clear_query_log()
                self._refresh_query_log()
                
    def _export_log(self):
        """Export query log to file"""
        if not self.ldap_conn:
            return
            
        filename, _ = QFileDialog.getSaveFileName(
            self, "Export Query Log", 
            f"ldap_queries_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            "JSON Files (*.json);;CSV Files (*.csv)"
        )
        
        if filename:
            queries = self.ldap_conn.get_query_log()
            
            if filename.endswith('.json'):
                # Export as JSON
                with open(filename, 'w') as f:
                    json.dump(queries, f, indent=2)
            elif filename.endswith('.csv'):
                # Export as CSV
                import csv
                with open(filename, 'w', newline='') as f:
                    if queries:
                        fieldnames = [
                            'timestamp', 'type', 'filter', 'base_dn',
                            'result_count', 'duration_ms', 'cache_hit'
                        ]
                        writer = csv.DictWriter(f, fieldnames=fieldnames)
                        writer.writeheader()
                        
                        for query in queries:
                            row = {
                                'timestamp': query.get('timestamp', ''),
                                'type': query.get('type', ''),
                                'filter': query.get('params', {}).get('filter', ''),
                                'base_dn': query.get('params', {}).get('base_dn', ''),
                                'result_count': query.get('result_count', 0),
                                'duration_ms': query.get('duration_ms', 0),
                                'cache_hit': query.get('cache_hit', False)
                            }
                            writer.writerow(row)
                            
            QMessageBox.information(
                self, "Export Complete",
                f"Query log exported to {filename}"
            )
