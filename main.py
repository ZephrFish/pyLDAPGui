#!/usr/bin/env python3
"""
pyLDAPGui - LDAP browser with BloodHound export capabilities
Built with PyQt6 for cross-platform compatibility

Now with Throttling mode enabled by default to avoid detection
"""
import sys
import os
import json
import csv
from datetime import datetime

# PyQt6 imports - yeah it's a lot but we use most of them
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTreeWidget, QTreeWidgetItem, QTableWidget, QTableWidgetItem,
    QSplitter, QMenuBar, QMenu, QStatusBar, QToolBar, QMessageBox,
    QDialog, QDialogButtonBox, QLabel, QLineEdit, QCheckBox,
    QGridLayout, QPushButton, QFileDialog, QHeaderView,
    QTabWidget, QTextEdit, QComboBox, QFormLayout, QListWidget,
    QGroupBox, QSpinBox
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QAction, QKeySequence, QIcon

# All the utils - mostly hacked together but also borrowed from various stack overflow threads
from utilities.ldap_connection import LDAPConnection
from utilities.profiles import ProfileManager
from utilities.exporters import BloodhoundExporter, CSVExporter
from utilities.ui_dialogs import (
    SearchDialog, TrustBrowserDialog, ObfuscationDialog,
    Neo4jConnectionDialog, DebugDialog
)


class ConnectionDialog(QDialog):
    def __init__(self, parent=None, profile_manager=None):
        super().__init__(parent)
        self.setWindowTitle("Connect to LDAP Server")
        self.setModal(True)
        self.resize(500, 550)
        self.profile_manager = profile_manager
        
        layout = QGridLayout()
        
        # Profile selection
        layout.addWidget(QLabel("Profile:"), 0, 0)
        self.profile_combo = QComboBox()
        self.profile_combo.addItem("-- New Connection --")
        if self.profile_manager:
            for profile in self.profile_manager.list_profiles():
                self.profile_combo.addItem(profile)
        self.profile_combo.currentTextChanged.connect(self.on_profile_selected)
        layout.addWidget(self.profile_combo, 0, 1, 1, 2)
        
        # Server
        layout.addWidget(QLabel("Server:"), 1, 0)
        self.server_input = QLineEdit()
        self.server_input.setPlaceholderText("ldap.example.com")
        layout.addWidget(self.server_input, 1, 1, 1, 2)
        
        # Port
        layout.addWidget(QLabel("Port:"), 2, 0)
        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("389")
        layout.addWidget(self.port_input, 2, 1, 1, 2)
        
        # Username
        layout.addWidget(QLabel("Username:"), 3, 0)
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("cn=admin,dc=example,dc=com or DOMAIN\\username")
        layout.addWidget(self.username_input, 3, 1, 1, 2)
        
        # Password
        layout.addWidget(QLabel("Password:"), 4, 0)
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.password_input, 4, 1, 1, 2)
        
        # SSL
        self.ssl_checkbox = QCheckBox("Use SSL/TLS")
        layout.addWidget(self.ssl_checkbox, 5, 0, 1, 3)
        
        # Proxy Settings Group
        proxy_group = QGroupBox("Proxy Settings (Optional)")
        proxy_layout = QGridLayout()
        
        # Proxy checkbox
        self.proxy_checkbox = QCheckBox("Use Proxy")
        self.proxy_checkbox.toggled.connect(self.toggle_proxy_settings)
        proxy_layout.addWidget(self.proxy_checkbox, 0, 0, 1, 3)
        
        # Check if SOCKS support is available
        from utilities.ldap_connection import LDAPConnection
        if not LDAPConnection.has_socks_support():
            info_label = QLabel("Note: SOCKS proxy requires: pip install python-socks[asyncio]")
            info_label.setStyleSheet("color: orange; font-size: 11px;")
            proxy_layout.addWidget(info_label, 1, 0, 1, 3)
        
        # Proxy Type
        proxy_layout.addWidget(QLabel("Type:"), 2, 0)
        self.proxy_type_combo = QComboBox()
        self.proxy_type_combo.addItems(["SOCKS5", "SOCKS4", "HTTP"])
        self.proxy_type_combo.setEnabled(False)
        proxy_layout.addWidget(self.proxy_type_combo, 2, 1, 1, 2)
        
        # Proxy Host
        proxy_layout.addWidget(QLabel("Host:"), 3, 0)
        self.proxy_host_input = QLineEdit()
        self.proxy_host_input.setPlaceholderText("127.0.0.1")
        self.proxy_host_input.setEnabled(False)
        proxy_layout.addWidget(self.proxy_host_input, 3, 1, 1, 2)
        
        # Proxy Port
        proxy_layout.addWidget(QLabel("Port:"), 4, 0)
        self.proxy_port_input = QSpinBox()
        self.proxy_port_input.setRange(1, 65535)
        self.proxy_port_input.setValue(1080)
        self.proxy_port_input.setEnabled(False)
        proxy_layout.addWidget(self.proxy_port_input, 4, 1, 1, 2)
        
        # Proxy Username (optional)
        proxy_layout.addWidget(QLabel("Username:"), 5, 0)
        self.proxy_username_input = QLineEdit()
        self.proxy_username_input.setPlaceholderText("Optional")
        self.proxy_username_input.setEnabled(False)
        proxy_layout.addWidget(self.proxy_username_input, 5, 1, 1, 2)
        
        # Proxy Password (optional)
        proxy_layout.addWidget(QLabel("Password:"), 6, 0)
        self.proxy_password_input = QLineEdit()
        self.proxy_password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.proxy_password_input.setPlaceholderText("Optional")
        self.proxy_password_input.setEnabled(False)
        proxy_layout.addWidget(self.proxy_password_input, 6, 1, 1, 2)
        
        proxy_group.setLayout(proxy_layout)
        layout.addWidget(proxy_group, 6, 0, 1, 3)
        
        # Save profile checkbox
        self.save_profile_checkbox = QCheckBox("Save as profile:")
        layout.addWidget(self.save_profile_checkbox, 7, 0)
        self.profile_name_input = QLineEdit()
        self.profile_name_input.setEnabled(False)
        self.save_profile_checkbox.toggled.connect(self.profile_name_input.setEnabled)
        layout.addWidget(self.profile_name_input, 7, 1, 1, 2)
        
        # Buttons
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons, 8, 0, 1, 3)
        
        self.setLayout(layout)
        
    def toggle_proxy_settings(self, checked):
        """Enable/disable proxy settings based on checkbox"""
        self.proxy_type_combo.setEnabled(checked)
        self.proxy_host_input.setEnabled(checked)
        self.proxy_port_input.setEnabled(checked)
        self.proxy_username_input.setEnabled(checked)
        self.proxy_password_input.setEnabled(checked)
        
    def on_profile_selected(self, profile_name):
        if profile_name == "-- New Connection --" or not self.profile_manager:
            # Clear fields
            self.server_input.clear()
            self.port_input.clear()
            self.username_input.clear()
            self.password_input.clear()
            self.ssl_checkbox.setChecked(False)
            self.proxy_checkbox.setChecked(False)
            self.proxy_host_input.clear()
            self.proxy_port_input.setValue(1080)
            self.proxy_username_input.clear()
            self.proxy_password_input.clear()
            self.proxy_type_combo.setCurrentIndex(0)
        else:
            # Load profile
            profile = self.profile_manager.get_profile(profile_name)
            if profile:
                self.server_input.setText(profile['host'])
                self.port_input.setText(str(profile['port']) if profile['port'] else "")
                self.username_input.setText(profile['username'])
                self.password_input.setText(profile['password'])
                self.ssl_checkbox.setChecked(profile['use_ssl'])
                
                # Load proxy settings if available
                proxy_settings = profile.get('proxy_settings', {})
                if proxy_settings and proxy_settings.get('enabled'):
                    self.proxy_checkbox.setChecked(True)
                    self.proxy_type_combo.setCurrentText(proxy_settings.get('type', 'SOCKS5'))
                    self.proxy_host_input.setText(proxy_settings.get('host', ''))
                    self.proxy_port_input.setValue(proxy_settings.get('port', 1080))
                    self.proxy_username_input.setText(proxy_settings.get('username', ''))
                    self.proxy_password_input.setText(proxy_settings.get('password', ''))
                else:
                    self.proxy_checkbox.setChecked(False)
        
    def get_connection_details(self):
        port = self.port_input.text()
        if not port:
            port = None
        else:
            port = int(port)
            
        details = {
            'host': self.server_input.text(),
            'username': self.username_input.text(),
            'password': self.password_input.text(),
            'use_ssl': self.ssl_checkbox.isChecked(),
            'port': port
        }
        
        # Add proxy settings if enabled
        if self.proxy_checkbox.isChecked():
            proxy_settings = {
                'enabled': True,
                'type': self.proxy_type_combo.currentText(),
                'host': self.proxy_host_input.text(),
                'port': self.proxy_port_input.value(),
                'username': self.proxy_username_input.text() or None,
                'password': self.proxy_password_input.text() or None
            }
            details['proxy_settings'] = proxy_settings
        else:
            details['proxy_settings'] = None
        
        # Save profile if requested
        if self.save_profile_checkbox.isChecked() and self.profile_name_input.text() and self.profile_manager:
            self.profile_manager.add_profile(
                self.profile_name_input.text(),
                details['host'],
                details['port'],
                details['username'],
                details['password'],
                details['use_ssl'],
                proxy_settings=details.get('proxy_settings')
            )
            
        return details


class LDAPBrowser(QMainWindow):
    def __init__(self):
        super().__init__()
        self.ldap_conn = LDAPConnection()
        self.current_entries = []
        self.profile_manager = ProfileManager()
        self.init_ui()
        
    def init_ui(self):
        self.setWindowTitle("pyLDAPGui")
        self.setGeometry(100, 100, 1200, 800)
        
        # Set application icon
        self._set_app_icon()
        
        # Create menu bar
        self.create_menu_bar()
        
        # Create toolbar
        self.create_toolbar()
        
        # Create main widget
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        
        # Create layout
        layout = QHBoxLayout(main_widget)
        
        # Create splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left panel - Tree view with filter
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        
        # Filter input
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Filter:"))
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Type to filter tree...")
        self.filter_input.textChanged.connect(self.on_filter_changed)
        filter_layout.addWidget(self.filter_input)
        clear_filter_btn = QPushButton("Clear")
        clear_filter_btn.clicked.connect(self.clear_filter)
        filter_layout.addWidget(clear_filter_btn)
        left_layout.addLayout(filter_layout)
        
        # Tree widget
        self.tree_widget = QTreeWidget()
        self.tree_widget.setHeaderLabel("LDAP Directory")
        self.tree_widget.itemExpanded.connect(self.on_item_expanded)
        self.tree_widget.itemSelectionChanged.connect(self.on_item_selected)
        left_layout.addWidget(self.tree_widget)
        
        splitter.addWidget(left_widget)
        
        # Right panel
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        
        # Quick Export buttons
        export_button_layout = QHBoxLayout()
        
        # Bloodhound export button - make it prominent
        self.bloodhound_export_btn = QPushButton("Export to Bloodhound")
        self.bloodhound_export_btn.setToolTip("Export all LDAP data to Bloodhound 4.3 Legacy format")
        self.bloodhound_export_btn.setStyleSheet("""
            QPushButton {
                background-color: #4287f5;
                color: white;
                font-weight: bold;
                font-size: 14px;
                padding: 8px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #3070d0;
            }
            QPushButton:pressed {
                background-color: #2050a0;
            }
            QPushButton:disabled {
                background-color: #cccccc;
                color: #666666;
            }
        """)
        self.bloodhound_export_btn.clicked.connect(self.export_to_bloodhound)
        self.bloodhound_export_btn.setEnabled(False)  # Enable when connected
        export_button_layout.addWidget(self.bloodhound_export_btn)
        
        # CSV export button
        self.csv_export_btn = QPushButton("Export to CSV")
        self.csv_export_btn.setToolTip("Export all LDAP data to CSV format")
        self.csv_export_btn.setStyleSheet("""
            QPushButton {
                background-color: #6c757d;
                color: white;
                font-weight: bold;
                font-size: 14px;
                padding: 8px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #5a6268;
            }
            QPushButton:pressed {
                background-color: #495057;
            }
            QPushButton:disabled {
                background-color: #cccccc;
                color: #666666;
            }
        """)
        self.csv_export_btn.clicked.connect(self.export_to_csv)
        self.csv_export_btn.setEnabled(False)  # Enable when connected
        export_button_layout.addWidget(self.csv_export_btn)
        
        # Neo4j ingestion button
        self.neo4j_ingest_btn = QPushButton("Ingest to Neo4j")
        self.neo4j_ingest_btn.setStyleSheet("""
            QPushButton {
                background-color: #1c8e51;
                color: white;
                font-weight: bold;
                font-size: 14px;
                padding: 8px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #157a42;
            }
            QPushButton:pressed {
                background-color: #0f5530;
            }
            QPushButton:disabled {
                background-color: #cccccc;
                color: #666666;
            }
        """)
        self.neo4j_ingest_btn.setToolTip("Ingest LDAP data directly to BloodHound Neo4j database")
        self.neo4j_ingest_btn.clicked.connect(self.ingest_to_neo4j)
        self.neo4j_ingest_btn.setEnabled(False)  # Enable when connected
        export_button_layout.addWidget(self.neo4j_ingest_btn)
        
        right_layout.addLayout(export_button_layout)
        
        # Add spacing
        right_layout.addSpacing(10)
        
        # Security Analysis buttons
        security_button_layout = QHBoxLayout()
        
        # ADCS Analysis button
        self.adcs_analysis_btn = QPushButton("ADCS Analysis")
        self.adcs_analysis_btn.setToolTip("Analyze Active Directory Certificate Services for vulnerabilities")
        self.adcs_analysis_btn.setStyleSheet("""
            QPushButton {
                background-color: #dc3545;
                color: white;
                font-weight: bold;
                font-size: 14px;
                padding: 8px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #c82333;
            }
            QPushButton:pressed {
                background-color: #bd2130;
            }
            QPushButton:disabled {
                background-color: #cccccc;
                color: #666666;
            }
        """)
        self.adcs_analysis_btn.clicked.connect(self.show_adcs_analysis)
        self.adcs_analysis_btn.setEnabled(False)  # Enable when connected
        security_button_layout.addWidget(self.adcs_analysis_btn)
        
        # Trust Analysis button
        self.trust_analysis_btn = QPushButton("Trust Analysis")
        self.trust_analysis_btn.setToolTip("Browse and analyze domain trust relationships")
        self.trust_analysis_btn.setStyleSheet("""
            QPushButton {
                background-color: #fd7e14;
                color: white;
                font-weight: bold;
                font-size: 14px;
                padding: 8px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #e96d09;
            }
            QPushButton:pressed {
                background-color: #d85c08;
            }
            QPushButton:disabled {
                background-color: #cccccc;
                color: #666666;
            }
        """)
        self.trust_analysis_btn.clicked.connect(self.show_trust_browser)
        self.trust_analysis_btn.setEnabled(False)  # Enable when connected
        security_button_layout.addWidget(self.trust_analysis_btn)
        
        right_layout.addLayout(security_button_layout)

        self.tab_widget = QTabWidget()

        self.attr_table = QTableWidget()
        self.attr_table.setColumnCount(2)
        self.attr_table.setHorizontalHeaderLabels(["Attribute", "Value"])
        self.attr_table.horizontalHeader().setStretchLastSection(True)
        self.tab_widget.addTab(self.attr_table, "Attributes")
        
        self.raw_text = QTextEdit()
        self.raw_text.setReadOnly(True)
        self.tab_widget.addTab(self.raw_text, "Raw Data")

        self.server_info_text = QTextEdit()
        self.server_info_text.setReadOnly(True)
        self.tab_widget.addTab(self.server_info_text, "Server Info")
        
        right_layout.addWidget(self.tab_widget)
        
        splitter.addWidget(right_widget)

        splitter.setSizes([400, 800])
        
        layout.addWidget(splitter)
        
        # Show if we are connected or not in a status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Not connected")
        
    def create_menu_bar(self):
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("File")
        
        connect_action = QAction("Connect...", self)
        connect_action.triggered.connect(self.show_connection_dialog)
        file_menu.addAction(connect_action)
        
        disconnect_action = QAction("Disconnect", self)
        disconnect_action.triggered.connect(self.disconnect)
        file_menu.addAction(disconnect_action)
        
        file_menu.addSeparator()
        
        export_csv_action = QAction("Export to CSV...", self)
        export_csv_action.setShortcut(QKeySequence("Ctrl+E"))
        export_csv_action.triggered.connect(self.export_to_csv)
        file_menu.addAction(export_csv_action)
        
        export_bloodhound_action = QAction("Export to Bloodhound...", self)
        export_bloodhound_action.setShortcut(QKeySequence("Ctrl+B"))
        export_bloodhound_action.setStatusTip("Export LDAP data to Bloodhound 4.x Legacy format with relationships")
        export_bloodhound_action.triggered.connect(self.export_to_bloodhound)
        file_menu.addAction(export_bloodhound_action)
        
        neo4j_ingest_action = QAction("Ingest to Neo4j...", self)
        neo4j_ingest_action.setShortcut(QKeySequence("Ctrl+N"))
        neo4j_ingest_action.setStatusTip("Ingest LDAP data directly to BloodHound Neo4j database")
        neo4j_ingest_action.triggered.connect(self.ingest_to_neo4j)
        file_menu.addAction(neo4j_ingest_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # View menu
        view_menu = menubar.addMenu("View")
        
        refresh_action = QAction("Refresh", self)
        refresh_action.triggered.connect(self.refresh_tree)
        view_menu.addAction(refresh_action)
        
        # Export menu
        export_menu = menubar.addMenu("Export")
        
        export_csv_action2 = QAction("Export All to CSV...", self)
        export_csv_action2.triggered.connect(self.export_to_csv)
        export_menu.addAction(export_csv_action2)
        
        export_bloodhound_action2 = QAction("Export All to Bloodhound...", self)
        export_bloodhound_action2.triggered.connect(self.export_to_bloodhound)
        export_menu.addAction(export_bloodhound_action2)
        
        export_opengraph_action = QAction("Export to OpenGraph...", self)
        export_opengraph_action.triggered.connect(self.export_to_opengraph)
        export_menu.addAction(export_opengraph_action)
        
        export_menu.addSeparator()
        
        export_selected_csv_action = QAction("Export Selected to CSV...", self)
        export_selected_csv_action.setEnabled(False)  # Will implement later
        export_menu.addAction(export_selected_csv_action)
        
        export_selected_bloodhound_action = QAction("Export Selected to Bloodhound...", self)
        export_selected_bloodhound_action.setEnabled(False)  # Will implement later
        export_menu.addAction(export_selected_bloodhound_action)
        
        # Search menu
        search_menu = menubar.addMenu("Search")
        
        search_action = QAction("Search...", self)
        search_action.setShortcut(QKeySequence("Ctrl+F"))
        search_action.triggered.connect(self.show_search_dialog)
        search_menu.addAction(search_action)
        
        filter_action = QAction("Filter Tree...", self)
        filter_action.setShortcut(QKeySequence("Ctrl+Shift+F"))
        filter_action.triggered.connect(self.focus_filter)
        search_menu.addAction(filter_action)
        
        # Tools menu
        tools_menu = menubar.addMenu("Tools")
        
        manage_profiles_action = QAction("Manage Profiles...", self)
        manage_profiles_action.triggered.connect(self.show_manage_profiles_dialog)
        tools_menu.addAction(manage_profiles_action)
        
        tools_menu.addSeparator()
        
        trust_browser_action = QAction("Browse Domain Trusts...", self)
        trust_browser_action.setStatusTip("View and analyse domain trust relationships")
        trust_browser_action.triggered.connect(self.show_trust_browser)
        tools_menu.addAction(trust_browser_action)
        
        tools_menu.addSeparator()
        
        obfuscation_action = QAction("LDAP Query Obfuscation...", self)
        obfuscation_action.setStatusTip("Generate obfuscated LDAP queries to evade detection")
        obfuscation_action.triggered.connect(self.show_obfuscation_dialog)
        tools_menu.addAction(obfuscation_action)
        
        tools_menu.addSeparator()
        
        # Query Optimization settings
        cache_action = QAction('Query Cache Settings...', self)
        cache_action.setStatusTip("Configure LDAP query caching for performance")
        cache_action.triggered.connect(self.show_cache_settings)
        tools_menu.addAction(cache_action)
        
        clear_cache_action = QAction('Clear Query Cache', self)
        clear_cache_action.setStatusTip("Clear all cached LDAP query results")
        clear_cache_action.triggered.connect(self.clear_query_cache)
        tools_menu.addAction(clear_cache_action)
        
        # Query Debug Console
        debug_action = QAction('Query Debug Console...', self)
        debug_action.setStatusTip("View LDAP query history and performance metrics")
        debug_action.triggered.connect(self.show_debug_console)
        tools_menu.addAction(debug_action)
        
        tools_menu.addSeparator()
        
        adcs_analysis_action = QAction("ADCS Certificate Analysis...", self)
        adcs_analysis_action.setStatusTip("Analyze Active Directory Certificate Services for vulnerabilities")
        adcs_analysis_action.triggered.connect(self.show_adcs_analysis)
        tools_menu.addAction(adcs_analysis_action)
        
        tools_menu.addSeparator()
        
        bloodhound_debug_action = QAction("Bloodhound Debug Tests...", self)
        bloodhound_debug_action.setStatusTip("Create test files to debug Bloodhound import issues")
        bloodhound_debug_action.triggered.connect(self.create_bloodhound_debug_tests)
        tools_menu.addAction(bloodhound_debug_action)
        
        # Throttling menu - for operational security settings
        Throttling_menu = menubar.addMenu("Throttling")
        
        self.Throttling_toggle_action = QAction("Enable Throttling Mode", self)
        self.Throttling_toggle_action.setCheckable(True)
        self.Throttling_toggle_action.setChecked(True)  # on by default
        self.Throttling_toggle_action.setStatusTip("Randomise query order and timing to avoid detection")
        self.Throttling_toggle_action.triggered.connect(self.toggle_Throttling_mode)
        Throttling_menu.addAction(self.Throttling_toggle_action)
        
        Throttling_settings_action = QAction("Throttling Settings...", self)
        Throttling_settings_action.setStatusTip("Configure Throttling timing and behaviour")
        Throttling_settings_action.triggered.connect(self.show_Throttling_settings)
        Throttling_menu.addAction(Throttling_settings_action)
        
    def create_toolbar(self):
        toolbar = QToolBar()
        self.addToolBar(toolbar)
        
        connect_action = QAction("Connect", self)
        connect_action.triggered.connect(self.show_connection_dialog)
        toolbar.addAction(connect_action)
        
        disconnect_action = QAction("Disconnect", self)
        disconnect_action.triggered.connect(self.disconnect)
        toolbar.addAction(disconnect_action)
        
        toolbar.addSeparator()
        
        refresh_action = QAction("Refresh", self)
        refresh_action.triggered.connect(self.refresh_tree)
        toolbar.addAction(refresh_action)
        
        toolbar.addSeparator()
        
        export_csv_action = QAction("Export CSV", self)
        export_csv_action.setToolTip("Export all entries to CSV format")
        export_csv_action.triggered.connect(self.export_to_csv)
        toolbar.addAction(export_csv_action)
        
        export_bloodhound_action = QAction("Export to Bloodhound", self)
        export_bloodhound_action.setToolTip("Export to Bloodhound 4.x JSON format")
        export_bloodhound_action.triggered.connect(self.export_to_bloodhound)
        toolbar.addAction(export_bloodhound_action)
        
        toolbar.addSeparator()
        
        search_action = QAction("Search", self)
        search_action.triggered.connect(self.show_search_dialog)
        toolbar.addAction(search_action)
        
        toolbar.addSeparator()
        
        trust_action = QAction("Domain Trusts", self)
        trust_action.setToolTip("Browse domain trust relationships")
        trust_action.triggered.connect(self.show_trust_browser)
        toolbar.addAction(trust_action)
        
        # Debug console button
        debug_action = QAction("Debug", self)
        debug_action.setToolTip("Open LDAP query debug console")
        debug_action.triggered.connect(self.show_debug_console)
        toolbar.addAction(debug_action)
        
    def show_connection_dialog(self):
        dialog = ConnectionDialog(self, self.profile_manager)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            details = dialog.get_connection_details()
            self.connect_to_ldap(**details)
            
    def connect_to_ldap(self, host, username, password, use_ssl, port, proxy_settings=None):
        self.status_bar.showMessage("Connecting...")
        
        # Show proxy info in status if using proxy
        if proxy_settings and proxy_settings.get('enabled'):
            self.status_bar.showMessage(f"Connecting to {host} via {proxy_settings['type']} proxy...")
        
        if self.ldap_conn.connect(host, username, password, use_ssl, port, proxy_settings):
            proxy_info = ""
            if proxy_settings and proxy_settings.get('enabled'):
                proxy_info = f" (via {proxy_settings['type']} proxy)"
            self.status_bar.showMessage(f"Connected to {host}{proxy_info}")
            self.populate_tree()
            self.update_server_info()
            # Enable export buttons
            self.bloodhound_export_btn.setEnabled(True)
            self.csv_export_btn.setEnabled(True)
            self.neo4j_ingest_btn.setEnabled(True)
            # Enable security analysis buttons
            self.adcs_analysis_btn.setEnabled(True)
            self.trust_analysis_btn.setEnabled(True)
        else:
            self.status_bar.showMessage("Connection failed")
            error_msg = "Failed to connect to LDAP server"
            if proxy_settings and proxy_settings.get('enabled'):
                error_msg += f"\n\nProxy settings:\n- Type: {proxy_settings['type']}\n- Host: {proxy_settings['host']}:{proxy_settings['port']}"
                if not self.ldap_conn.has_socks_support():
                    error_msg += "\n\nNote: SOCKS proxy support requires:\npip install python-socks[asyncio]"
            QMessageBox.critical(self, "Connection Error", error_msg)
            
    def disconnect(self):
        self.ldap_conn.disconnect()
        self.tree_widget.clear()
        self.attr_table.setRowCount(0)
        self.raw_text.clear()
        self.server_info_text.clear()
        self.status_bar.showMessage("Disconnected")
        self.bloodhound_export_btn.setEnabled(False)
        self.csv_export_btn.setEnabled(False)
        self.neo4j_ingest_btn.setEnabled(False)
        self.adcs_analysis_btn.setEnabled(False)
        self.trust_analysis_btn.setEnabled(False)
        
    def populate_tree(self):
        self.tree_widget.clear()
        
        if not self.ldap_conn.base_dn:
            return
            
        # Create root item
        root_item = QTreeWidgetItem(self.tree_widget)
        root_item.setText(0, self.ldap_conn.base_dn)
        root_item.setData(0, Qt.ItemDataRole.UserRole, self.ldap_conn.base_dn)
        
        # Add placeholder child
        placeholder = QTreeWidgetItem(root_item)
        placeholder.setText(0, "Loading...")
        
        self.tree_widget.expandItem(root_item)
        
    def on_item_expanded(self, item):
        # Check if this is the first expansion
        if item.childCount() == 1 and item.child(0).text(0) == "Loading...":
            # Remove placeholder
            item.takeChild(0)
            
            # Get DN
            dn = item.data(0, Qt.ItemDataRole.UserRole)
            
            children = self.ldap_conn.get_children(dn)
            
            for child in children:
                child_item = QTreeWidgetItem(item)
                
                # Determine display name
                attrs = child['attributes']
                display_name = child['dn'].split(',')[0]
                
                if 'cn' in attrs:
                    display_name = f"cn={attrs['cn']}"
                elif 'ou' in attrs:
                    display_name = f"ou={attrs['ou']}"
                
                child_item.setText(0, display_name)
                child_item.setData(0, Qt.ItemDataRole.UserRole, child['dn'])
                
                # Add placeholder for expandable items, this is on my todo
                if self.is_container(attrs.get('objectClass', [])):
                    placeholder = QTreeWidgetItem(child_item)
                    placeholder.setText(0, "Loading...")
                    
    def is_container(self, object_classes):
        if isinstance(object_classes, str):
            object_classes = [object_classes]
            
        container_classes = ['organizationalUnit', 'container', 'organization', 'domain', 'builtinDomain']
        return any(oc in container_classes for oc in object_classes)
        
    def on_item_selected(self):
        current_item = self.tree_widget.currentItem()
        if not current_item:
            return
            
        dn = current_item.data(0, Qt.ItemDataRole.UserRole)
        if not dn:
            return
            
        # Get entry details
        entry = self.ldap_conn.get_entry(dn)
        if entry:
            self.display_entry(entry)
            
    def display_entry(self, entry):
        # Update attributes table
        attrs = entry['attributes']
        self.attr_table.setRowCount(len(attrs))
        
        row = 0
        for attr_name, attr_value in sorted(attrs.items()):
            self.attr_table.setItem(row, 0, QTableWidgetItem(attr_name))
            
            # Handle different value types
            if isinstance(attr_value, list):
                value_str = '\n'.join(str(v) for v in attr_value)
            else:
                value_str = str(attr_value)
                
            self.attr_table.setItem(row, 1, QTableWidgetItem(value_str))
            row += 1
            
        # Update raw data
        self.raw_text.setPlainText(json.dumps(entry, indent=2, default=str))
        
    def update_server_info(self):
        info = self.ldap_conn.get_server_info()
        self.server_info_text.setPlainText(json.dumps(info, indent=2, default=str))
        
    def refresh_tree(self):
        if self.ldap_conn.connection:
            self.populate_tree()
            
    def export_to_csv(self):
        if not self.ldap_conn.connection:
            QMessageBox.warning(self, "Export Error", "Not connected to LDAP server")
            return
            
        filename, _ = QFileDialog.getSaveFileName(self, "Export to CSV", "", "CSV Files (*.csv)")
        if not filename:
            return
            
        # Get all entries
        entries = self.ldap_conn.search(size_limit=10000)
        
        if not entries:
            QMessageBox.warning(self, "Export Error", "No entries to export")
            return
            
        # Collect all unique attributes
        all_attrs = set()
        for entry in entries:
            all_attrs.update(entry['attributes'].keys())
            
        # Write CSV
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['dn'] + sorted(list(all_attrs))
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            
            for entry in entries:
                row = {'dn': entry['dn']}
                for attr in all_attrs:
                    if attr in entry['attributes']:
                        value = entry['attributes'][attr]
                        if isinstance(value, list):
                            row[attr] = '|'.join(str(v) for v in value)
                        else:
                            row[attr] = str(value)
                    else:
                        row[attr] = ''
                        
                writer.writerow(row)
                
        QMessageBox.information(self, "Export Complete", f"Exported {len(entries)} entries to {filename}")
        
    def export_to_bloodhound(self):
        if not self.ldap_conn.connection:
            QMessageBox.warning(self, "Export Error", "Not connected to LDAP server")
            return
            
        filename, _ = QFileDialog.getSaveFileName(self, "Export to Bloodhound", "", "JSON Files (*.json)")
        if not filename:
            return
            
        # Show progress
        self.status_bar.showMessage("Exporting to Bloodhound format (optimized queries)...")
        
        # Use optimized batch query method
        try:
            # Get all data using optimized queries
            bloodhound_data = self.ldap_conn.get_bloodhound_data(use_cache=True)
            
            # Combine all entries
            entries = []
            for category, category_entries in bloodhound_data.items():
                entries.extend(category_entries)
            
            # Use the Bloodhound exporter
            exporter = BloodhoundExporter()
            zip_filename = exporter.export_to_bloodhound(entries, filename)
                
            QMessageBox.information(self, "Export Complete", 
                                    f"Exported data to {zip_filename}\n\n"
                                    f"Users: {len(bloodhound_data.get('users', []))}\n"
                                    f"Computers: {len(bloodhound_data.get('computers', []))}\n"
                                    f"Groups: {len(bloodhound_data.get('groups', []))}\n"
                                    f"OUs: {len(bloodhound_data.get('ous', []))}\n"
                                    f"Domains: {len(bloodhound_data.get('domains', []))}\n"
                                    f"Trusts: {len(bloodhound_data.get('trusts', []))}\n\n"
                                    f"Upload this ZIP file to Bloodhound")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", f"Failed to export: {str(e)}")
            self.status_bar.showMessage("Export failed")
        
    def ingest_to_neo4j(self):
        """Open Neo4j connection dialog for direct ingestion"""
        if not self.ldap_conn.connection:
            QMessageBox.warning(self, "Ingestion Error", "Not connected to LDAP server")
            return
            
        # Show progress
        self.status_bar.showMessage("Preparing Neo4j ingestion (optimized queries)...")
        
        try:
            # Use optimized batch query method
            bloodhound_data = self.ldap_conn.get_bloodhound_data(use_cache=True)
            
            # Check if we have any data
            total_entries = sum(len(entries) for entries in bloodhound_data.values())
            if total_entries == 0:
                QMessageBox.warning(self, "Ingestion Error", "No entries to ingest")
                self.status_bar.showMessage("Ready")
                return
            
            # Convert raw LDAP data to BloodHound format
            self.status_bar.showMessage("Converting data to BloodHound format...")
            QApplication.processEvents()  # Update UI
            
            exporter = BloodhoundExporter()
            
            # Flatten all entries to find domain name
            all_entries = []
            for entries in bloodhound_data.values():
                all_entries.extend(entries)
            
            # Get domain name once
            domain_name = exporter._find_domain_name(all_entries)
            
            converted_data = {
                'users': [],
                'computers': [],
                'groups': [],
                'domains': [],
                'ous': []
            }
            
            # Process each entry type
            for entry_type, entries in bloodhound_data.items():
                if entry_type == 'trusts':
                    continue  # Skip trusts for now
                    
                for entry in entries:
                    if entry_type == 'users':
                        obj = exporter._create_user(entry, domain_name)
                        if obj:
                            converted_data['users'].append(obj)
                    elif entry_type == 'computers':
                        obj = exporter._create_computer(entry, domain_name)
                        if obj:
                            converted_data['computers'].append(obj)
                    elif entry_type == 'groups':
                        obj = exporter._create_group(entry, domain_name)
                        if obj:
                            converted_data['groups'].append(obj)
                    elif entry_type == 'domains':
                        obj = exporter._create_domain(entry, domain_name)
                        if obj:
                            converted_data['domains'].append(obj)
                    elif entry_type == 'ous':
                        obj = exporter._create_ou(entry, domain_name)
                        if obj:
                            converted_data['ous'].append(obj)
                
            # Show conversion summary
            self.status_bar.showMessage(
                f"Converted: {len(converted_data['users'])} users, "
                f"{len(converted_data['computers'])} computers, "
                f"{len(converted_data['groups'])} groups"
            )
            QApplication.processEvents()  # Update UI
            
            # Open Neo4j connection dialog with converted data
            dialog = Neo4jConnectionDialog(self, converted_data)
            dialog.exec()
            
            self.status_bar.showMessage("Ready")
        except Exception as e:
            QMessageBox.critical(self, "Ingestion Error", f"Failed to prepare data: {str(e)}")
            self.status_bar.showMessage("Ingestion failed")
        
    def show_manage_profiles_dialog(self):
        dialog = ProfileManagerDialog(self, self.profile_manager)
        dialog.exec()
        
    def show_search_dialog(self):
        if not self.ldap_conn.connection:
            QMessageBox.warning(self, "Search Error", "Not connected to LDAP server")
            return
            
        dialog = SearchDialog(self, self.ldap_conn)
        dialog.exec()
        
    def on_filter_changed(self, text):
        """Filter tree items based on text"""
        self.filter_tree(text)
        
    def filter_tree(self, filter_text):
        """Apply filter to tree widget"""
        filter_text = filter_text.lower()
        
        def set_item_visibility(item, parent_matches=False):
            # Check if this item matches
            item_text = item.text(0).lower()
            item_matches = filter_text in item_text
            
            # Check children
            child_matches = False
            for i in range(item.childCount()):
                child = item.child(i)
                if set_item_visibility(child, item_matches or parent_matches):
                    child_matches = True
                    
            # Item is visible if it matches or has matching children
            visible = item_matches or child_matches or (parent_matches and not filter_text)
            item.setHidden(not visible)
            
            return visible
            
        # Apply filter to all top-level items
        for i in range(self.tree_widget.topLevelItemCount()):
            set_item_visibility(self.tree_widget.topLevelItem(i))
            
        # Expand all visible items if filter is active
        if filter_text:
            self.tree_widget.expandAll()
            
    def clear_filter(self):
        """Clear the filter"""
        self.filter_input.clear()
        
    def focus_filter(self):
        """Focus on the filter input"""
        self.filter_input.setFocus()
        self.filter_input.selectAll()
        
    def show_trust_browser(self):
        """Show domain trust browser dialog"""
        if not self.ldap_conn.connection:
            QMessageBox.warning(self, "Trust Browser", "Not connected to LDAP server")
            return
            
        dialog = TrustBrowserDialog(self, self.ldap_conn)
        dialog.show()  # Non-modal
        # Trusts load automatically via QTimer in dialog init
        
    def show_obfuscation_dialog(self):
        """Show LDAP query obfuscation dialog"""
        dialog = ObfuscationDialog(self)
        dialog.show()  # Non-modal
        
    def create_bloodhound_debug_tests(self):
        """Create systematic test files to debug Bloodhound import issues"""
        from datetime import datetime
        import zipfile
        import json
        import os
        
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        
        # Create debug tests directory
        debug_dir = "bloodhound_debug_tests"
        if not os.path.exists(debug_dir):
            os.makedirs(debug_dir)
        
        test_files_created = []
        
        try:
            # Test 1: Empty files (like OUs that worked)
            empty_tests = [
                ("empty_users.zip", "users"),
                ("empty_computers.zip", "computers"), 
                ("empty_groups.zip", "groups"),
                ("empty_domains.zip", "domains")
            ]
            
            for zip_name, obj_type in empty_tests:
                zip_path = os.path.join(debug_dir, zip_name)
                with zipfile.ZipFile(zip_path, 'w') as zf:
                    content = {
                        obj_type: [],
                        "meta": {"count": 0, "type": obj_type, "version": 4}
                    }
                    zf.writestr(f"{timestamp}_{obj_type}.json", json.dumps(content, separators=(',', ':')))
                test_files_created.append(zip_name)
            
            # Test 2: Minimal objects
            minimal_user = {
                "ObjectIdentifier": "S-1-5-21-1111-2222-3333-1001",
                "Properties": {"domain": "TEST.LOCAL", "name": "USER@TEST.LOCAL"}
            }
            
            zip_path = os.path.join(debug_dir, "minimal_user.zip")
            with zipfile.ZipFile(zip_path, 'w') as zf:
                content = {
                    "users": [minimal_user],
                    "meta": {"count": 1, "type": "users", "version": 4}
                }
                zf.writestr(f"{timestamp}_users.json", json.dumps(content, separators=(',', ':')))
            test_files_created.append("minimal_user.zip")
            
            # Test 3: Basic user with DN
            basic_user = {
                "ObjectIdentifier": "S-1-5-21-1111-2222-3333-1001",
                "Properties": {
                    "domain": "TEST.LOCAL",
                    "name": "USER@TEST.LOCAL",
                    "distinguishedname": "CN=USER,DC=TEST,DC=LOCAL"
                }
            }
            
            zip_path = os.path.join(debug_dir, "basic_user.zip")
            with zipfile.ZipFile(zip_path, 'w') as zf:
                content = {
                    "users": [basic_user],
                    "meta": {"count": 1, "type": "users", "version": 4}
                }
                zf.writestr(f"{timestamp}_users.json", json.dumps(content, separators=(',', ':')))
            test_files_created.append("basic_user.zip")
            
            # Test 4: User with arrays
            array_user = {
                "ObjectIdentifier": "S-1-5-21-1111-2222-3333-1001",
                "Properties": {
                    "domain": "TEST.LOCAL", 
                    "name": "USER@TEST.LOCAL",
                    "distinguishedname": "CN=USER,DC=TEST,DC=LOCAL",
                    "enabled": True
                },
                "Aces": [],
                "SPNTargets": [],
                "HasSIDHistory": []
            }
            
            zip_path = os.path.join(debug_dir, "array_user.zip")
            with zipfile.ZipFile(zip_path, 'w') as zf:
                content = {
                    "users": [array_user],
                    "meta": {"count": 1, "type": "users", "version": 4}
                }
                zf.writestr(f"{timestamp}_users.json", json.dumps(content, separators=(',', ':')))
            test_files_created.append("array_user.zip")
            
            # Test 5: Without meta field
            zip_path = os.path.join(debug_dir, "no_meta.zip")
            with zipfile.ZipFile(zip_path, 'w') as zf:
                no_meta = {"users": [minimal_user]}
                zf.writestr(f"{timestamp}_users.json", json.dumps(no_meta, separators=(',', ':')))
            test_files_created.append("no_meta.zip")
            
            # Test 6: Real LDAP data (minimal)
            if self.ldap_conn.connection:
                # Get one actual user from LDAP
                entries = self.ldap_conn.search(size_limit=1)
                if entries:
                    # Find one user
                    for entry in entries:
                        attrs = entry.get('attributes', {})
                        classes = attrs.get('objectClass', [])
                        if isinstance(classes, str):
                            classes = [classes]
                        classes_lower = [c.lower() for c in classes]
                        sam = attrs.get('sAMAccountName', '')
                        
                        if 'user' in classes_lower and sam and not sam.endswith('$'):
                            # Use the real exporter but limit to one user
                            exporter = BloodhoundExporter()
                            real_user = exporter._create_user(entry, exporter._find_domain_name([entry]))
                            if real_user:
                                zip_path = os.path.join(debug_dir, "real_ldap_user.zip")
                                with zipfile.ZipFile(zip_path, 'w') as zf:
                                    content = {
                                        "users": [real_user],
                                        "meta": {"count": 1, "type": "users", "version": 4}
                                    }
                                    zf.writestr(f"{timestamp}_users.json", json.dumps(content, separators=(',', ':')))
                                test_files_created.append("real_ldap_user.zip")
                            break
            
            # Create instruction file
            instructions = """BLOODHOUND LEHACY DEBUG TEST INSTRUCTIONS
==================================================

Test files created in bloodhound_debug_tests folder.
Upload files in this order and note results:

1. EMPTY FILES (should work like OUs):
   - empty_users.zip
   - empty_computers.zip
   - empty_groups.zip
   - empty_domains.zip

2. MINIMAL OBJECTS:
   - minimal_user.zip (just domain and name)
   - basic_user.zip (adds distinguished name)
   - array_user.zip (adds empty arrays)
   - no_meta.zip (removes meta field)

3. REAL DATA:
   - real_ldap_user.zip (actual LDAP user data)

For each file, note:
- Does it hang at 0% or upload successfully?
- If successful, does it show 'no data in file'?
- Any error messages in Bloodhound?

This will help identify exactly what causes the 0% hang.
"""
            
            with open(os.path.join(debug_dir, "INSTRUCTIONS.txt"), 'w') as f:
                f.write(instructions)
            
            QMessageBox.information(
                self, 
                "Debug Tests Created", 
                f"Created {len(test_files_created)} test files in '{debug_dir}' folder.\n\n"
                f"Files created:\n" + "\n".join(f"- {f}" for f in test_files_created) + 
                f"\n\nSee INSTRUCTIONS.txt for testing order.\n\n"
                f"Test each file in Bloodhound and note which ones hang at 0% vs upload successfully."
            )
            
        except Exception as e:
            QMessageBox.critical(self, "Error Creating Tests", f"Failed to create debug tests:\n{str(e)}")


    def export_to_opengraph(self):
        """Export LDAP data to BloodHound OpenGraph format"""
        if not self.ldap_conn.connection:
            QMessageBox.warning(self, "Export Error", "Not connected to LDAP server")
            return
            
        # Ask about session data
        reply = QMessageBox.question(
            self, "OpenGraph Export Options",
            "Include session data in export?\n\n"
            "Session data adds temporal information but increases file size.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No | QMessageBox.StandardButton.Cancel
        )
        
        if reply == QMessageBox.StandardButton.Cancel:
            return
            
        include_session = reply == QMessageBox.StandardButton.Yes
        
        filename, _ = QFileDialog.getSaveFileName(
            self, "Export to OpenGraph Format",
            f"ldap_opengraph_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip",
            "ZIP Files (*.zip)"
        )
        
        if filename:
            progress = QProgressDialog("Exporting to OpenGraph format...", "Cancel", 0, 0, self)
            progress.setWindowModality(Qt.WindowModality.WindowModal)
            progress.show()
            
            try:
                # Get LDAP entries
                entries = self.ldap_conn.get_bloodhound_data()
                
                # Export using OpenGraph exporter
                from utilities.opengraph_exporter import OpenGraphExporter
                exporter = OpenGraphExporter()
                output_file = exporter.export_to_opengraph(entries, filename, include_session)
                
                progress.close()
                
                QMessageBox.information(
                    self, "Export Complete",
                    f"Successfully exported {len(entries)} LDAP objects to:\n{output_file}\n\n"
                    f"Format: BloodHound OpenGraph\n"
                    f"Session Data: {'Included' if include_session else 'Not included'}"
                )
                
                self.statusBar().showMessage(f"Export complete: {output_file}", 5000)
                
            except Exception as e:
                progress.close()
                QMessageBox.critical(self, "Export Error", f"Failed to export data:\n{str(e)}")
                
    def show_adcs_analysis(self):
        """Show ADCS Certificate Template Analysis dialog"""
        if not self.ldap_conn.connection:
            QMessageBox.warning(self, "ADCS Analysis", "Not connected to LDAP server")
            return
            
        from utilities.adcs_dialog import ADCSAnalysisDialog
        dialog = ADCSAnalysisDialog(self, self.ldap_conn)
        dialog.show()  # Non-modal
        
    def show_cache_settings(self):
        """Show dialog to configure query cache and throttle settings"""
        if not self.ldap_conn.connection:
            QMessageBox.warning(self, "Cache & Throttle Settings", "Not connected to LDAP server")
            return
            
        # Create dialog with tabs for cache and throttle settings
        dialog = QDialog(self)
        dialog.setWindowTitle("Cache & Throttle Settings")
        dialog.setModal(True)
        dialog.resize(500, 400)
        
        layout = QVBoxLayout()
        
        # Create tab widget
        tabs = QTabWidget()
        
        # Cache tab
        cache_tab = QWidget()
        cache_layout = QVBoxLayout()
        
        # Cache settings group
        cache_group = QGroupBox("Cache Configuration")
        cache_form = QFormLayout()
        
        # Cache TTL setting
        ttl_spin = QSpinBox()
        ttl_spin.setRange(60, 7200)  # up to 2 hours
        ttl_spin.setValue(self.ldap_conn._cache_ttl)
        ttl_spin.setSuffix(" seconds")
        cache_form.addRow("Cache TTL:", ttl_spin)
        
        # Cache size limit
        size_spin = QSpinBox()
        size_spin.setRange(1, 1000)  # up to 1GB
        size_spin.setValue(self.ldap_conn._cache_size_mb)
        size_spin.setSuffix(" MB")
        cache_form.addRow("Cache size limit:", size_spin)
        
        # Page size setting
        page_spin = QSpinBox()
        page_spin.setRange(100, 10000)
        page_spin.setValue(self.ldap_conn._page_size)
        page_spin.setSuffix(" entries")
        cache_form.addRow("Page size for searches:", page_spin)
        
        cache_group.setLayout(cache_form)
        cache_layout.addWidget(cache_group)
        
        # Cache statistics
        stats_group = QGroupBox("Cache Statistics")
        stats_layout = QFormLayout()
        
        # Get current stats
        cache_stats = self.ldap_conn.get_cache_stats()
        
        stats_layout.addRow("Cache hits:", QLabel(str(cache_stats['hits'])))
        stats_layout.addRow("Cache misses:", QLabel(str(cache_stats['misses'])))
        stats_layout.addRow("Hit rate:", QLabel(f"{cache_stats['hit_rate']}%"))
        stats_layout.addRow("Evictions:", QLabel(str(cache_stats['evictions'])))
        stats_layout.addRow("Current entries:", QLabel(str(cache_stats['cache_entries'])))
        stats_layout.addRow("Current size:", QLabel(f"{cache_stats['cache_size_mb']} MB"))
        
        stats_group.setLayout(stats_layout)
        cache_layout.addWidget(stats_group)
        
        # Clear cache button
        clear_btn = QPushButton("Clear Cache Now")
        clear_btn.clicked.connect(lambda: self._clear_cache_with_dialog(cache_stats['cache_entries']))
        cache_layout.addWidget(clear_btn)
        
        cache_layout.addStretch()
        cache_tab.setLayout(cache_layout)
        tabs.addTab(cache_tab, "Cache")
        
        # Throttle tab
        throttle_tab = QWidget()
        throttle_layout = QVBoxLayout()
        
        # Throttle settings group
        throttle_group = QGroupBox("Query Throttling")
        throttle_form = QFormLayout()
        
        # Enable throttling
        throttle_enabled = QCheckBox("Enable query throttling")
        throttle_enabled.setChecked(self.ldap_conn._throttle_enabled)
        throttle_form.addRow(throttle_enabled)
        
        # Queries per minute
        qpm_spin = QSpinBox()
        qpm_spin.setRange(1, 600)  # up to 10 queries/second
        qpm_spin.setValue(self.ldap_conn._queries_per_minute)
        qpm_spin.setSuffix(" queries/min")
        qpm_spin.setEnabled(throttle_enabled.isChecked())
        throttle_form.addRow("Maximum queries per minute:", qpm_spin)
        
        # Burst size
        burst_spin = QSpinBox()
        burst_spin.setRange(1, 20)
        burst_spin.setValue(self.ldap_conn._burst_size)
        burst_spin.setSuffix(" queries")
        burst_spin.setEnabled(throttle_enabled.isChecked())
        throttle_form.addRow("Burst size:", burst_spin)
        
        # Connect enable checkbox to spinboxes
        throttle_enabled.toggled.connect(qpm_spin.setEnabled)
        throttle_enabled.toggled.connect(burst_spin.setEnabled)
        
        throttle_group.setLayout(throttle_form)
        throttle_layout.addWidget(throttle_group)
        
        # Throttle info
        info_label = QLabel(
            "Query throttling helps avoid detection by limiting the rate of LDAP queries.\n"
            "This works alongside Throttling mode for maximum stealth.\n\n"
            "- Queries per minute: Maximum sustained query rate\n"
            "- Burst size: Number of queries allowed in quick succession"
        )
        info_label.setWordWrap(True)
        throttle_layout.addWidget(info_label)
        
        throttle_layout.addStretch()
        throttle_tab.setLayout(throttle_layout)
        tabs.addTab(throttle_tab, "Throttling")
        
        layout.addWidget(tabs)
        
        # Buttons
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(lambda: self._apply_cache_throttle_settings(
            dialog, ttl_spin.value(), size_spin.value(), page_spin.value(),
            throttle_enabled.isChecked(), qpm_spin.value(), burst_spin.value()
        ))
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        
        dialog.setLayout(layout)
        dialog.exec()
    
    def _apply_cache_throttle_settings(self, dialog, ttl, size_mb, page_size, 
                                      throttle_enabled, qpm, burst):
        """Apply cache and throttle settings"""
        # Apply cache settings
        self.ldap_conn.set_cache_settings(size_mb, ttl)
        self.ldap_conn._page_size = page_size
        
        # Apply throttle settings
        self.ldap_conn.set_throttle_settings(throttle_enabled, qpm, burst)
        
        dialog.accept()
        QMessageBox.information(self, "Settings Updated", 
                              "Cache and throttle settings updated successfully")
    
    def _clear_cache_with_dialog(self, cache_size):
        """Clear cache with confirmation"""
        reply = QMessageBox.question(
            self, 
            "Clear Cache", 
            f"Clear {cache_size} cached entries?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            self.ldap_conn.clear_cache()
            QMessageBox.information(self, "Cache Cleared", 
                                  f"Cleared {cache_size} cached queries")
    
    def clear_query_cache(self):
        """Clear the LDAP query cache"""
        if not self.ldap_conn.connection:
            QMessageBox.warning(self, "Clear Cache", "Not connected to LDAP server")
            return
            
        cache_size = len(self.ldap_conn._cache)
        self.ldap_conn.clear_cache()
        QMessageBox.information(self, "Cache Cleared", f"Cleared {cache_size} cached queries")
    
    def show_debug_console(self):
        """Show the LDAP query debug console"""
        dialog = DebugDialog(self, self.ldap_conn)
        dialog.exec()
    
    def toggle_Throttling_mode(self, checked):
        """Toggle Throttling mode on/off - affects query randomisation"""
        if self.ldap_conn:
            self.ldap_conn.set_Throttling_mode(checked)
            status = "enabled" if checked else "disabled"
            self.statusBar().showMessage(f"Throttling mode {status}", 5000)
            
            # quick reminder of what this does
            if checked:
                QMessageBox.information(
                    self,
                    "Throttling Mode Enabled",
                    "LDAP queries will now execute in random order with delays.\n\n"
                    "This makes enumeration harder to detect but slower.\n"
                    "Adjust timing in Throttling → Throttling Settings."
                )
    
    def show_Throttling_settings(self):
        """Show Throttling configuration dialog"""
        if not self.ldap_conn:
            QMessageBox.warning(self, "Not Connected", 
                              "Connect to an LDAP server first to configure Throttling settings.")
            return
            
        dialog = QDialog(self)
        dialog.setWindowTitle("Throttling Settings")
        dialog.setModal(True)
        
        layout = QFormLayout()
        
        # current settings
        min_delay = getattr(self.ldap_conn, '_min_query_delay', 0.5)
        max_delay = getattr(self.ldap_conn, '_max_query_delay', 2.0)
        
        # delay spinboxes
        min_spin = QSpinBox()
        min_spin.setRange(100, 10000)  # milliseconds
        min_spin.setSuffix(" ms")
        min_spin.setValue(int(min_delay * 1000))
        
        max_spin = QSpinBox()
        max_spin.setRange(100, 30000)  # up to 30 seconds
        max_spin.setSuffix(" ms")
        max_spin.setValue(int(max_delay * 1000))
        
        layout.addRow("Minimum delay:", min_spin)
        layout.addRow("Maximum delay:", max_spin)
        
        # presets
        preset_combo = QComboBox()
        preset_combo.addItems(["Custom", "Fast (0.5-2s)", "Normal (1-5s)", "Stealthy (3-10s)"])
        preset_combo.currentTextChanged.connect(lambda text: self._apply_Throttling_preset(text, min_spin, max_spin))
        layout.addRow("Presets:", preset_combo)
        
        # buttons
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | 
                                  QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        
        dialog.setLayout(layout)
        
        if dialog.exec() == QDialog.DialogCode.Accepted:
            # apply new settings
            min_ms = min_spin.value()
            max_ms = max_spin.value()
            
            if max_ms < min_ms:
                max_ms = min_ms
                
            self.ldap_conn.set_Throttling_mode(
                self.Throttling_toggle_action.isChecked(),
                min_ms / 1000.0,
                max_ms / 1000.0
            )
            
            self.statusBar().showMessage(
                f"Throttling timing updated: {min_ms}-{max_ms}ms between queries", 
                5000
            )
    
    def _apply_Throttling_preset(self, preset, min_spin, max_spin):
        """Apply Throttling timing presets"""
        if preset == "Fast (0.5-2s)":
            min_spin.setValue(500)
            max_spin.setValue(2000)
        elif preset == "Normal (1-5s)":
            min_spin.setValue(1000)
            max_spin.setValue(5000)
        elif preset == "Stealthy (3-10s)":
            min_spin.setValue(3000)
            max_spin.setValue(10000)
        # Custom does nothing
    
    def _set_app_icon(self):
        """Set application icon from image.png"""
        import os
        import sys
        
        # Try different icon file options
        icon_files = ['assets/pyldap_gui.ico', 'assets/image.png', 'assets/pyldap_gui.png']
        
        for icon_file in icon_files:
            if os.path.exists(icon_file):
                icon = QIcon(icon_file)
                self.setWindowIcon(icon)
                
                # Also set for the application (shows in dock/taskbar)
                if hasattr(QApplication, 'instance') and QApplication.instance():
                    QApplication.instance().setWindowIcon(icon)
                break


class ProfileManagerDialog(QDialog):
    def __init__(self, parent=None, profile_manager=None):
        super().__init__(parent)
        self.profile_manager = profile_manager
        self.setWindowTitle("Manage Connection Profiles")
        self.setModal(True)
        self.resize(400, 300)
        
        layout = QVBoxLayout()
        
        # Profile list
        self.profile_list = QListWidget()
        self.update_profile_list()
        layout.addWidget(self.profile_list)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        delete_button = QPushButton("Delete")
        delete_button.clicked.connect(self.delete_profile)
        button_layout.addWidget(delete_button)
        
        button_layout.addStretch()
        
        close_button = QPushButton("Close")
        close_button.clicked.connect(self.accept)
        button_layout.addWidget(close_button)
        
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
        
    def update_profile_list(self):
        self.profile_list.clear()
        if self.profile_manager:
            for profile in self.profile_manager.list_profiles():
                self.profile_list.addItem(profile)
                
    def delete_profile(self):
        current_item = self.profile_list.currentItem()
        if current_item:
            profile_name = current_item.text()
            reply = QMessageBox.question(
                self,
                "Delete Profile",
                f"Are you sure you want to delete the profile '{profile_name}'?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                self.profile_manager.delete_profile(profile_name)
                self.update_profile_list()


def main():
    app = QApplication(sys.argv)
    browser = LDAPBrowser()
    browser.show()
    sys.exit(app.exec())


if __name__ == '__main__':
    main()