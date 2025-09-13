"""
Utilities Package for pyLDAPGui

~ Description : Contains all helper modules and dialogs for the application.
                Modules are organized by functionality into consolidated files
                following PEP8 standards.

@ Module Organization:
  - ldap_connection   : Core LDAP connectivity and operations
  - profiles          : Connection profile management
  - exporters         : Data export functionality (CSV, Bloodhound, Neo4j)
  - ui_dialogs        : All UI dialog windows
  - ldap_obfuscator   : Query obfuscation engine
  - trust_analyser    : Domain trust analysis
  - status_panel      : Status display widget
  - query_history     : Query history tracking widget

@ Author: ZephrFish
@ License: MIT
"""

# Core modules
from .ldap_connection import LDAPConnection
from .profiles import ProfileManager

# Exporters
from .exporters import BloodhoundExporter, CSVExporter, Neo4jConnector
from .opengraph_exporter import OpenGraphExporter

# UI Dialogs
from .ui_dialogs import (
    SearchDialog,
    TrustBrowserDialog,
    ObfuscationDialog,
    Neo4jConnectionDialog,
    DebugDialog
)
from .adcs_dialog import ADCSAnalysisDialog

# Analysis modules  
from .ldap_obfuscator import LDAPObfuscator
from .trust_analyser import TrustAnalyser
from .adcs_analyzer import ADCSAnalyzer

# UI Widgets
from .status_panel import StatusPanel
from .query_history import QueryHistoryWidget

__all__ = [
    # Core
    'LDAPConnection',
    'ProfileManager',
    
    # Exporters
    'BloodhoundExporter',
    'OpenGraphExporter',
    'CSVExporter',
    'Neo4jConnector',
    
    # Dialogs
    'SearchDialog',
    'TrustBrowserDialog',
    'ObfuscationDialog',
    'Neo4jConnectionDialog',
    'DebugDialog',
    'ADCSAnalysisDialog',
    
    # Analysis
    'LDAPObfuscator',
    'TrustAnalyser',
    'ADCSAnalyzer',
    
    # Widgets
    'StatusPanel',
    'QueryHistoryWidget'
]