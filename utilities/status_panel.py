"""
Status panel widget for pyLDAPGui
Shows connection status, statistics, and quick actions
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
    QPushButton, QGroupBox, QGridLayout, QProgressBar
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QFont, QPalette, QColor


class StatusPanel(QWidget):
    """Status panel showing connection info and statistics"""
    
    refresh_requested = pyqtSignal()
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        
        # Timer for auto-refresh
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self.refresh_requested.emit)
        
    def setup_ui(self):
        """Setup the status panel UI"""
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Connection Status Group
        conn_group = QGroupBox("Connection Status")
        conn_layout = QGridLayout()
        
        # Status indicator
        self.status_indicator = QLabel("*")
        self.status_indicator.setStyleSheet("color: red; font-size: 16px;")
        conn_layout.addWidget(self.status_indicator, 0, 0)
        
        self.status_label = QLabel("Disconnected")
        font = QFont()
        font.setBold(True)
        self.status_label.setFont(font)
        conn_layout.addWidget(self.status_label, 0, 1)
        
        # Server info
        self.server_label = QLabel("Server: Not connected")
        conn_layout.addWidget(self.server_label, 1, 0, 1, 2)
        
        self.user_label = QLabel("User: Not connected")
        conn_layout.addWidget(self.user_label, 2, 0, 1, 2)
        
        self.base_dn_label = QLabel("Base DN: Not connected")
        self.base_dn_label.setWordWrap(True)
        conn_layout.addWidget(self.base_dn_label, 3, 0, 1, 2)
        
        conn_group.setLayout(conn_layout)
        layout.addWidget(conn_group)
        
        # Statistics Group
        stats_group = QGroupBox("Statistics")
        stats_layout = QGridLayout()
        
        # Entry counts
        stats_layout.addWidget(QLabel("Total Entries:"), 0, 0)
        self.total_entries_label = QLabel("0")
        stats_layout.addWidget(self.total_entries_label, 0, 1)
        
        stats_layout.addWidget(QLabel("Users:"), 1, 0)
        self.users_label = QLabel("0")
        stats_layout.addWidget(self.users_label, 1, 1)
        
        stats_layout.addWidget(QLabel("Computers:"), 2, 0)
        self.computers_label = QLabel("0")
        stats_layout.addWidget(self.computers_label, 2, 1)
        
        stats_layout.addWidget(QLabel("Groups:"), 3, 0)
        self.groups_label = QLabel("0")
        stats_layout.addWidget(self.groups_label, 3, 1)
        
        # Cache stats
        stats_layout.addWidget(QLabel("Cache Hit Rate:"), 4, 0)
        self.cache_rate_label = QLabel("0%")
        stats_layout.addWidget(self.cache_rate_label, 4, 1)
        
        stats_layout.addWidget(QLabel("Queries/min:"), 5, 0)
        self.query_rate_label = QLabel("0")
        stats_layout.addWidget(self.query_rate_label, 5, 1)
        
        stats_group.setLayout(stats_layout)
        layout.addWidget(stats_group)
        
        # OpSec Status Group
        opsec_group = QGroupBox("OpSec Status")
        opsec_layout = QVBoxLayout()
        
        self.opsec_status_label = QLabel("OpSec: Enabled")
        self.opsec_status_label.setStyleSheet("color: green; font-weight: bold;")
        opsec_layout.addWidget(self.opsec_status_label)
        
        self.throttle_status_label = QLabel("Throttle: 30 queries/min")
        opsec_layout.addWidget(self.throttle_status_label)
        
        self.delay_status_label = QLabel("Delay: 0.5-2.0s")
        opsec_layout.addWidget(self.delay_status_label)
        
        opsec_group.setLayout(opsec_layout)
        layout.addWidget(opsec_group)
        
        # Quick Actions
        actions_group = QGroupBox("Quick Actions")
        actions_layout = QVBoxLayout()
        
        self.refresh_btn = QPushButton("Refresh Statistics")
        self.refresh_btn.clicked.connect(self.refresh_requested.emit)
        actions_layout.addWidget(self.refresh_btn)
        
        self.auto_refresh_btn = QPushButton("Auto-Refresh: Off")
        self.auto_refresh_btn.setCheckable(True)
        self.auto_refresh_btn.toggled.connect(self.toggle_auto_refresh)
        actions_layout.addWidget(self.auto_refresh_btn)
        
        actions_group.setLayout(actions_layout)
        layout.addWidget(actions_group)
        
        # Add stretch to push everything to top
        layout.addStretch()
        
        self.setLayout(layout)
        
    def update_connection_status(self, connected, server=None, user=None, base_dn=None):
        """Update connection status display"""
        if connected:
            self.status_indicator.setStyleSheet("color: green; font-size: 16px;")
            self.status_label.setText("Connected")
            self.server_label.setText(f"Server: {server or 'Unknown'}")
            self.user_label.setText(f"User: {user or 'Unknown'}")
            self.base_dn_label.setText(f"Base DN: {base_dn or 'Unknown'}")
        else:
            self.status_indicator.setStyleSheet("color: red; font-size: 16px;")
            self.status_label.setText("Disconnected")
            self.server_label.setText("Server: Not connected")
            self.user_label.setText("User: Not connected")
            self.base_dn_label.setText("Base DN: Not connected")
    
    def update_statistics(self, stats):
        """Update statistics display"""
        self.total_entries_label.setText(str(stats.get('total_entries', 0)))
        self.users_label.setText(str(stats.get('users', 0)))
        self.computers_label.setText(str(stats.get('computers', 0)))
        self.groups_label.setText(str(stats.get('groups', 0)))
        
        # Cache stats
        cache_stats = stats.get('cache_stats', {})
        hit_rate = cache_stats.get('hit_rate', 0)
        self.cache_rate_label.setText(f"{hit_rate}%")
        
        # Color code cache hit rate
        if hit_rate >= 80:
            self.cache_rate_label.setStyleSheet("color: green;")
        elif hit_rate >= 50:
            self.cache_rate_label.setStyleSheet("color: orange;")
        else:
            self.cache_rate_label.setStyleSheet("color: red;")
        
        # Query rate
        query_rate = stats.get('query_rate', 0)
        self.query_rate_label.setText(str(query_rate))
    
    def update_opsec_status(self, opsec_enabled, throttle_enabled, qpm, min_delay, max_delay):
        """Update OpSec status display"""
        if opsec_enabled:
            self.opsec_status_label.setText("OpSec: Enabled")
            self.opsec_status_label.setStyleSheet("color: green; font-weight: bold;")
        else:
            self.opsec_status_label.setText("OpSec: Disabled")
            self.opsec_status_label.setStyleSheet("color: red; font-weight: bold;")
        
        if throttle_enabled:
            self.throttle_status_label.setText(f"Throttle: {qpm} queries/min")
        else:
            self.throttle_status_label.setText("Throttle: Disabled")
        
        self.delay_status_label.setText(f"Delay: {min_delay}-{max_delay}s")
    
    def toggle_auto_refresh(self, checked):
        """Toggle auto-refresh timer"""
        if checked:
            self.auto_refresh_btn.setText("Auto-Refresh: On")
            self.refresh_timer.start(5000)  # Refresh every 5 seconds
        else:
            self.auto_refresh_btn.setText("Auto-Refresh: Off")
            self.refresh_timer.stop()