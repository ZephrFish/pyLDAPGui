"""
Query history widget for pyLDAPGui
Shows recent LDAP queries with timing and cache information
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem,
    QHeaderView, QPushButton, QHBoxLayout, QLabel, QComboBox
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QColor
from datetime import datetime


class QueryHistoryWidget(QWidget):
    """Widget showing recent LDAP query history"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.queries = []
        self.max_queries = 100
        
    def setup_ui(self):
        """Setup the query history UI"""
        layout = QVBoxLayout()
        
        # Header with controls
        header_layout = QHBoxLayout()
        
        header_label = QLabel("Recent Queries")
        header_label.setStyleSheet("font-weight: bold; font-size: 14px;")
        header_layout.addWidget(header_label)
        
        header_layout.addStretch()
        
        # Filter by type
        self.type_filter = QComboBox()
        self.type_filter.addItems(["All", "Search", "Batch", "Export"])
        self.type_filter.currentTextChanged.connect(self.apply_filter)
        header_layout.addWidget(QLabel("Filter:"))
        header_layout.addWidget(self.type_filter)
        
        # Clear button
        clear_btn = QPushButton("Clear History")
        clear_btn.clicked.connect(self.clear_history)
        header_layout.addWidget(clear_btn)
        
        layout.addLayout(header_layout)
        
        # Query table
        self.query_table = QTableWidget()
        self.query_table.setColumnCount(6)
        self.query_table.setHorizontalHeaderLabels([
            "Time", "Type", "Filter/Query", "Results", "Duration", "Cache"
        ])
        
        # Set column widths
        header = self.query_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        
        # Make read-only
        self.query_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        
        # Alternating row colors
        self.query_table.setAlternatingRowColors(True)
        
        layout.addWidget(self.query_table)
        
        # Summary stats
        stats_layout = QHBoxLayout()
        
        self.total_label = QLabel("Total: 0")
        stats_layout.addWidget(self.total_label)
        
        stats_layout.addWidget(QLabel("|"))
        
        self.cache_hits_label = QLabel("Cache Hits: 0")
        stats_layout.addWidget(self.cache_hits_label)
        
        stats_layout.addWidget(QLabel("|"))
        
        self.avg_duration_label = QLabel("Avg Duration: 0ms")
        stats_layout.addWidget(self.avg_duration_label)
        
        stats_layout.addStretch()
        
        layout.addLayout(stats_layout)
        
        self.setLayout(layout)
    
    def add_query(self, query_info):
        """Add a query to the history"""
        # Add to beginning of list
        self.queries.insert(0, query_info)
        
        # Limit size
        if len(self.queries) > self.max_queries:
            self.queries = self.queries[:self.max_queries]
        
        # Update display
        self.update_display()
    
    def update_display(self):
        """Update the query table display"""
        # Get current filter
        filter_type = self.type_filter.currentText()
        
        # Filter queries
        if filter_type == "All":
            filtered_queries = self.queries
        else:
            filtered_queries = [q for q in self.queries if q.get('type', '').lower() == filter_type.lower()]
        
        # Update table
        self.query_table.setRowCount(len(filtered_queries))
        
        for row, query in enumerate(filtered_queries):
            # Time
            timestamp = query.get('timestamp', '')
            if isinstance(timestamp, str):
                try:
                    dt = datetime.fromisoformat(timestamp)
                    time_str = dt.strftime("%H:%M:%S")
                except:
                    time_str = timestamp
            else:
                time_str = str(timestamp)
            
            time_item = QTableWidgetItem(time_str)
            self.query_table.setItem(row, 0, time_item)
            
            # Type
            query_type = query.get('type', 'unknown')
            type_item = QTableWidgetItem(query_type)
            self.query_table.setItem(row, 1, type_item)
            
            # Filter/Query
            params = query.get('params', {})
            filter_str = params.get('filter', params.get('query', 'N/A'))
            if len(filter_str) > 50:
                filter_str = filter_str[:47] + "..."
            filter_item = QTableWidgetItem(filter_str)
            filter_item.setToolTip(params.get('filter', params.get('query', 'N/A')))
            self.query_table.setItem(row, 2, filter_item)
            
            # Results
            result_count = query.get('result_count', 0)
            results_item = QTableWidgetItem(str(result_count))
            self.query_table.setItem(row, 3, results_item)
            
            # Duration
            duration = query.get('duration_ms', 0)
            duration_item = QTableWidgetItem(f"{duration}ms")
            
            # Color code duration
            if duration > 1000:
                duration_item.setForeground(QColor(255, 0, 0))  # Red for slow
            elif duration > 500:
                duration_item.setForeground(QColor(255, 165, 0))  # Orange for medium
            else:
                duration_item.setForeground(QColor(0, 128, 0))  # Green for fast
            
            self.query_table.setItem(row, 4, duration_item)
            
            # Cache
            cache_hit = query.get('cache_hit', False)
            cache_item = QTableWidgetItem("HIT" if cache_hit else "MISS")
            
            if cache_hit:
                cache_item.setForeground(QColor(0, 128, 0))  # Green
                cache_item.setBackground(QColor(0, 128, 0, 30))  # Light green bg
            else:
                cache_item.setForeground(QColor(128, 128, 128))  # Gray
            
            self.query_table.setItem(row, 5, cache_item)
        
        # Update stats
        self.update_stats()
    
    def update_stats(self):
        """Update summary statistics"""
        total = len(self.queries)
        cache_hits = sum(1 for q in self.queries if q.get('cache_hit', False))
        
        if total > 0:
            avg_duration = sum(q.get('duration_ms', 0) for q in self.queries) / total
        else:
            avg_duration = 0
        
        self.total_label.setText(f"Total: {total}")
        self.cache_hits_label.setText(f"Cache Hits: {cache_hits}")
        self.avg_duration_label.setText(f"Avg Duration: {avg_duration:.1f}ms")
    
    def apply_filter(self):
        """Apply the selected filter"""
        self.update_display()
    
    def clear_history(self):
        """Clear the query history"""
        self.queries.clear()
        self.update_display()
    
    def load_from_connection(self, ldap_conn):
        """Load query history from LDAP connection"""
        if ldap_conn and hasattr(ldap_conn, 'get_query_log'):
            self.queries = ldap_conn.get_query_log()
            self.update_display()