#!/usr/bin/env python3
"""
ADCS Analysis Dialog for pyLDAPGui

~ Description : Dialog window for Active Directory Certificate Services
                vulnerability analysis and reporting

@ Author: ZephrFish
@ License: MIT
"""

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTextEdit, QTableWidget, QTableWidgetItem, QGroupBox,
    QHeaderView, QSplitter, QListWidget, QListWidgetItem,
    QProgressDialog, QMessageBox, QFileDialog, QTabWidget,
    QWidget, QComboBox
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont

from .adcs_analyzer import ADCSAnalyzer, CertificateVulnerability


class ADCSAnalysisThread(QThread):
    """Thread for running ADCS analysis"""
    
    progress_updated = pyqtSignal(int, str)
    analysis_complete = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)
    
    def __init__(self, ldap_connection):
        super().__init__()
        self.ldap_conn = ldap_connection
        
    def run(self):
        """Run ADCS analysis"""
        try:
            self.progress_updated.emit(0, "Initializing ADCS analyzer...")
            analyzer = ADCSAnalyzer(self.ldap_conn)
            
            self.progress_updated.emit(20, "Enumerating certificate templates...")
            
            # Perform analysis
            results = analyzer.analyze_environment()
            
            self.progress_updated.emit(100, "Analysis complete")
            self.analysis_complete.emit(results)
            
        except Exception as e:
            self.error_occurred.emit(str(e))


class ADCSAnalysisDialog(QDialog):
    """
    ADCS Certificate Template Analysis Dialog
    
    ~ Description : Provides interface for analyzing Active Directory
                    Certificate Services for security vulnerabilities
    """
    
    def __init__(self, parent=None, ldap_connection=None):
        """
        Initialize ADCS analysis dialog
        
        @ Args:
            parent         : Parent widget
            ldap_connection: Active LDAP connection
        """
        super().__init__(parent)
        self.ldap_conn = ldap_connection
        self.analysis_results = None
        
        self.setWindowTitle("ADCS Certificate Template Analysis")
        self.setModal(False)
        self.resize(1000, 700)
        
        self._init_ui()
        
    def _init_ui(self):
        """Initialize user interface"""
        layout = QVBoxLayout()
        
        # Header
        header_layout = QHBoxLayout()
        header_label = QLabel("Active Directory Certificate Services Security Analysis")
        header_label.setStyleSheet("font-size: 16px; font-weight: bold;")
        header_layout.addWidget(header_label)
        
        header_layout.addStretch()
        
        # Analyze button
        self.analyze_btn = QPushButton("Run Analysis")
        self.analyze_btn.clicked.connect(self._run_analysis)
        header_layout.addWidget(self.analyze_btn)
        
        layout.addLayout(header_layout)
        
        # Info text
        info_label = QLabel(
            "This tool analyzes certificate templates for common vulnerabilities "
            "including ESC1-ESC8 attack paths. Run the analysis to identify "
            "misconfigurations that could lead to privilege escalation."
        )
        info_label.setWordWrap(True)
        layout.addWidget(info_label)
        
        # Tab widget for results
        self.tab_widget = QTabWidget()
        
        # Summary tab
        self.summary_widget = self._create_summary_tab()
        self.tab_widget.addTab(self.summary_widget, "Summary")
        
        # Templates tab
        self.templates_widget = self._create_templates_tab()
        self.tab_widget.addTab(self.templates_widget, "Certificate Templates")
        
        # Vulnerabilities tab
        self.vulns_widget = self._create_vulnerabilities_tab()
        self.tab_widget.addTab(self.vulns_widget, "Vulnerabilities")
        
        # Recommendations tab
        self.recommendations_widget = self._create_recommendations_tab()
        self.tab_widget.addTab(self.recommendations_widget, "Recommendations")
        
        layout.addWidget(self.tab_widget)
        
        # Export buttons
        export_layout = QHBoxLayout()
        
        export_json_btn = QPushButton("Export JSON")
        export_json_btn.clicked.connect(lambda: self._export_results('json'))
        export_layout.addWidget(export_json_btn)
        
        export_csv_btn = QPushButton("Export CSV")
        export_csv_btn.clicked.connect(lambda: self._export_results('csv'))
        export_layout.addWidget(export_csv_btn)
        
        export_bh_btn = QPushButton("Export to BloodHound")
        export_bh_btn.clicked.connect(lambda: self._export_results('bloodhound'))
        export_layout.addWidget(export_bh_btn)
        
        export_layout.addStretch()
        
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        export_layout.addWidget(close_btn)
        
        layout.addLayout(export_layout)
        self.setLayout(layout)
        
    def _create_summary_tab(self) -> QWidget:
        """Create summary tab widget"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        self.summary_text = QTextEdit()
        self.summary_text.setReadOnly(True)
        layout.addWidget(self.summary_text)
        
        widget.setLayout(layout)
        return widget
        
    def _create_templates_tab(self) -> QWidget:
        """Create certificate templates tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Templates table
        self.templates_table = QTableWidget()
        self.templates_table.setColumnCount(5)
        self.templates_table.setHorizontalHeaderLabels([
            "Template Name", "Risk Score", "Enrollment Rights", 
            "Vulnerabilities", "Status"
        ])
        self.templates_table.horizontalHeader().setStretchLastSection(True)
        self.templates_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self.templates_table.itemSelectionChanged.connect(
            self._on_template_selected
        )
        
        layout.addWidget(self.templates_table)
        
        # Template details
        self.template_details = QTextEdit()
        self.template_details.setReadOnly(True)
        self.template_details.setMaximumHeight(200)
        layout.addWidget(self.template_details)
        
        widget.setLayout(layout)
        return widget
        
    def _create_vulnerabilities_tab(self) -> QWidget:
        """Create vulnerabilities tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Vulnerability filter
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Severity:"))
        
        self.severity_filter = QComboBox()
        self.severity_filter.addItems(["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
        self.severity_filter.currentTextChanged.connect(self._filter_vulnerabilities)
        filter_layout.addWidget(self.severity_filter)
        
        filter_layout.addStretch()
        layout.addLayout(filter_layout)
        
        # Vulnerabilities table
        self.vulns_table = QTableWidget()
        self.vulns_table.setColumnCount(4)
        self.vulns_table.setHorizontalHeaderLabels([
            "Type", "Severity", "Affected Template/CA", "Description"
        ])
        self.vulns_table.horizontalHeader().setStretchLastSection(True)
        self.vulns_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self.vulns_table.itemSelectionChanged.connect(
            self._on_vulnerability_selected
        )
        
        layout.addWidget(self.vulns_table)
        
        # Vulnerability details
        self.vuln_details = QTextEdit()
        self.vuln_details.setReadOnly(True)
        self.vuln_details.setMaximumHeight(200)
        layout.addWidget(self.vuln_details)
        
        widget.setLayout(layout)
        return widget
        
    def _create_recommendations_tab(self) -> QWidget:
        """Create recommendations tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        self.recommendations_text = QTextEdit()
        self.recommendations_text.setReadOnly(True)
        layout.addWidget(self.recommendations_text)
        
        widget.setLayout(layout)
        return widget
        
    def _run_analysis(self):
        """Run ADCS security analysis"""
        if not self.ldap_conn or not self.ldap_conn.connection:
            QMessageBox.warning(
                self, "No Connection",
                "Please connect to an LDAP server first."
            )
            return
            
        # Disable button
        self.analyze_btn.setEnabled(False)
        
        # Create progress dialog
        progress = QProgressDialog(
            "Running ADCS analysis...", "Cancel", 0, 100, self
        )
        progress.setWindowModality(Qt.WindowModality.WindowModal)
        
        # Create and start analysis thread
        self.analysis_thread = ADCSAnalysisThread(self.ldap_conn)
        self.analysis_thread.progress_updated.connect(
            lambda val, msg: progress.setValue(val) or progress.setLabelText(msg)
        )
        self.analysis_thread.analysis_complete.connect(
            lambda results: self._on_analysis_complete(results, progress)
        )
        self.analysis_thread.error_occurred.connect(
            lambda err: self._on_analysis_error(err, progress)
        )
        
        progress.canceled.connect(self.analysis_thread.terminate)
        self.analysis_thread.start()
        
    def _on_analysis_complete(self, results: dict, progress: QProgressDialog):
        """Handle analysis completion"""
        progress.close()
        self.analyze_btn.setEnabled(True)
        self.analysis_results = results
        
        # Update UI with results
        self._update_summary(results)
        self._update_templates(results)
        self._update_vulnerabilities(results)
        self._update_recommendations(results)
        
        # Show notification
        stats = results.get('statistics', {})
        QMessageBox.information(
            self, "Analysis Complete",
            f"Found {stats.get('total_vulnerabilities', 0)} vulnerabilities "
            f"across {stats.get('total_templates', 0)} certificate templates."
        )
        
    def _on_analysis_error(self, error: str, progress: QProgressDialog):
        """Handle analysis error"""
        progress.close()
        self.analyze_btn.setEnabled(True)
        
        QMessageBox.critical(
            self, "Analysis Error",
            f"An error occurred during analysis:\n{error}"
        )
        
    def _update_summary(self, results: dict):
        """Update summary tab"""
        summary = []
        
        summary.append("ADCS Security Analysis Summary")
        summary.append("=" * 50)
        summary.append("")
        
        # Statistics
        stats = results.get('statistics', {})
        summary.append("Statistics:")
        summary.append(f"- Total Certificate Templates: {stats.get('total_templates', 0)}")
        summary.append(f"- Enabled Templates: {stats.get('enabled_templates', 0)}")
        summary.append(f"- Vulnerable Templates: {stats.get('vulnerable_templates', 0)}")
        summary.append(f"- Total Certificate Authorities: {stats.get('total_cas', 0)}")
        summary.append("")
        
        summary.append("Vulnerability Summary:")
        summary.append(f"- Total Vulnerabilities: {stats.get('total_vulnerabilities', 0)}")
        summary.append(f"- Critical: {stats.get('critical_vulnerabilities', 0)}")
        summary.append(f"- High: {stats.get('high_vulnerabilities', 0)}")
        summary.append(f"- Medium: {stats.get('medium_vulnerabilities', 0)}")
        summary.append(f"- High Risk Templates: {stats.get('high_risk_templates', 0)}")
        summary.append("")
        
        # Top risks
        summary.append("Top Security Risks:")
        vulns = results.get('vulnerabilities', [])
        critical_vulns = [v for v in vulns if v.get('severity') == 'CRITICAL']
        
        for i, vuln in enumerate(critical_vulns[:5], 1):
            vuln_type = vuln.get('type')
            if hasattr(vuln_type, 'name'):
                summary.append(f"{i}. {vuln_type.name}: {vuln.get('description', '')}")
            else:
                summary.append(f"{i}. {vuln.get('description', '')}")
                
        self.summary_text.setText('\n'.join(summary))
        
    def _update_templates(self, results: dict):
        """Update templates tab"""
        templates = results.get('certificate_templates', [])
        self.templates_table.setRowCount(len(templates))
        
        for row, template in enumerate(templates):
            # Template name
            self.templates_table.setItem(
                row, 0, QTableWidgetItem(template.get('display_name', ''))
            )
            
            # Risk score
            risk_score = template.get('risk_score', 0)
            risk_item = QTableWidgetItem(str(risk_score))
            if risk_score >= 70:
                risk_item.setBackground(Qt.GlobalColor.red)
                risk_item.setForeground(Qt.GlobalColor.white)
            elif risk_score >= 40:
                risk_item.setBackground(Qt.GlobalColor.yellow)
            self.templates_table.setItem(row, 1, risk_item)
            
            # Enrollment rights
            enrollment = "Domain Users" if self._check_domain_user_enrollment(template) else "Restricted"
            self.templates_table.setItem(row, 2, QTableWidgetItem(enrollment))
            
            # Vulnerabilities
            vuln_count = len(template.get('vulnerabilities', []))
            self.templates_table.setItem(row, 3, QTableWidgetItem(str(vuln_count)))
            
            # Status
            status = "Enabled" if template.get('enabled', False) else "Disabled"
            self.templates_table.setItem(row, 4, QTableWidgetItem(status))
            
    def _update_vulnerabilities(self, results: dict):
        """Update vulnerabilities tab"""
        self.all_vulns = results.get('vulnerabilities', [])
        self._display_vulnerabilities(self.all_vulns)
        
    def _display_vulnerabilities(self, vulns: list):
        """Display vulnerabilities in table"""
        self.vulns_table.setRowCount(len(vulns))
        
        for row, vuln in enumerate(vulns):
            # Type
            vuln_type = vuln.get('type')
            if hasattr(vuln_type, 'name'):
                type_text = vuln_type.name
            else:
                type_text = str(vuln_type)
            self.vulns_table.setItem(row, 0, QTableWidgetItem(type_text))
            
            # Severity
            severity = vuln.get('severity', '')
            sev_item = QTableWidgetItem(severity)
            if severity == 'CRITICAL':
                sev_item.setBackground(Qt.GlobalColor.red)
                sev_item.setForeground(Qt.GlobalColor.white)
            elif severity == 'HIGH':
                sev_item.setBackground(Qt.GlobalColor.darkRed)
                sev_item.setForeground(Qt.GlobalColor.white)
            elif severity == 'MEDIUM':
                sev_item.setBackground(Qt.GlobalColor.yellow)
            self.vulns_table.setItem(row, 1, sev_item)
            
            # Affected
            affected = vuln.get('ca', '')
            if not affected:
                # Find affected template
                for template in self.analysis_results.get('certificate_templates', []):
                    if vuln in template.get('vulnerabilities', []):
                        affected = template.get('display_name', '')
                        break
            self.vulns_table.setItem(row, 2, QTableWidgetItem(affected))
            
            # Description
            self.vulns_table.setItem(
                row, 3, QTableWidgetItem(vuln.get('description', ''))
            )
            
    def _update_recommendations(self, results: dict):
        """Update recommendations tab"""
        recommendations = results.get('recommendations', [])
        
        text = ["Security Recommendations", "=" * 50, ""]
        
        for i, rec in enumerate(recommendations, 1):
            text.append(f"{i}. {rec}")
            text.append("")
            
        self.recommendations_text.setText('\n'.join(text))
        
    def _on_template_selected(self):
        """Handle template selection"""
        current_row = self.templates_table.currentRow()
        if current_row < 0 or not self.analysis_results:
            return
            
        templates = self.analysis_results.get('certificate_templates', [])
        if current_row < len(templates):
            template = templates[current_row]
            self._show_template_details(template)
            
    def _show_template_details(self, template: dict):
        """Show detailed template information"""
        details = []
        details.append(f"Template: {template.get('display_name', '')}")
        details.append(f"DN: {template.get('dn', '')}")
        details.append(f"Risk Score: {template.get('risk_score', 0)}")
        details.append("")
        
        details.append("Properties:")
        details.append(f"- Schema Version: {template.get('schema_version', 1)}")
        details.append(f"- Enrollment Flag: 0x{template.get('enrollment_flag', 0):X}")
        details.append(f"- Name Flag: 0x{template.get('name_flag', 0):X}")
        details.append(f"- Required Signatures: {template.get('authorized_signatures', 0)}")
        details.append("")
        
        details.append("Extended Key Usage:")
        ekus = template.get('eku_names', [])
        for eku in ekus:
            details.append(f"- {eku}")
            
        if template.get('vulnerabilities'):
            details.append("")
            details.append("Vulnerabilities:")
            for vuln in template['vulnerabilities']:
                details.append(f"- {vuln.get('type', {}).name}: {vuln.get('description', '')}")
                
        self.template_details.setText('\n'.join(details))
        
    def _on_vulnerability_selected(self):
        """Handle vulnerability selection"""
        current_row = self.vulns_table.currentRow()
        if current_row < 0:
            return
            
        # Get currently displayed vulnerabilities
        vulns = self._get_displayed_vulnerabilities()
        if current_row < len(vulns):
            vuln = vulns[current_row]
            self._show_vulnerability_details(vuln)
            
    def _get_displayed_vulnerabilities(self) -> list:
        """Get currently displayed vulnerabilities based on filter"""
        filter_text = self.severity_filter.currentText()
        if filter_text == "All":
            return self.all_vulns
        else:
            return [v for v in self.all_vulns if v.get('severity') == filter_text]
            
    def _show_vulnerability_details(self, vuln: dict):
        """Show detailed vulnerability information"""
        details = []
        
        vuln_type = vuln.get('type')
        if hasattr(vuln_type, 'name'):
            details.append(f"Vulnerability: {vuln_type.name}")
        else:
            details.append(f"Vulnerability: {vuln_type}")
            
        details.append(f"Severity: {vuln.get('severity', '')}")
        details.append("")
        
        details.append("Details:")
        details.append(vuln.get('details', ''))
        details.append("")
        
        details.append("Remediation:")
        details.append(vuln.get('remediation', ''))
        
        self.vuln_details.setText('\n'.join(details))
        
    def _filter_vulnerabilities(self, severity: str):
        """Filter vulnerabilities by severity"""
        filtered_vulns = self._get_displayed_vulnerabilities()
        self._display_vulnerabilities(filtered_vulns)
        
    def _check_domain_user_enrollment(self, template: dict) -> bool:
        """Check if domain users can enroll"""
        # This is a simplified check - would need to parse permissions
        return template.get('risk_score', 0) > 50
        
    def _export_results(self, format: str):
        """Export analysis results"""
        if not self.analysis_results:
            QMessageBox.warning(
                self, "No Results",
                "Please run the analysis first."
            )
            return
            
        if format == 'json':
            filename, _ = QFileDialog.getSaveFileName(
                self, "Export Results",
                "adcs_analysis.json",
                "JSON Files (*.json)"
            )
        elif format == 'csv':
            filename, _ = QFileDialog.getSaveFileName(
                self, "Export Results",
                "adcs_vulnerabilities.csv",
                "CSV Files (*.csv)"
            )
        elif format == 'bloodhound':
            filename, _ = QFileDialog.getSaveFileName(
                self, "Export Results",
                "adcs_edges.json",
                "JSON Files (*.json)"
            )
        else:
            return
            
        if filename:
            try:
                analyzer = ADCSAnalyzer(self.ldap_conn)
                exported_data = analyzer.export_findings(
                    self.analysis_results, format
                )
                
                with open(filename, 'w') as f:
                    f.write(exported_data)
                    
                QMessageBox.information(
                    self, "Export Complete",
                    f"Results exported to {filename}"
                )
            except Exception as e:
                QMessageBox.critical(
                    self, "Export Error",
                    f"Failed to export results: {str(e)}"
                )