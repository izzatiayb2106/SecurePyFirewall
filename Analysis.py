import sys
from PyQt6.QtWidgets import (
    QFrame, QLabel, QPushButton, QVBoxLayout, QHBoxLayout,
    QWidget, QSpacerItem, QSizePolicy, QApplication, QGridLayout
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QPalette, QColor
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import numpy as np
from LogMonitor import LogMonitorPage

class CustomCard(QFrame):
    def __init__(self, title, parent=None):
        super().__init__(parent)
        self.setObjectName("customCard")
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(20, 20, 20, 20)
        self.layout.setSpacing(15)
        
        # Card Title
        self.title = QLabel(title)
        self.title.setObjectName("cardTitle")
        self.title.setFont(QFont("Segoe UI", 14, QFont.Weight.DemiBold))
        self.layout.addWidget(self.title)

class AnalysisPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.main_window = parent
        self.setup_ui()
        self.apply_styles()

    def setup_ui(self):
        # Main Layout
        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(25)
        main_layout.setContentsMargins(30, 30, 30, 30)

        # Header
        header = QLabel("Network Traffic Analysis")
        header.setObjectName("pageHeader")
        header.setFont(QFont("Segoe UI", 28, QFont.Weight.Bold))
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(header)

        # Grid Layout for Cards
        grid_layout = QGridLayout()
        grid_layout.setSpacing(20)

        # Protocol Distribution Card
        protocol_card = CustomCard("Protocol Distribution")
        self.protocol_fig = Figure(figsize=(6, 4), dpi=100, facecolor='#FFFFFF')
        self.protocol_canvas = FigureCanvas(self.protocol_fig)
        self.protocol_ax = self.protocol_fig.add_subplot(111)
        protocol_card.layout.addWidget(self.protocol_canvas)
        grid_layout.addWidget(protocol_card, 0, 0)

        # Port Distribution Card
        port_card = CustomCard("Port Distribution")
        self.port_fig = Figure(figsize=(6, 4), dpi=100, facecolor='#FFFFFF')
        self.port_canvas = FigureCanvas(self.port_fig)
        self.port_ax = self.port_fig.add_subplot(111)
        port_card.layout.addWidget(self.port_canvas)
        grid_layout.addWidget(port_card, 0, 1)

        # Status Card
        status_card = CustomCard("Analysis Results")
        
        # Anomaly Status
        self.anomaly_label = QLabel("No Anomalies Detected")
        self.anomaly_label.setObjectName("statusLabel")
        self.anomaly_label.setFont(QFont("Segoe UI", 12))
        status_card.layout.addWidget(self.anomaly_label)

        # Statistics Grid
        stats_grid = QGridLayout()
        stats_grid.setSpacing(15)

        # Allowed Packets
        allowed_label = QLabel("Allowed Packets")
        allowed_label.setObjectName("statsLabel")
        self.allowed_count = QLabel("0")
        self.allowed_count.setObjectName("statsValue")
        stats_grid.addWidget(allowed_label, 0, 0)
        stats_grid.addWidget(self.allowed_count, 1, 0)

        # Denied Packets
        denied_label = QLabel("Denied Packets")
        denied_label.setObjectName("statsLabel")
        self.denied_count = QLabel("0")
        self.denied_count.setObjectName("statsValue")
        stats_grid.addWidget(denied_label, 0, 1)
        stats_grid.addWidget(self.denied_count, 1, 1)

        status_card.layout.addLayout(stats_grid)
        grid_layout.addWidget(status_card, 0, 2)

        main_layout.addLayout(grid_layout)

        # Buttons Container
        button_container = QHBoxLayout()
        button_container.setSpacing(15)

        # Analyze Button
        analyze_btn = QPushButton("Start Analysis")
        analyze_btn.setObjectName("primaryButton")
        analyze_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        analyze_btn.clicked.connect(self.analyze_packets)
        button_container.addWidget(analyze_btn)

        # Back Button
        back_btn = QPushButton("Back to Main Menu")
        back_btn.setObjectName("secondaryButton")
        back_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        back_btn.clicked.connect(self.go_back)
        button_container.addWidget(back_btn)

        main_layout.addLayout(button_container)

    def apply_styles(self):
        self.setStyleSheet("""
            QWidget {
                background-color: #D8C4B6;
                color: #333333;
            }
            
            #pageHeader {
                color: #333333;
                margin-bottom: 20px;
            }
            
            #customCard {
                background-color: white;
                border-radius: 10px;
                border: 1px solid #B4A69C;
            }
            
            #cardTitle {
                color: #333333;
                padding-bottom: 10px;
            }
            
            #statusLabel {
                font-size: 14px;
            }
            
            #statsLabel {
                color: #666666;
                font-size: 12px;
            }
            
            #statsValue {
                color: #333333;
                font-size: 24px;
                font-weight: bold;
            }
            
            #primaryButton, #secondaryButton {
                background-color: #4A4A4A;
                color: white;
                border: none;
                padding: 12px 30px;
                border-radius: 5px;
                font-size: 14px;
                font-weight: bold;
            }
            
            #primaryButton:hover, #secondaryButton:hover {
                background-color: #2E2E2E;
            }
            
            #primaryButton:pressed, #secondaryButton:pressed {
                background-color: #1A1A1A;
            }
        """)

    def update_protocol_chart(self, log_entries):
        protocols = [entry['protocol'] for entry in log_entries]
        protocol_counts = {}
        for protocol in protocols:
            protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1

        labels = protocol_counts.keys()
        sizes = protocol_counts.values()
        colors = ['#B4A69C', '#A18072', '#8B6B5D', '#755C4B', '#5F4D3E']

        self.protocol_ax.clear()
        patches, texts, autotexts = self.protocol_ax.pie(
            sizes, 
            labels=labels, 
            autopct='%1.1f%%', 
            startangle=90,
            colors=colors,
            textprops={'color': '#333333'}
        )
        self.protocol_fig.tight_layout()
        self.protocol_canvas.draw()

    def update_port_distribution(self, log_entries):
        ports = [int(entry['port']) for entry in log_entries]
        port_counts = {}
        for port in ports:
            port_counts[port] = port_counts.get(port, 0) + 1

        self.port_ax.clear()
        bars = self.port_ax.bar(
            range(len(port_counts)), 
            port_counts.values(),
            color='#B4A69C'
        )
        self.port_ax.set_xticks(range(len(port_counts)))
        self.port_ax.set_xticklabels(port_counts.keys(), rotation=45)
        self.port_ax.set_xlabel('Port Number')
        self.port_ax.set_ylabel('Number of Packets')
        
        # Add value labels on top of bars
        for bar in bars:
            height = bar.get_height()
            self.port_ax.text(
                bar.get_x() + bar.get_width()/2.,
                height,
                f'{int(height)}',
                ha='center',
                va='bottom',
                color='#333333'
            )
            
        self.port_fig.tight_layout()
        self.port_canvas.draw()

    def analyze_packets(self):
        if self.main_window and hasattr(self.main_window, 'stacked_widget'):
            log_monitor_page = self.main_window.findChild(LogMonitorPage)
            if log_monitor_page:
                log_entries = []
                for row in range(log_monitor_page.log_table.rowCount()):
                    log_entry = {
                        'source_ip': log_monitor_page.log_table.item(row, 1).text(),
                        'dest_ip': log_monitor_page.log_table.item(row, 2).text(),
                        'protocol': log_monitor_page.log_table.item(row, 3).text(),
                        'port': log_monitor_page.log_table.item(row, 4).text(),
                        'action': log_monitor_page.log_table.item(row, 5).text(),
                        'status': log_monitor_page.log_table.item(row, 6).text()
                    }
                    log_entries.append(log_entry)
                self.update_dashboard(log_entries)

    def update_dashboard(self, log_entries):
        self.update_protocol_chart(log_entries)
        self.update_port_distribution(log_entries)
        self.detect_anomalies(log_entries)
        self.update_statistics(log_entries)

    def detect_anomalies(self, log_entries):
        denied_sources = {}
        for entry in log_entries:
            if entry['status'] == "Denied":
                source_ip = entry['source_ip']
                denied_sources[source_ip] = denied_sources.get(source_ip, 0) + 1

        anomalous_ip = None
        max_denied = 0
        for ip, count in denied_sources.items():
            if count > max_denied:
                max_denied = count
                anomalous_ip = ip

        if anomalous_ip:
            self.anomaly_label.setText(
                f"⚠️ Anomaly Detected: High denied packets from {anomalous_ip} ({max_denied} denied)")
            self.anomaly_label.setStyleSheet("color: #E74C3C;")
        else:
            self.anomaly_label.setText("✓ No Anomalies Detected")
            self.anomaly_label.setStyleSheet("color: #27AE60;")

    def update_statistics(self, log_entries):
        allowed_count = sum(1 for entry in log_entries if entry['status'] == "Allowed")
        denied_count = sum(1 for entry in log_entries if entry['status'] == "Denied")
        
        self.allowed_count.setText(str(allowed_count))
        self.denied_count.setText(str(denied_count))
        
        # Update colors based on values
        self.allowed_count.setStyleSheet("color: #27AE60;")
        self.denied_count.setStyleSheet("color: #E74C3C;")

    def go_back(self):
        if self.main_window and hasattr(self.main_window, 'stacked_widget'):
            self.main_window.stacked_widget.setCurrentIndex(0)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setFont(QFont("Segoe UI", 10))
    
    window = AnalysisPage()
    window.resize(1200, 800)
    window.show()
    
    sys.exit(app.exec())