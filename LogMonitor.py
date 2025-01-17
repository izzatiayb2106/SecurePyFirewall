import sys
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QPushButton, QLabel, 
                            QTextEdit, QFrame, QTableWidget, QTableWidgetItem,
                            QHeaderView, QHBoxLayout)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont
from datetime import datetime

class LogMonitorPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.main_window = parent
        self.setup_ui()
        
        # Connect buttons
        self.clear_button.clicked.connect(self.clear_logs)
        self.back_button.clicked.connect(self.go_back)

    def setup_ui(self):
        # Main layout
        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(20)
        main_layout.setContentsMargins(20, 20, 20, 20)
        
        # Title
        title = QLabel("ACL Log Monitor")
        title.setFont(QFont("Inter", 20, QFont.Weight.Bold))
        title.setStyleSheet("color: #2E2E2E; padding: 10px;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(title)

        # Log Table
        self.log_table = QTableWidget()
        self.log_table.setStyleSheet("""
            QTableWidget {
                background-color: white;
                border: 2px solid #4A4A4A;
                border-radius: 5px;
            }
            QHeaderView::section {
                background-color: #4A4A4A;
                color: white;
                padding: 5px;
                border: none;
            }
        """)
        self.log_table.setColumnCount(7)
        self.log_table.setHorizontalHeaderLabels([
            "Timestamp", "Source IP", "Destination IP", 
            "Protocol", "Port", "Action", "Status"
        ])
        
        # Set column widths
        header = self.log_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)  # Timestamp
        for i in range(1, 7):
            header.setSectionResizeMode(i, QHeaderView.ResizeMode.Stretch)
        
        main_layout.addWidget(self.log_table)

        # Statistics Frame
        stats_frame = QFrame()
        stats_frame.setStyleSheet("""
            QFrame {
                background-color: white;
                border: 2px solid #4A4A4A;
                border-radius: 5px;
                padding: 10px;
            }
            QLabel {
                font-family: Inter;
                color: #2E2E2E;
            }
        """)
        
        stats_layout = QHBoxLayout(stats_frame)
        
        # Statistics labels
        self.total_packets_label = QLabel("Total Packets: 0")
        self.allowed_packets_label = QLabel("Allowed: 0")
        self.denied_packets_label = QLabel("Denied: 0")
        
        for label in [self.total_packets_label, self.allowed_packets_label, self.denied_packets_label]:
            label.setFont(QFont("Inter", 12))
            stats_layout.addWidget(label)
            stats_layout.addSpacing(20)
        
        main_layout.addWidget(stats_frame)

        # Buttons
        button_layout = QHBoxLayout()
        button_layout.setSpacing(10)
        
        self.clear_button = QPushButton("Clear Logs")
        self.back_button = QPushButton("Back")
        
        for button in [self.clear_button, self.back_button]:
            button.setStyleSheet(self.get_button_style())
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            button_layout.addWidget(button)
        
        main_layout.addLayout(button_layout)

    def get_button_style(self):
        return """
            QPushButton {
                background-color: #4A4A4A;
                color: white;
                border: none;
                padding: 10px 20px;
                font-family: Inter;
                font-size: 14px;
                font-weight: bold;
                border-radius: 5px;
                min-width: 100px;
            }
            QPushButton:hover {
                background-color: #2E2E2E;
            }
            QPushButton:pressed {
                background-color: #1A1A1A;
            }
        """

    def add_log_entry(self, source_ip, dest_ip, protocol, port, action, status):
        row = self.log_table.rowCount()
        self.log_table.insertRow(row)
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Create table items
        items = [
            QTableWidgetItem(timestamp),
            QTableWidgetItem(source_ip),
            QTableWidgetItem(dest_ip),
            QTableWidgetItem(protocol),
            QTableWidgetItem(str(port)),
            QTableWidgetItem(action),
            QTableWidgetItem(status)
        ]
        
        # Set items in the table
        for col, item in enumerate(items):
            item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)  # Make items read-only
            self.log_table.setItem(row, col, item)
            
            # Color-code the status column
            if col == 6:  # Status column
                if status == "Allowed":
                    item.setBackground(Qt.GlobalColor.green)
                else:
                    item.setBackground(Qt.GlobalColor.red)
        
        # Update statistics
        self.update_statistics()
        
        # Scroll to the latest entry
        self.log_table.scrollToBottom()

    def update_statistics(self):
        total_rows = self.log_table.rowCount()
        allowed_count = sum(1 for row in range(total_rows) 
                          if self.log_table.item(row, 6).text() == "Allowed")
        denied_count = total_rows - allowed_count
        
        self.total_packets_label.setText(f"Total Packets: {total_rows}")
        self.allowed_packets_label.setText(f"Allowed: {allowed_count}")
        self.denied_packets_label.setText(f"Denied: {denied_count}")

    def clear_logs(self):
        self.log_table.setRowCount(0)
        self.update_statistics()

    def go_back(self):
        if self.main_window and hasattr(self.main_window, 'stacked_widget'):
            self.main_window.stacked_widget.setCurrentIndex(0)

# For testing the page independently
if __name__ == "__main__":
    from PyQt6.QtWidgets import QApplication
    import sys
    
    app = QApplication(sys.argv)
    app.setFont(QFont("Inter", 10))
    
    window = LogMonitorPage()
    window.setStyleSheet("background-color: #D8C4B6;")
    window.resize(900, 600)
    
    # Add some sample log entries for testing
    window.add_log_entry("192.168.1.100", "10.0.0.1", "TCP", "80", "ALLOW", "Allowed")
    window.add_log_entry("192.168.1.101", "10.0.0.2", "UDP", "443", "DENY", "Denied")
    
    window.show()
    sys.exit(app.exec())