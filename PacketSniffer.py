import sys
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QPushButton, QLabel, 
                            QTextEdit, QFrame, QApplication, QMainWindow,
                            QHBoxLayout, QComboBox, QLineEdit, QTableWidget, QTableWidgetItem,
                            QHeaderView, QSpinBox)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont
from scapy.all import sniff
from LogMonitor import LogMonitorPage
import threading
from scapy.layers.inet import IP, TCP, UDP, ICMP

class PacketCaptureThread(QThread):
    packet_received = pyqtSignal(str)
    packet_processed = pyqtSignal(dict)  # Add this new signal
    capture_complete = pyqtSignal(int)

    def __init__(self, acl_rules):  # Modified to accept acl_rules
        super().__init__()
        self.running = True
        self.acl_rules = acl_rules

    def run(self):
        try:
            packets = sniff(iface="Wi-Fi", prn=self.process_packet, 
                stop_filter=lambda _: not self.running)
            self.capture_complete.emit(len(packets))
        except Exception as e:
            self.packet_received.emit(f"Error starting capture: {str(e)}\n")

    def stop(self):
        self.running = False

    def check_acl_rules(self, src_ip, dst_ip, protocol, port):
        for rule in self.acl_rules:
            # Skip rule if IP doesn't match (unless rule IP is empty or matches)
            if rule['ip'] and rule['ip'] not in [src_ip, dst_ip]:
                continue
            
            # Skip rule if port doesn't match (unless rule port is 0 or matches)
            if rule['port'] != 0 and rule['port'] != port:
                continue
            
            # Skip rule if protocol doesn't match (unless rule protocol is 'Any' or matches)
            if rule['protocol'] != 'Any' and rule['protocol'] != protocol:
                continue
            
            # If we get here, rule matches - return the action
            return rule['action']
        
        # If no rules match, default to Allow
        return "Allow"

    def process_packet(self, packet):
        try:
            # Extract packet information
            src_ip = packet[IP].src if IP in packet else "N/A"
            dst_ip = packet[IP].dst if IP in packet else "N/A"
            
            # Determine protocol and port
            if TCP in packet:
                protocol = "TCP"
                port = packet[TCP].dport
            elif UDP in packet:
                protocol = "UDP"
                port = packet[UDP].dport
            elif ICMP in packet:
                protocol = "ICMP"
                port = 0
            else:
                protocol = "Other"
                port = 0
            
            # Basic packet info for display
            packet_info = f"Source: {src_ip}, Destination: {dst_ip}, Protocol: {protocol}, Port: {port}\n"
            self.packet_received.emit(packet_info)
            
            # Check packet against ACL rules
            action = self.check_acl_rules(src_ip, dst_ip, protocol, port)
            status = "Allowed" if action == "Allow" else "Denied"
            
            # Emit packet processing result
            packet_data = {
                'source_ip': src_ip,
                'dest_ip': dst_ip,
                'protocol': protocol,
                'port': port,
                'action': action,
                'status': status
            }
            self.packet_processed.emit(packet_data)
            
        except Exception as e:
            self.packet_received.emit(f"Error processing packet: {str(e)}\n")

class SnifferPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.main_window = parent
        self.capture_thread = None
        self.acl_rules = []  # Initialize ACL rules list
        self.is_capturing = False  # Add this line to initialize the flag
        self.setup_ui()
        
        # Connect buttons
        self.start_button.clicked.connect(self.toggle_capture)
        self.back_button.clicked.connect(self.go_back)

    def setup_ui(self):
        # Main layout with spacing
        main_layout = QHBoxLayout(self)
        main_layout.setSpacing(20)  # Add spacing between left and right sections
        main_layout.setContentsMargins(20, 20, 20, 20)  # Add margins around the entire layout
        
        # Left side - Packet Sniffer (40% width)
        left_layout = QVBoxLayout()
        left_layout.setSpacing(10)
        
        # Packet Sniffer Title
        title = QLabel("Packet Sniffer")
        title.setFont(QFont("Inter", 20, QFont.Weight.Bold))
        title.setStyleSheet("color: #2E2E2E; padding: 10px;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        left_layout.addWidget(title)

        # Text display area with reduced height
        self.display_text = QTextEdit()
        self.display_text.setStyleSheet("""
            QTextEdit {
                background-color: white;
                border: 2px solid #4A4A4A;
                border-radius: 5px;
                padding: 10px;
                font-family: Inter;
                font-size: 12px;
                color: #2E2E2E;
            }
        """)
        self.display_text.setReadOnly(True)
        self.display_text.setMinimumHeight(300)  # Set minimum height
        left_layout.addWidget(self.display_text)

        # Sniffer Buttons
        button_layout = QHBoxLayout()
        button_layout.setSpacing(10)
        self.start_button = QPushButton("Start Capture")
        self.back_button = QPushButton("Back")
        self.view_logs_button = QPushButton("View Logs")
        
        for button in [self.start_button, self.back_button, self.view_logs_button]:
            button.setStyleSheet(self.get_button_style())
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            button_layout.addWidget(button)        
        # Add button layout to left_layout
        left_layout.addLayout(button_layout)  # Add this line to fix the missing buttons
        
        # Connect the view logs button
        self.view_logs_button.clicked.connect(self.show_log_monitor)
        
        # Right side - Access Control (60% width)
        right_layout = QVBoxLayout()
        right_layout.setSpacing(10)
        
        # ACL Title with styling
        acl_title = QLabel("Access Control Rules")
        acl_title.setFont(QFont("Inter", 20, QFont.Weight.Bold))
        acl_title.setStyleSheet("color: #2E2E2E; padding: 10px;")
        acl_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        right_layout.addWidget(acl_title)

        # ACL Form in a styled frame
        form_frame = QFrame()
        form_frame.setStyleSheet("""
            QFrame {
                background-color: white;
                border: 2px solid #4A4A4A;
                border-radius: 5px;
                padding: 10px;
            }
            QLabel {
                font-weight: bold;
                min-width: 80px;
            }
        """)
        form_layout = QVBoxLayout(form_frame)
        form_layout.setSpacing(10)
        
        # Form fields with better spacing
        fields = [
            ("IP Address:", self.create_ip_input()),
            ("Port:", self.create_port_input()),
            ("Protocol:", self.create_protocol_combo()),
            ("Action:", self.create_action_combo())
        ]
        
        for label_text, widget in fields:
            field_layout = QHBoxLayout()
            label = QLabel(label_text)
            field_layout.addWidget(label)
            field_layout.addWidget(widget)
            form_layout.addLayout(field_layout)

        # Add Rule Button
        self.add_rule_button = QPushButton("Add Rule")
        self.add_rule_button.setStyleSheet(self.get_button_style())
        self.add_rule_button.clicked.connect(self.add_rule)
        form_layout.addWidget(self.add_rule_button)
        
        right_layout.addWidget(form_frame)

        # Rules Table with styling
        self.rules_table = QTableWidget()
        self.rules_table.setStyleSheet("""
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
        self.rules_table.setColumnCount(5)
        self.rules_table.setHorizontalHeaderLabels(["IP", "Port", "Protocol", "Action", ""])
        self.rules_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        right_layout.addWidget(self.rules_table)

        # Add layouts to main layout with proper proportions
        main_layout.addLayout(left_layout, 40)  # 40% width
        main_layout.addLayout(right_layout, 60)  # 60% width

    def create_ip_input(self):
        self.ip_input = QLineEdit()  # Store as instance variable
        self.ip_input.setPlaceholderText("e.g., 192.168.1.1")
        self.ip_input.setStyleSheet("padding: 5px;")
        return self.ip_input

    def create_port_input(self):
        self.port_input = QSpinBox()  # Store as instance variable
        self.port_input.setRange(1, 65535)
        self.port_input.setStyleSheet("padding: 5px;")
        return self.port_input

    def create_protocol_combo(self):
        self.protocol_combo = QComboBox()  # Store as instance variable
        self.protocol_combo.addItems(["TCP", "UDP", "ICMP", "Any"])
        self.protocol_combo.setStyleSheet("padding: 5px;")
        return self.protocol_combo

    def create_action_combo(self):
        self.action_combo = QComboBox()  # Store as instance variable
        self.action_combo.addItems(["Allow", "Deny"])
        self.action_combo.setStyleSheet("padding: 5px;")
        return self.action_combo

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
            QPushButton:disabled {
                background-color: #888888;
            }
        """

    def add_rule(self):
        # Get values from form
        ip = self.ip_input.text()
        port = self.port_input.value()
        protocol = self.protocol_combo.currentText()
        action = self.action_combo.currentText()
        
        # Add to rules table and list
        row = self.rules_table.rowCount()
        self.rules_table.insertRow(row)
        
        self.rules_table.setItem(row, 0, QTableWidgetItem(ip))
        self.rules_table.setItem(row, 1, QTableWidgetItem(str(port)))
        self.rules_table.setItem(row, 2, QTableWidgetItem(protocol))
        self.rules_table.setItem(row, 3, QTableWidgetItem(action))
        
        delete_button = QPushButton("Delete")
        delete_button.setStyleSheet(self.get_button_style())
        delete_button.clicked.connect(lambda: self.delete_rule(row))
        self.rules_table.setCellWidget(row, 4, delete_button)
        
        # Add to ACL rules list
        self.acl_rules.append({
            'ip': ip,
            'port': port,
            'protocol': protocol,
            'action': action
        })
        
        # If capture is running, update the thread's rules
        if self.capture_thread and self.capture_thread.isRunning():
            self.capture_thread.acl_rules = self.acl_rules.copy()

    def delete_rule(self, row):
        self.rules_table.removeRow(row)
        self.acl_rules.pop(row)

    def toggle_capture(self):
        if not self.is_capturing:
            self.start_capture()
        else:
            self.stop_capture()

    def start_capture(self):
        self.display_text.append("\nStarting packet capture...\n")
        self.start_button.setText("Stop Capture")
        self.is_capturing = True
        
        # Create capture thread with current ACL rules
        self.capture_thread = PacketCaptureThread(self.acl_rules)
        self.capture_thread.packet_received.connect(self.update_display)
        self.capture_thread.packet_processed.connect(self.log_packet)
        self.capture_thread.capture_complete.connect(self.capture_finished)
        self.capture_thread.start()

    def log_packet(self, packet_data):
        # Get reference to log monitor page
        log_monitor = self.main_window.findChild(LogMonitorPage)
        if log_monitor:
            log_monitor.add_log_entry(
                packet_data['source_ip'],
                packet_data['dest_ip'],
                packet_data['protocol'],
                str(packet_data['port']),
                packet_data['action'],
                packet_data['status']
            )

    def show_log_monitor(self):
        if self.main_window and hasattr(self.main_window, 'stacked_widget'):
            # Find the log monitor page index
            for i in range(self.main_window.stacked_widget.count()):
                if isinstance(self.main_window.stacked_widget.widget(i), LogMonitorPage):
                    self.main_window.stacked_widget.setCurrentIndex(i)
                    break

    def stop_capture(self):
        if self.capture_thread and self.capture_thread.isRunning():
            self.capture_thread.stop()
            self.capture_thread.wait()
            self.is_capturing = False
            self.start_button.setText("Start Capture")
            self.display_text.append("\nCapture stopped by user.\n")

    def update_display(self, packet_info):
        self.display_text.append(packet_info)
        # Scroll to the bottom
        scrollbar = self.display_text.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def capture_finished(self, packet_count):
        self.display_text.append(f"\nCapture completed. Total packets captured: {packet_count}\n")
        self.start_button.setText("Start Capture")
        self.is_capturing = False

    def go_back(self):
        # First stop any ongoing capture
        if self.is_capturing:
            self.stop_capture()
        
        # Then navigate back
        if self.main_window and hasattr(self.main_window, 'stacked_widget'):
            self.main_window.stacked_widget.setCurrentIndex(0)

# For testing the page independently
if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setFont(QFont("Inter", 10))
    
    window = SnifferPage()
    window.setStyleSheet("background-color: #D8C4B6;")
    window.resize(900, 600)
    window.show()
    
    sys.exit(app.exec())