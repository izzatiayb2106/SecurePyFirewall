import sys
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QPushButton, QLabel, 
                            QTextEdit, QFrame, QApplication)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont
from scapy.all import sniff
import threading

class PacketCaptureThread(QThread):
    packet_received = pyqtSignal(str)
    capture_complete = pyqtSignal(int)

    def run(self):
        try:
            packets = sniff(iface="Wi-Fi", prn=self.process_packet, timeout=10)
            self.capture_complete.emit(len(packets))
        except Exception as e:
            self.packet_received.emit(f"Error starting capture: {str(e)}\n")

    def process_packet(self, packet):
        try:
            src = packet.src if hasattr(packet, "src") else "N/A"
            dst = packet.dst if hasattr(packet, "dst") else "N/A"
            proto = packet.proto if hasattr(packet, "proto") else "N/A"
            
            packet_info = f"Source: {src}, Destination: {dst}, Protocol: {proto}\n"
            self.packet_received.emit(packet_info)
        except Exception as e:
            self.packet_received.emit(f"Error processing packet: {str(e)}\n")

class SnifferPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.capture_thread = None

    def setup_ui(self):
        # Main layout
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        
        # Title
        title = QLabel("Packet Sniffer")
        title.setFont(QFont("Inter", 32, QFont.Weight.Bold))
        title.setStyleSheet("color: #2E2E2E; margin: 20px 0;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)

        # Text display area
        self.display_text = QTextEdit()
        self.display_text.setStyleSheet("""
            QTextEdit {
                background-color: white;
                border: 1px solid #CCCCCC;
                border-radius: 5px;
                padding: 15px;
                font-family: Inter;
                font-size: 12px;
                color: #2E2E2E;
            }
        """)
        self.display_text.setReadOnly(True)
        layout.addWidget(self.display_text)

        # Button style
        button_style = """
            QPushButton {
                background-color: #4A4A4A;
                color: white;
                border: none;
                padding: 15px 30px;
                font-family: Inter;
                font-size: 14px;
                font-weight: bold;
                border-radius: 5px;
                min-width: 150px;
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

        # Buttons
        self.start_button = QPushButton("Start Capture")
        self.start_button.setStyleSheet(button_style)
        self.start_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.start_button.clicked.connect(self.start_capture)
        layout.addWidget(self.start_button)

        self.back_button = QPushButton("Back")
        self.back_button.setStyleSheet(button_style)
        self.back_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.back_button.clicked.connect(self.go_back)
        layout.addWidget(self.back_button)

        # Add spacing between buttons
        layout.addSpacing(20)

    def start_capture(self):
        self.display_text.append("\nStarting packet capture...\n")
        self.start_button.setEnabled(False)
        
        # Create and start the capture thread
        self.capture_thread = PacketCaptureThread()
        self.capture_thread.packet_received.connect(self.update_display)
        self.capture_thread.capture_complete.connect(self.capture_finished)
        self.capture_thread.start()

    def update_display(self, packet_info):
        self.display_text.append(packet_info)
        # Scroll to the bottom
        scrollbar = self.display_text.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def capture_finished(self, packet_count):
        self.display_text.append(f"\nCapture completed. Total packets captured: {packet_count}\n")
        self.start_button.setEnabled(True)

    def go_back(self):
        # This should be connected to your main window's navigation system
        if hasattr(self.parent(), 'stacked_widget'):
            self.parent().stacked_widget.setCurrentIndex(0)

# For testing the page independently
if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setFont(QFont("Inter", 10))
    
    window = SnifferPage()
    window.setStyleSheet("background-color: #D8C4B6;")
    window.resize(900, 600)
    window.show()
    
    sys.exit(app.exec())