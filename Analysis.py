import sys
from PyQt6.QtWidgets import (
    QFrame, QLabel, QPushButton, QVBoxLayout, 
    QTextEdit, QWidget, QSpacerItem, QSizePolicy,
    QApplication  # Add this import
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QPalette, QColor

class AnalysisPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.main_window = parent
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(20)
        layout.setContentsMargins(40, 40, 40, 40)

        # Header
        header = QLabel("Packet Analysis")
        header_font = QFont("Inter", 24, QFont.Weight.Bold)
        header.setFont(header_font)
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(header)

        # Text display area
        self.display_text = QTextEdit()
        self.display_text.setFont(QFont("Inter", 12))
        self.display_text.setStyleSheet("""
            QTextEdit {
                background-color: #FFFFFF;
                color: #2E2E2E;
                border: 1px solid #CCCCCC;
                padding: 15px;
                border-radius: 5px;
            }
        """)
        layout.addWidget(self.display_text)

        # Analyze button
        analyze_btn = QPushButton("Start Analysis")
        analyze_btn.setStyleSheet(self.get_button_style())
        analyze_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        analyze_btn.clicked.connect(self.analyze_packets)
        layout.addWidget(analyze_btn)

        # Back button
        back_btn = QPushButton("Back")
        back_btn.setStyleSheet(self.get_button_style())
        back_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        back_btn.clicked.connect(self.go_back)
        layout.addWidget(back_btn)

        # Add spacing
        layout.addSpacerItem(QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding))

    def get_button_style(self):
        return """
            QPushButton {
                background-color: #4A4A4A;
                color: white;
                border: none;
                padding: 15px 30px;
                border-radius: 5px;
                font-family: 'Inter';
                font-size: 14px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #2E2E2E;
            }
            QPushButton:pressed {
                background-color: #1A1A1A;
            }
        """

    def analyze_packets(self):
        self.display_text.append("Analyzing packets... (Placeholder for analysis logic)")

    def go_back(self):
        if self.main_window and hasattr(self.main_window, 'stacked_widget'):
            self.main_window.stacked_widget.setCurrentIndex(0)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setFont(QFont("Inter", 10))
    
    window = AnalysisPage()
    window.setStyleSheet("background-color: #D8C4B6;")
    window.resize(900, 600)
    window.show()
    
    sys.exit(app.exec())