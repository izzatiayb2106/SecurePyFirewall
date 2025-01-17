import sys
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QPushButton, QLabel, QStackedWidget)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from PacketSniffer import SnifferPage  # Import the SnifferPage class
from LogMonitor import LogMonitorPage  # Import the LogMonitorPage class
from Analysis import AnalysisPage # Import the AnalysisPage class

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SecurePy Firewall")
        self.setMinimumSize(900, 600)
        
        # Set the background color
        self.setStyleSheet("background-color: #D8C4B6;")
        
        # Create stacked widget to handle different pages
        self.stacked_widget = QStackedWidget()
        self.setCentralWidget(self.stacked_widget)
        
        # Create pages
        self.main_menu = self.create_main_menu()
        self.sniffer_page = SnifferPage(self)  # Pass self as parent
        self.access_control_page = LogMonitorPage(self) #pass self as parent 
        self.analysis_page = AnalysisPage(self) #pass self as parent
        
        # Add pages to stacked widget
        self.stacked_widget.addWidget(self.main_menu)
        self.stacked_widget.addWidget(self.sniffer_page)
        self.stacked_widget.addWidget(self.access_control_page)
        self.stacked_widget.addWidget(self.analysis_page)

    def create_main_menu(self):
        page = QWidget()
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # Title
        title = QLabel("SecurePy Firewall")
        title.setFont(QFont("Inter", 32, QFont.Weight.Bold))
        title.setStyleSheet("color: #2E2E2E;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        
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
                min-width: 200px;
            }
            QPushButton:hover {
                background-color: #2E2E2E;
            }
            QPushButton:pressed {
                background-color: #1A1A1A;
            }
        """
        
        # Buttons
        buttons = [
            ("Packet Analysis", lambda: self.stacked_widget.setCurrentIndex(1)),
            ("Log Monitoring", lambda: self.stacked_widget.setCurrentIndex(2)),
            ("Analysis", lambda: self.stacked_widget.setCurrentIndex(3)),
            ("Exit", self.close)
        ]
        
        for text, callback in buttons:
            button = QPushButton(text)
            button.setStyleSheet(button_style)
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            button.clicked.connect(callback)
            layout.addWidget(button)
            layout.addSpacing(15)
        
        page.setLayout(layout)
        return page

    def create_access_control_page(self):
        page = QWidget()
        layout = QVBoxLayout()
        
        title = QLabel("Access Control")
        title.setFont(QFont("Inter", 24, QFont.Weight.Bold))
        title.setStyleSheet("color: #2E2E2E;")
        layout.addWidget(title)
        
        back_button = QPushButton("Back to Main Menu")
        back_button.setStyleSheet("""
            QPushButton {
                background-color: #4A4A4A;
                color: white;
                border: none;
                padding: 10px 20px;
                font-family: Inter;
                font-weight: bold;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #2E2E2E;
            }
        """)
        back_button.clicked.connect(lambda: self.stacked_widget.setCurrentIndex(0))
        layout.addWidget(back_button)
        
        page.setLayout(layout)
        return page

    def create_analysis_page(self):
        page = QWidget()
        layout = QVBoxLayout()
        
        title = QLabel("Analysis")
        title.setFont(QFont("Inter", 24, QFont.Weight.Bold))
        title.setStyleSheet("color: #2E2E2E;")
        layout.addWidget(title)
        
        back_button = QPushButton("Back to Main Menu")
        back_button.setStyleSheet("""
            QPushButton {
                background-color: #4A4A4A;
                color: white;
                border: none;
                padding: 10px 20px;
                font-family: Inter;
                font-weight: bold;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #2E2E2E;
            }
        """)
        back_button.clicked.connect(lambda: self.stacked_widget.setCurrentIndex(0))
        layout.addWidget(back_button)
        
        page.setLayout(layout)
        return page

def main():
    app = QApplication(sys.argv)
    app.setFont(QFont("Inter", 10))
    
    window = MainWindow()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()