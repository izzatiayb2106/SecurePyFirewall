import tkinter as tk
from tkinter import ttk

def create_analysis_page(root, show_frame, main_menu_frame):
    analysis_frame = ttk.Frame(root)
    analysis_frame.configure(style="TFrame")

    # Header with modern styling
    header = ttk.Label(
        analysis_frame,
        text="Packet Analysis",
        style="Title.TLabel"
    )
    header.pack(pady=40)

    def analyze_packets():
        display_text.insert(tk.END, "Analyzing packets... (Placeholder for analysis logic)\n")

    # Button container for better organization
    button_frame = ttk.Frame(analysis_frame)
    button_frame.pack(pady=20)

    # Analyze button with modern styling
    analyze_btn = tk.Button(
        button_frame,
        text="Start Analysis",
        command=analyze_packets,
        font=("Inter", 14, "bold"),
        bg="#4A4A4A",
        fg="white",
        padx=30,
        pady=15,
        relief="flat",
        cursor="hand2",
        borderwidth=0,
        activebackground="#2E2E2E",
        activeforeground="white"
    )
    analyze_btn.pack(pady=10)

    # Modern text display area
    display_text = tk.Text(
        analysis_frame,
        wrap="word",
        font=("Inter", 12),
        bg="#FFFFFF",
        fg="#2E2E2E",
        padx=15,
        pady=15,
        relief="flat",
        borderwidth=1
    )
    display_text.pack(fill="both", expand=True, padx=40, pady=20)

    # Back button with modern styling
    back_btn = tk.Button(
        button_frame,
        text="Back",
        command=lambda: show_frame(main_menu_frame),
        font=("Inter", 14, "bold"),
        bg="#4A4A4A",
        fg="white",
        padx=30,
        pady=15,
        relief="flat",
        cursor="hand2",
        borderwidth=0,
        activebackground="#2E2E2E",
        activeforeground="white"
    )
    back_btn.pack(pady=10)

    # Add hover effects to buttons
    for btn in (analyze_btn, back_btn):
        btn.bind("<Enter>", lambda e, btn=btn: btn.configure(bg="#2E2E2E"))
        btn.bind("<Leave>", lambda e, btn=btn: btn.configure(bg="#4A4A4A"))

    return analysis_frame