import tkinter as tk
from tkinter import ttk
import subprocess
import platform

def create_access_control_page(root, show_frame, main_menu_frame):
    access_control_frame = ttk.Frame(root)
    access_control_frame.configure(style="TFrame")

    # Header with modern styling
    header = ttk.Label(
        access_control_frame,
        text="Access Control",
        style="Title.TLabel"
    )
    header.pack(pady=40)

    # Input container
    input_frame = ttk.Frame(access_control_frame)
    input_frame.pack(pady=20)

    # IP input
    rule_label = ttk.Label(
        input_frame,
        text="Enter IP:",
        font=("Inter", 14, "bold"),
        background="#D8C4B6",
        foreground="#2E2E2E"
    )
    rule_label.grid(row=0, column=0, sticky="w", padx=10, pady=10)

    ip_entry = ttk.Entry(
        input_frame,
        font=("Inter", 12),
        width=30
    )
    ip_entry.grid(row=0, column=1, padx=10, pady=10)

    # Protocol selection
    protocol_label = ttk.Label(
        input_frame,
        text="Select Protocol:",
        font=("Inter", 14, "bold"),
        background="#D8C4B6",
        foreground="#2E2E2E"
    )
    protocol_label.grid(row=1, column=0, sticky="w", padx=10, pady=10)

    protocol_var = tk.StringVar()
    protocol_combobox = ttk.Combobox(
        input_frame,
        textvariable=protocol_var,
        values=["TCP", "UDP", "ICMP", "All"],
        font=("Inter", 12),
        state="readonly",
        width=28
    )
    protocol_combobox.grid(row=1, column=1, padx=10, pady=10)
    protocol_combobox.set("All")  # Default

    # Port input
    port_label = ttk.Label(
        input_frame,
        text="Enter Port (optional):",
        font=("Inter", 14, "bold"),
        background="#D8C4B6",
        foreground="#2E2E2E"
    )
    port_label.grid(row=2, column=0, sticky="w", padx=10, pady=10)

    port_entry = ttk.Entry(
        input_frame,
        font=("Inter", 12),
        width=30
    )
    port_entry.grid(row=2, column=1, padx=10, pady=10)

    # Text display area
    display_text = tk.Text(
        access_control_frame,
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

    # Function to block IP
    def block_access():
        ip_to_block = ip_entry.get()
        protocol = protocol_var.get()
        port = port_entry.get()

        if not ip_to_block:
            display_text.insert(tk.END, "Error: Please enter a valid IP address.\n")
            return

        if port and not port.isdigit():
            display_text.insert(tk.END, "Error: Port must be a number.\n")
            return

        system_os = platform.system()
        try:
            if system_os == "Linux":
                enforce_iptables(ip_to_block, protocol, port, action="block")
            elif system_os == "Windows":
                enforce_netsh(ip_to_block, protocol, port, action="block")
            else:
                display_text.insert(tk.END, "Unsupported Operating System.\n")
                return
            display_text.insert(tk.END, f"Successfully blocked IP: {ip_to_block}, Protocol: {protocol}, Port: {port or 'All'}\n")
        except Exception as e:
            display_text.insert(tk.END, f"Error: {str(e)}\n")

    # Function to unblock IP
    def unblock_access():
        ip_to_unblock = ip_entry.get()
        protocol = protocol_var.get()
        port = port_entry.get()

        if not ip_to_unblock:
            display_text.insert(tk.END, "Error: Please enter a valid IP address.\n")
            return

        if port and not port.isdigit():
            display_text.insert(tk.END, "Error: Port must be a number.\n")
            return

        system_os = platform.system()
        try:
            if system_os == "Linux":
                enforce_iptables(ip_to_unblock, protocol, port, action="unblock")
            elif system_os == "Windows":
                enforce_netsh(ip_to_unblock, protocol, port, action="unblock")
            else:
                display_text.insert(tk.END, "Unsupported Operating System.\n")
                return
            display_text.insert(tk.END, f"Successfully unblocked IP: {ip_to_unblock}, Protocol: {protocol}, Port: {port or 'All'}\n")
        except Exception as e:
            display_text.insert(tk.END, f"Error: {str(e)}\n")

    # Add system-specific blocking and unblocking logic
    def enforce_iptables(ip, protocol, port, action):
        cmd = ["iptables"]
        if action == "block":
            cmd += ["-A", "INPUT", "-s", ip]
        elif action == "unblock":
            cmd += ["-D", "INPUT", "-s", ip]

        if protocol != "All":
            cmd += ["-p", protocol.lower()]
        if port:
            cmd += ["--dport", port]
        cmd += ["-j", "DROP"]
        subprocess.run(cmd, check=True)

    def enforce_netsh(ip, protocol, port, action):
        if action == "block":
            cmd = ["netsh", "advfirewall", "firewall", "add", "rule",
                   f"name=BlockIP_{ip}", f"dir=in", f"action=block", f"remoteip={ip}"]
        elif action == "unblock":
            cmd = ["netsh", "advfirewall", "firewall", "delete", "rule",
                   f"name=BlockIP_{ip}"]

        if protocol != "All":
            cmd += [f"protocol={protocol.lower()}"]
        if port and action == "block":
            cmd += [f"localport={port}"]
        subprocess.run(cmd, check=True)

    # Button container
    button_frame = ttk.Frame(access_control_frame)
    button_frame.pack(pady=20)

    # Block Access button
    block_btn = tk.Button(
        button_frame,
        text="Block Access",
        command=block_access,
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
    block_btn.pack(pady=10)

    # Unblock Access button
    unblock_btn = tk.Button(
        button_frame,
        text="Unblock Access",
        command=unblock_access,
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
    unblock_btn.pack(pady=10)

    # Back button
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
    for btn in (block_btn, unblock_btn, back_btn):
        btn.bind("<Enter>", lambda e, btn=btn: btn.configure(bg="#2E2E2E"))
        btn.bind("<Leave>", lambda e, btn=btn: btn.configure(bg="#4A4A4A"))

    return access_control_frame