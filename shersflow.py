import tkinter as tk
from tkinter import ttk
from scapy.all import *
import paramiko

class PenetrationTestingTool(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("ShersFlow")
        self.geometry("800x600")

        self.container = ttk.Frame(self)
        self.container.pack(side="top", fill="both", expand=True)

        self.frames = {}
        for F in (StartPage, DeauthPage, MD5CrackPage, SSHBruteForcePage, NetworkScanPage, VulnerabilityScanPage):
            page_name = F.__name__
            frame = F(parent=self.container, controller=self)
            self.frames[page_name] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        self.show_frame("StartPage")

    def show_frame(self, page_name):
        frame = self.frames[page_name]
        frame.tkraise()

class StartPage(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        label = ttk.Label(self, text="Penetration Testing Tool", font=("Helvetica", 18))
        label.pack(side="top", fill="x", pady=10)

        buttons = [
            ("Deauthentication Attack", "DeauthPage"),
            ("MD5 Cracking", "MD5CrackPage"),
            ("SSH Brute Force", "SSHBruteForcePage"),
            ("Network Scanning", "NetworkScanPage"),
            ("Vulnerability Scanning", "VulnerabilityScanPage")
        ]

        for text, page in buttons:
            button = ttk.Button(self, text=text, command=lambda page=page: controller.show_frame(page))
            button.pack(fill="x", pady=5)

class DeauthPage(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        label = ttk.Label(self, text="Deauthentication Attack", font=("Helvetica", 18))
        label.pack(side="top", fill="x", pady=10)
        
        interface_label = ttk.Label(self, text="Interface:")
        interface_label.pack()
        self.interface_entry = ttk.Entry(self)
        self.interface_entry.pack()
        target_label = ttk.Label(self, text="Target MAC:")
        target_label.pack()
        self.target_entry = ttk.Entry(self)
        self.target_entry.pack()
        deauth_button = ttk.Button(self, text="Start Deauth Attack", command=self.start_deauth_attack)
        deauth_button.pack(pady=5)
        
        self.output_text = tk.Text(self, height=15, state='disabled')
        self.output_text.pack(fill="both", expand=True)

    def start_deauth_attack(self):
        interface = self.interface_entry.get()
        target_mac = self.target_entry.get()
        # Placeholder function for deauth attack
        self.log_output(f"Deauth attack started on interface {interface} targeting {target_mac}")

    def log_output(self, message):
        self.output_text.config(state='normal')
        self.output_text.insert(tk.END, message + "\n")
        self.output_text.config(state='disabled')

class MD5CrackPage(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        label = ttk.Label(self, text="MD5 Cracking", font=("Helvetica", 18))
        label.pack(side="top", fill="x", pady=10)
        
        hash_label = ttk.Label(self, text="MD5 Hash:")
        hash_label.pack()
        self.hash_entry = ttk.Entry(self)
        self.hash_entry.pack()
        wordlist_label = ttk.Label(self, text="Wordlist File:")
        wordlist_label.pack()
        self.wordlist_entry = ttk.Entry(self)
        self.wordlist_entry.pack()
        crack_button = ttk.Button(self, text="Crack MD5", command=self.crack_md5)
        crack_button.pack(pady=5)
        
        self.output_text = tk.Text(self, height=15, state='disabled')
        self.output_text.pack(fill="both", expand=True)

    def crack_md5(self):
        md5_hash = self.hash_entry.get()
        wordlist = self.wordlist_entry.get()
        # Placeholder function for MD5 cracking
        self.log_output(f"MD5 cracking started for hash {md5_hash} using wordlist {wordlist}")

    def log_output(self, message):
        self.output_text.config(state='normal')
        self.output_text.insert(tk.END, message + "\n")
        self.output_text.config(state='disabled')

class SSHBruteForcePage(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        label = ttk.Label(self, text="SSH Brute Force", font=("Helvetica", 18))
        label.pack(side="top", fill="x", pady=10)
        
        target_label = ttk.Label(self, text="Target IP:")
        target_label.pack()
        self.target_entry = ttk.Entry(self)
        self.target_entry.pack()
        username_label = ttk.Label(self, text="Username:")
        username_label.pack()
        self.username_entry = ttk.Entry(self)
        self.username_entry.pack()
        password_label = ttk.Label(self, text="Password File:")
        password_label.pack()
        self.password_entry = ttk.Entry(self)
        self.password_entry.pack()
        brute_button = ttk.Button(self, text="Start Brute Force", command=self.start_brute_force)
        brute_button.pack(pady=5)
        
        self.output_text = tk.Text(self, height=15, state='disabled')
        self.output_text.pack(fill="both", expand=True)

    def start_brute_force(self):
        target_ip = self.target_entry.get()
        username = self.username_entry.get()
        password_file = self.password_entry.get()
        # Placeholder function for SSH brute force
        self.log_output(f"SSH brute force started on {target_ip} with username {username} using password file {password_file}")

    def log_output(self, message):
        self.output_text.config(state='normal')
        self.output_text.insert(tk.END, message + "\n")
        self.output_text.config(state='disabled')

class NetworkScanPage(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        label = ttk.Label(self, text="Network Scanning", font=("Helvetica", 18))
        label.pack(side="top", fill="x", pady=10)
        
        target_label = ttk.Label(self, text="Target Network:")
        target_label.pack()
        self.target_entry = ttk.Entry(self)
        self.target_entry.pack()
        scan_button = ttk.Button(self, text="Start Network Scan", command=self.start_network_scan)
        scan_button.pack(pady=5)
        
        self.output_text = tk.Text(self, height=15, state='disabled')
        self.output_text.pack(fill="both", expand=True)

    def start_network_scan(self):
        target_network = self.target_entry.get()
        # Placeholder function for network scan
        self.log_output(f"Network scan started on {target_network}")

    def log_output(self, message):
        self.output_text.config(state='normal')
        self.output_text.insert(tk.END, message + "\n")
        self.output_text.config(state='disabled')

class VulnerabilityScanPage(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        label = ttk.Label(self, text="Vulnerability Scanning", font=("Helvetica", 18))
        label.pack(side="top", fill="x", pady=10)
        
        target_label = ttk.Label(self, text="Target IP:")
        target_label.pack()
        self.target_entry = ttk.Entry(self)
        self.target_entry.pack()
        vuln_button = ttk.Button(self, text="Start Vulnerability Scan", command=self.start_vuln_scan)
        vuln_button.pack(pady=5)
        
        self.output_text = tk.Text(self, height=15, state='disabled')
        self.output_text.pack(fill="both", expand=True)

    def start_vuln_scan(self):
        target_ip = self.target_entry.get()
        # Placeholder function for vulnerability scan
        self.log_output(f"Vulnerability scan started on {target_ip}")

    def log_output(self, message):
        self.output_text.config(state='normal')
        self.output_text.insert(tk.END, message + "\n")
        self.output_text.config(state='disabled')

def set_style():
    style = ttk.Style()
    style.theme_use('clam')  # You can use 'clam', 'alt', 'default', or any other ttk theme
    style.configure('TButton', font=('Helvetica', 12), padding=10)
    style.configure('TLabel', font=('Helvetica', 14))

if __name__ == "__main__":
    set_style()
    app = PenetrationTestingTool()
    app.mainloop()
