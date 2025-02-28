import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import datetime
import os
import threading
import time
import socket  # Import the socket module
import ipaddress
import core.webserver  # Import the webserver module

class CampaignConfigTab:
    def __init__(self, parent, client_manager, logger):  # Add client_manager
        self.logger = logger
        self.frame = ttk.Frame(parent)
        self.client_manager = client_manager # Store the client_manager
        self.create_widgets()

    def create_widgets(self):
        # Campaign Name
        ttk.Label(self.frame, text="Campaign Name:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.entry_campaign = ttk.Entry(self.frame, width=30)
        self.entry_campaign.grid(row=0, column=1, padx=5, pady=5)

        # C&C IP
        ttk.Label(self.frame, text="C&C IP:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.ip_var = tk.StringVar()
        self.ip_combo = ttk.Combobox(self.frame, textvariable=self.ip_var, width=27)
        self.ip_combo.grid(row=1, column=1, padx=5, pady=5)
        self.populate_ip_dropdown()  # Populate the dropdown on startup
        self.ip_combo.bind('<KeyRelease>', self.check_ip_entry)  # Bind key release event
        self.ip_combo.bind('<FocusOut>', self.check_ip_entry)
        self.ip_combo['state'] = 'normal'

        # Port
        ttk.Label(self.frame, text="Port:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        self.entry_port = ttk.Entry(self.frame, width=30)
        self.entry_port.grid(row=2, column=1, padx=5, pady=5)

        # Beacon Period
        ttk.Label(self.frame, text="Beacon Period (sec):").grid(row=3, column=0, sticky=tk.W, padx=5, pady=5)
        self.entry_beacon = ttk.Entry(self.frame, width=30)
        self.entry_beacon.grid(row=3, column=1, padx=5, pady=5)

        # Kill Date
        ttk.Label(self.frame, text="Kill Date (dd/mm/yyyy):").grid(row=4, column=0, sticky=tk.W, padx=5, pady=5)
        self.entry_kill_date = ttk.Entry(self.frame, width=30)
        self.entry_kill_date.grid(row=4, column=1, padx=5, pady=5)

        # SSL Option
        self.ssl_var = tk.BooleanVar()
        self.ssl_check = ttk.Checkbutton(self.frame, text="Use SSL", variable=self.ssl_var, command=self.toggle_ssl_options)
        self.ssl_check.grid(row=5, column=0, sticky=tk.W, padx=5, pady=5)

        # Certificate Path
        ttk.Label(self.frame, text="Certificate Path:").grid(row=6, column=0, sticky=tk.W, padx=5, pady=5)
        self.entry_cert = ttk.Entry(self.frame, width=30, state='disabled')
        self.entry_cert.grid(row=6, column=1, padx=5, pady=5)
        self.btn_browse_cert = ttk.Button(self.frame, text="Browse", command=self.browse_cert, state='disabled')
        self.btn_browse_cert.grid(row=6, column=2, padx=5, pady=5)

        # Key Path
        ttk.Label(self.frame, text="Key Path:").grid(row=7, column=0, sticky=tk.W, padx=5, pady=5)
        self.entry_key = ttk.Entry(self.frame, width=30, state='disabled')
        self.entry_key.grid(row=7, column=1, padx=5, pady=5)
        self.btn_browse_key = ttk.Button(self.frame, text="Browse", command=self.browse_key, state='disabled')
        self.btn_browse_key.grid(row=7, column=2, padx=5, pady=5)

        # Start Campaign Button
        self.btn_start_campaign = ttk.Button(self.frame, text="Start Campaign", command=self.start_campaign)
        self.btn_start_campaign.grid(row=8, column=0, columnspan=3, pady=10)

    def check_ip_entry(self, event):
        """Checks if the entered IP is valid or should be added to the dropdown."""
        current_value = self.ip_var.get()
        
        try:
            ipaddress.ip_address(current_value)
            if current_value not in self.ip_combo['values']:
                self.ip_combo['values'] = list(self.ip_combo['values']) + [current_value]
        except ValueError:
            pass  # Handle as non-IP, allowing partial entry.

    def populate_ip_dropdown(self):
        """Populates the IP dropdown with host machine IPs."""
        host_ips = self.get_host_ips()
        self.ip_combo['values'] = host_ips

        # Optionally, set the first IP as the default
        if host_ips:
            self.ip_var.set(host_ips[0])

    def get_host_ips(self):
        """Gets the host machine's IP addresses."""
        host_name = socket.gethostname()
        try:
            host_ips = socket.gethostbyname_ex(host_name)[2]
        except socket.gaierror:
            host_ips = []
        return host_ips

    def toggle_ssl_options(self):
        state = 'normal' if self.ssl_var.get() else 'disabled'
        self.entry_cert.config(state=state)
        self.entry_key.config(state=state)
        self.btn_browse_cert.config(state=state)
        self.btn_browse_key.config(state=state)

    def browse_cert(self):
        filepath = filedialog.askopenfilename(title="Select Certificate File")
        if filepath:
            self.entry_cert.delete(0, tk.END)
            self.entry_cert.insert(0, filepath)

    def browse_key(self):
        filepath = filedialog.askopenfilename(title="Select Key File")
        if filepath:
            self.entry_key.delete(0, tk.END)
            self.entry_key.insert(0, filepath)

    def start_campaign(self):
        campaign_name = self.entry_campaign.get().strip()
        ip = self.ip_var.get().strip()  # Get IP from dropdown or entry
        port = self.entry_port.get().strip()
        beacon = self.entry_beacon.get().strip()
        kill_date_str = self.entry_kill_date.get().strip()
        use_ssl = self.ssl_var.get()
        cert_path = self.entry_cert.get().strip() if use_ssl else ""
        key_path = self.entry_key.get().strip() if use_ssl else ""

        if not campaign_name or not ip or not port or not beacon or not kill_date_str:
            messagebox.showerror("Error", "Please fill in all required fields.")
            return

        try:
            datetime.datetime.strptime(kill_date_str, "%d/%m/%Y")
        except ValueError:
            messagebox.showerror("Error", "Kill Date must be in dd/mm/yyyy format.")
            return
        
        #validate IP
        try:
          ipaddress.ip_address(ip)
        except ValueError:
          messagebox.showerror("Error", "C&C IP is not valid.")
          return

        campaign_dir = campaign_name + "_campaign"
        try:
            os.makedirs(campaign_dir, exist_ok=True)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create campaign directory: {e}")
            return

        config_content = (
            f"Campaign Name: {campaign_name}\n"
            f"C&C IP: {ip}\n"
            f"Port: {port}\n"
            f"Beacon Period: {beacon} sec\n"
            f"Kill Date: {kill_date_str}\n"
            f"Use SSL: {use_ssl}\n"
            f"Certificate Path: {cert_path}\n"
            f"Key Path: {key_path}\n"
        )
        config_path = os.path.join(campaign_dir, "config.txt")
        try:
            with open(config_path, "w") as f:
                f.write(config_content)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to write config file: {e}")
            return

        messagebox.showinfo("Success", f"Campaign started!\nConfig saved to:\n{config_path}")
        self.logger(f"Campaign '{campaign_name}' started with C&C {ip}:{port}")

        # Start the actual webserver in a separate thread using the new module
        try:
            core.webserver.start_webserver(ip, port, self.client_manager, self.logger) # pass the client_manager
        except Exception as e:
            self.logger(f"Failed to start webserver: {e}")


    def start_dummy_webserver(self, ip, port):
        self.logger("Starting dummy webserver...")
        for i in range(5):
            time.sleep(1)
            self.logger(f"Webserver running on {ip}:{port}... ({i+1})")
        self.logger("Dummy webserver stopped.")

    # Methods for other modules to access campaign settings
    def get_ip(self):
        return self.ip_var.get().strip()

    def get_port(self):
        return self.entry_port.get().strip()

    def get_ssl(self):
        return self.ssl_var.get()
