import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import datetime
import os
import threading
import time
import socket  # Import the socket module
import ipaddress
import core.webserver  # Import the webserver module
import random
import string
import json

class CampaignConfigTab:
    def __init__(self, parent, client_manager, logger):  # Add client_manager
        self.logger = logger
        self.frame = ttk.Frame(parent)
        self.client_manager = client_manager # Store the client_manager
        self.create_widgets()
        self.server_thread = None  # Initialize server_thread to None

    def create_widgets(self):
        # First, initialize all required variables before using them
        self.ssl_var = tk.BooleanVar()
        self.url_random_var = tk.BooleanVar(value=True)
        self.url_pattern_var = tk.StringVar(value="web_app")
        self.path_rotation_var = tk.BooleanVar(value=True)
        self.rotation_interval_var = tk.StringVar(value="3600")
        
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

        # URL Randomization Section - Keep checkbox but remove display of paths
        url_frame = ttk.LabelFrame(self.frame, text="URL Path Customization")
        url_frame.grid(row=5, column=0, columnspan=3, sticky="ew", padx=5, pady=5)

        # Checkbox for URL Randomization
        self.url_random_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(url_frame, text="Randomize URLs to evade detection", 
                        variable=self.url_random_var).grid(row=0, column=0, columnspan=2, sticky="w", padx=5, pady=2)

        # URL pattern selection
        ttk.Label(url_frame, text="URL Pattern:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.url_pattern_var = tk.StringVar(value="web_app")
        self.url_pattern_combo = ttk.Combobox(url_frame, textvariable=self.url_pattern_var, width=27, 
                                        values=["web_app", "api", "cdn", "blog", "custom"])
        self.url_pattern_combo.grid(row=1, column=1, padx=5, pady=5)
        self.url_pattern_combo.bind("<<ComboboxSelected>>", self.on_pattern_selected)



        # Create hidden entries for URL paths
        self.entry_beacon_path = ttk.Entry(self.frame)
        self.entry_agent_path = ttk.Entry(self.frame)
        self.entry_stager_path = ttk.Entry(self.frame)
        self.entry_cmd_result_path = ttk.Entry(self.frame)
        self.entry_file_upload_path = ttk.Entry(self.frame)

        # Generate random button
        ttk.Button(url_frame, text="Generate Random URLs", 
                command=self.generate_random_urls).grid(row=2, column=0, columnspan=2, pady=5)

        # Path Rotation Section - Keep checkbox and interval but remove text area
        rotation_frame = ttk.LabelFrame(self.frame, text="Dynamic Path Rotation")
        rotation_frame.grid(row=6, column=0, columnspan=3, sticky="ew", padx=5, pady=5)
        
        # Enable path rotation checkbox
        self.path_rotation_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(rotation_frame, text="Enable dynamic path rotation to evade detection", 
                    variable=self.path_rotation_var, 
                    command=self.toggle_path_rotation).grid(row=0, column=0, columnspan=2, sticky="w", padx=5, pady=2)
        
        # Rotation interval
        ttk.Label(rotation_frame, text="Rotation Interval (seconds):").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        rotation_values = ["1800", "3600", "7200", "14400", "28800", "86400"]
        self.rotation_interval_var = tk.StringVar(value="3600")
        self.rotation_interval_combo = ttk.Combobox(rotation_frame, textvariable=self.rotation_interval_var, 
                                                values=rotation_values, width=27)
        self.rotation_interval_combo.grid(row=1, column=1, padx=5, pady=5)
        ttk.Label(rotation_frame, text="Rotation intervals: 30 min, 1 hour, 2 hours, 4 hours, 8 hours, 24 hours").grid(
            row=2, column=0, columnspan=2, sticky="w", padx=5, pady=0)

        # SSL Option
        self.ssl_var = tk.BooleanVar()
        self.ssl_check = ttk.Checkbutton(self.frame, text="Use SSL", variable=self.ssl_var, command=self.toggle_ssl_options)
        self.ssl_check.grid(row=7, column=0, sticky=tk.W, padx=5, pady=5)

        # Certificate Path
        ttk.Label(self.frame, text="Certificate Path:").grid(row=8, column=0, sticky=tk.W, padx=5, pady=5)
        self.entry_cert = ttk.Entry(self.frame, width=30, state='disabled')
        self.entry_cert.grid(row=8, column=1, padx=5, pady=5)
        self.btn_browse_cert = ttk.Button(self.frame, text="Browse", command=self.browse_cert, state='disabled')
        self.btn_browse_cert.grid(row=8, column=2, padx=5, pady=5)

        # Key Path
        ttk.Label(self.frame, text="Key Path:").grid(row=9, column=0, sticky=tk.W, padx=5, pady=5)
        self.entry_key = ttk.Entry(self.frame, width=30, state='disabled')
        self.entry_key.grid(row=9, column=1, padx=5, pady=5)
        self.btn_browse_key = ttk.Button(self.frame, text="Browse", command=self.browse_key, state='disabled')
        self.btn_browse_key.grid(row=9, column=2, padx=5, pady=5)

        # Start Campaign Button
        self.btn_start_campaign = ttk.Button(self.frame, text="Start Campaign", command=self.start_campaign)
        self.btn_start_campaign.grid(row=10, column=0, columnspan=3, pady=10)

        # Stop Campaign Button
        self.btn_stop_campaign = ttk.Button(self.frame, text="Stop Campaign", command=self.stop_campaign, state=tk.DISABLED)
        self.btn_stop_campaign.grid(row=11, column=0, columnspan=3, pady=10)
        
        # Generate random URLs in the background
        self.generate_random_urls()

    def on_pattern_selected(self, event):
        """Handle pattern selection change event and generate new URLs"""
        self.generate_random_urls()

    def toggle_path_rotation(self):
        """Toggle path rotation options based on checkbox"""
        state = 'normal' if self.path_rotation_var.get() else 'disabled'
        self.rotation_interval_combo.config(state=state)

    def generate_random_urls(self):
        """Generate random, legitimate-looking URLs based on the selected pattern"""
        pattern = self.url_pattern_var.get()
        
        # Helper function to generate random strings
        def random_string(length=6, include_numbers=True):
            chars = string.ascii_lowercase
            if include_numbers:
                chars += string.digits
            return ''.join(random.choice(chars) for _ in range(length))
        
        # Different URL patterns based on selection
        if pattern == "web_app":
            self.entry_beacon_path.delete(0, tk.END)
            self.entry_beacon_path.insert(0, f"/app/{random_string(5)}/status")
            
            self.entry_agent_path.delete(0, tk.END)
            self.entry_agent_path.insert(0, f"/app/{random_string(5)}/resources/main.js")
            
            self.entry_stager_path.delete(0, tk.END)
            self.entry_stager_path.insert(0, f"/app/{random_string(4)}/assets/loader.js")
            
            self.entry_cmd_result_path.delete(0, tk.END)
            self.entry_cmd_result_path.insert(0, f"/app/{random_string(6)}/feedback")
            
            self.entry_file_upload_path.delete(0, tk.END)
            self.entry_file_upload_path.insert(0, f"/app/{random_string(5)}/upload")
            
        elif pattern == "api":
            self.entry_beacon_path.delete(0, tk.END)
            self.entry_beacon_path.insert(0, f"/api/v{random.randint(1,3)}/{random_string(4)}/check")
            
            self.entry_agent_path.delete(0, tk.END)
            self.entry_agent_path.insert(0, f"/api/v{random.randint(1,3)}/client/script")
            
            self.entry_stager_path.delete(0, tk.END)
            self.entry_stager_path.insert(0, f"/api/v{random.randint(1,3)}/init")
            
            self.entry_cmd_result_path.delete(0, tk.END)
            self.entry_cmd_result_path.insert(0, f"/api/v{random.randint(1,3)}/response")
            
            self.entry_file_upload_path.delete(0, tk.END)
            self.entry_file_upload_path.insert(0, f"/api/v{random.randint(1,3)}/storage")
            
        elif pattern == "cdn":
            self.entry_beacon_path.delete(0, tk.END)
            self.entry_beacon_path.insert(0, f"/cdn/ping/{random_string(8)}")
            
            self.entry_agent_path.delete(0, tk.END)
            self.entry_agent_path.insert(0, f"/cdn/js/{random_string(6)}.min.js")
            
            self.entry_stager_path.delete(0, tk.END)
            self.entry_stager_path.insert(0, f"/cdn/lib/{random_string(5)}.js")
            
            self.entry_cmd_result_path.delete(0, tk.END)
            self.entry_cmd_result_path.insert(0, f"/cdn/analytics/{random_string(7)}")
            
            self.entry_file_upload_path.delete(0, tk.END)
            self.entry_file_upload_path.insert(0, f"/cdn/storage/{random_string(8)}")
            
        elif pattern == "blog":
            self.entry_beacon_path.delete(0, tk.END)
            self.entry_beacon_path.insert(0, f"/blog/comments/{random_string(6)}")
            
            self.entry_agent_path.delete(0, tk.END)
            self.entry_agent_path.insert(0, f"/blog/wp-content/themes/{random_string(5)}/script.js")
            
            self.entry_stager_path.delete(0, tk.END)
            self.entry_stager_path.insert(0, f"/blog/wp-includes/js/{random_string(4)}.js")
            
            self.entry_cmd_result_path.delete(0, tk.END)
            self.entry_cmd_result_path.insert(0, f"/blog/trackback/{random_string(8)}")
            
            self.entry_file_upload_path.delete(0, tk.END)
            self.entry_file_upload_path.insert(0, f"/blog/wp-content/uploads/{random_string(5)}")
        
        # Update the preview
        self.update_url_preview()
        

    def update_url_preview(self, event=None):
        """This function is kept for compatibility but doesn't update a preview anymore"""
        # Get path values and ensure they start with /
        beacon_path = self.entry_beacon_path.get()
        if not beacon_path.startswith('/'):
            self.entry_beacon_path.delete(0, tk.END)
            self.entry_beacon_path.insert(0, '/' + beacon_path)
                
        agent_path = self.entry_agent_path.get()
        if not agent_path.startswith('/'):
            self.entry_agent_path.delete(0, tk.END) 
            self.entry_agent_path.insert(0, '/' + agent_path)
                
        stager_path = self.entry_stager_path.get()
        if not stager_path.startswith('/'):
            self.entry_stager_path.delete(0, tk.END)
            self.entry_stager_path.insert(0, '/' + stager_path)
                
        cmd_result_path = self.entry_cmd_result_path.get()
        if not cmd_result_path.startswith('/'):
            self.entry_cmd_result_path.delete(0, tk.END)
            self.entry_cmd_result_path.insert(0, '/' + cmd_result_path)
            
        file_upload_path = self.entry_file_upload_path.get()
        if not file_upload_path.startswith('/'):
            self.entry_file_upload_path.delete(0, tk.END)
            self.entry_file_upload_path.insert(0, '/' + file_upload_path)

    def toggle_url_entries(self):
        """Toggle URL entry fields based on randomization checkbox"""
        state = 'normal' if self.url_random_var.get() else 'disabled'
        self.url_pattern_combo.config(state=state)
        self.entry_beacon_path.config(state=state)
        self.entry_agent_path.config(state=state)
        self.entry_stager_path.config(state=state)
        self.entry_cmd_result_path.config(state=state)
        self.entry_file_upload_path.config(state=state)

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
        
        # Update URL preview with new protocol
        self.update_url_preview()

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
        
        # Get custom URL paths
        use_custom_urls = self.url_random_var.get()
        beacon_path = self.entry_beacon_path.get().strip() if use_custom_urls else "/beacon"
        agent_path = self.entry_agent_path.get().strip() if use_custom_urls else "/raw_agent" 
        stager_path = self.entry_stager_path.get().strip() if use_custom_urls else "/b64_stager"
        cmd_result_path = self.entry_cmd_result_path.get().strip() if use_custom_urls else "/command_result"
        file_upload_path = self.entry_file_upload_path.get().strip() if use_custom_urls else "/file_upload"
        
        # Get path rotation settings
        path_rotation = self.path_rotation_var.get()
        rotation_interval = int(self.rotation_interval_var.get())

        if not campaign_name or not ip or not port or not beacon or not kill_date_str:
            messagebox.showerror("Error", "Please fill in all required fields.")
            return

        try:
            datetime.datetime.strptime(kill_date_str, "%d/%m/%Y")
        except ValueError:
            messagebox.showerror("Error", "Kill Date must be in dd/mm/yyyy format.")
            return
        
        # validate IP
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            messagebox.showerror("Error", "C&C IP is not valid.")
            return
        
        # Validate SSL settings if SSL is selected
        if use_ssl:
            if not cert_path or not key_path:
                messagebox.showerror("Error", "Certificate and Key paths are required when SSL is enabled.")
                return
            if not os.path.exists(cert_path):
                messagebox.showerror("Error", f"Certificate file not found: {cert_path}")
                return
            if not os.path.exists(key_path):
                messagebox.showerror("Error", f"Key file not found: {key_path}")
                return

        campaign_dir = campaign_name + "_campaign"
        try:
            os.makedirs(campaign_dir, exist_ok=True)
            # Create uploads directory for file uploads
            uploads_dir = os.path.join(campaign_dir, "uploads")
            os.makedirs(uploads_dir, exist_ok=True)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create campaign directory: {e}")
            return

        # Save URL paths configuration
        url_paths = {
            "beacon_path": beacon_path,
            "agent_path": agent_path,
            "stager_path": stager_path,
            "cmd_result_path": cmd_result_path,
            "file_upload_path": file_upload_path
        }
        
        url_paths_file = os.path.join(campaign_dir, "url_paths.json")
        try:
            with open(url_paths_file, "w") as f:
                json.dump(url_paths, f, indent=4)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to write URL paths file: {e}")
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
            f"Custom URLs: {use_custom_urls}\n"
            f"Beacon Path: {beacon_path}\n"
            f"Agent Path: {agent_path}\n"
            f"Stager Path: {stager_path}\n"
            f"Command Result Path: {cmd_result_path}\n"
            f"File Upload Path: {file_upload_path}\n"
            f"Path Rotation Enabled: {path_rotation}\n"
            f"Rotation Interval: {rotation_interval} seconds\n"
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
            self.server_thread = core.webserver.start_webserver(
                ip, 
                int(port), 
                self.client_manager, 
                self.logger,
                campaign_name,  # Pass campaign name to the webserver
                use_ssl=use_ssl,
                cert_path=cert_path if use_ssl else None,
                key_path=key_path if use_ssl else None,
                url_paths=url_paths,  # Pass the URL paths to the webserver
                path_rotation=path_rotation,  # Pass path rotation flag
                rotation_interval=rotation_interval  # Pass rotation interval
            )
            self.btn_start_campaign.config(state=tk.DISABLED)
            self.btn_stop_campaign.config(state=tk.NORMAL)
        except Exception as e:
            self.logger(f"Failed to start webserver: {e}")
            if self.server_thread:
                self.stop_campaign()

    def stop_campaign(self):
        if self.server_thread and self.server_thread.is_alive():
            try:
                core.webserver.stop_webserver()
                self.server_thread.join()  # Wait for the server thread to finish
            except Exception as e:
                self.logger(f"Failed to stop webserver properly: {e}")
        self.server_thread = None
        self.btn_start_campaign.config(state=tk.NORMAL)
        self.btn_stop_campaign.config(state=tk.DISABLED)
        self.logger(f"Campaign stopped.")
        messagebox.showinfo("Success", f"Campaign stopped.")
    
    # Methods for other modules to access campaign settings
    def get_ip(self):
        return self.ip_var.get().strip()

    def get_port(self):
        return self.entry_port.get().strip()

    def get_ssl(self):
        return self.ssl_var.get()