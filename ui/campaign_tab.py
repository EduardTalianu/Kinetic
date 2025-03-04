import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import datetime
import os
import threading
import time
import socket
import ipaddress
import random
import string
import json
import core.server

class CampaignConfigTab:
    def __init__(self, parent, client_manager, logger):
        self.logger = logger
        self.frame = ttk.Frame(parent)
        self.client_manager = client_manager
        self.log_manager = None  # Will be set by the MainGUI after initialization
        self.server_thread = None
        self.create_widgets()

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
        
        # Campaign Actions Buttons (New and Load)
        campaign_buttons_frame = ttk.Frame(self.frame)
        campaign_buttons_frame.grid(row=0, column=2, sticky=tk.W, padx=5, pady=5)
        
        # Generate Random Campaign Name Button
        self.btn_generate_name = ttk.Button(campaign_buttons_frame, text="Generate Name", command=self.generate_random_name)
        self.btn_generate_name.pack(side=tk.LEFT, padx=2)
        
        # Load Campaign Button
        self.btn_load_campaign = ttk.Button(campaign_buttons_frame, text="Load Campaign", command=self.load_campaign)
        self.btn_load_campaign.pack(side=tk.LEFT, padx=2)

        # C&C IP
        ttk.Label(self.frame, text="C&C IP:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.ip_var = tk.StringVar()
        self.ip_combo = ttk.Combobox(self.frame, textvariable=self.ip_var, width=27)
        self.ip_combo.grid(row=1, column=1, padx=5, pady=5)
        self.populate_ip_dropdown()
        self.ip_combo.bind('<KeyRelease>', self.check_ip_entry)
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
    
    def generate_random_name(self):
        """Generate a random campaign name"""
        campaign_name = "Campaign_" + ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
        self.entry_campaign.delete(0, tk.END)
        self.entry_campaign.insert(0, campaign_name)
    
    def load_campaign(self):
        """Load an existing campaign from a folder"""
        # Ask user to select a campaign folder
        campaign_folder = filedialog.askdirectory(title="Select Campaign Folder")
        
        if not campaign_folder:
            return  # User canceled
        
        # Check if this is a valid campaign folder (should end with "_campaign")
        folder_name = os.path.basename(campaign_folder)
        if not folder_name.endswith("_campaign"):
            messagebox.showerror("Invalid Campaign", 
                              "The selected folder does not appear to be a valid campaign folder.\n"
                              "Campaign folders should end with '_campaign'.")
            return
        
        # Get campaign name by removing "_campaign" suffix
        campaign_name = folder_name[:-9]
        
        # Look for config.txt in the campaign folder
        config_path = os.path.join(campaign_folder, "config.txt")
        if not os.path.exists(config_path):
            messagebox.showerror("Invalid Campaign", 
                              f"Could not find configuration file in {campaign_folder}.\n"
                              "Make sure you selected a valid campaign folder.")
            return
        
        # Load configuration from config.txt
        try:
            self.load_campaign_config(config_path, campaign_name)
            
            # Also look for url_paths.json to load custom URL paths
            url_paths_file = os.path.join(campaign_folder, "url_paths.json")
            if os.path.exists(url_paths_file):
                self.load_url_paths(url_paths_file)
                
            messagebox.showinfo("Campaign Loaded", 
                             f"Campaign '{campaign_name}' loaded successfully.\n"
                             "You can now start the campaign to resume operations.")
            
            # Set the log manager campaign folder
            if self.log_manager:
                self.log_manager.set_campaign_folder(campaign_name)
        except Exception as e:
            messagebox.showerror("Load Error", f"Error loading campaign: {e}")
    
    def load_campaign_config(self, config_path, campaign_name):
        """Load campaign configuration from file"""
        with open(config_path, 'r') as f:
            config_lines = f.readlines()
        
        # Parse config.txt to extract settings
        config = {}
        for line in config_lines:
            if ':' in line:
                key, value = line.split(':', 1)
                config[key.strip()] = value.strip()
        
        # Clear existing values
        self.entry_campaign.delete(0, tk.END)
        self.ip_var.set("")
        self.entry_port.delete(0, tk.END)
        self.entry_beacon.delete(0, tk.END)
        self.entry_kill_date.delete(0, tk.END)
        self.entry_cert.delete(0, tk.END)
        self.entry_key.delete(0, tk.END)
        
        # Set values from config
        self.entry_campaign.insert(0, campaign_name)
        
        if "C&C IP" in config:
            self.ip_var.set(config["C&C IP"])
            
        if "Port" in config:
            self.entry_port.insert(0, config["Port"])
            
        if "Beacon Period" in config:
            # Extract just the number from "X sec"
            beacon_period = config["Beacon Period"]
            if " sec" in beacon_period:
                beacon_period = beacon_period.split(" ")[0]
            self.entry_beacon.insert(0, beacon_period)
            
        if "Kill Date" in config:
            self.entry_kill_date.insert(0, config["Kill Date"])
            
        # Set SSL options
        if "Use SSL" in config:
            use_ssl = config["Use SSL"].lower() == "true"
            self.ssl_var.set(use_ssl)
            self.toggle_ssl_options()
            
            if use_ssl:
                if "Certificate Path" in config:
                    self.entry_cert.insert(0, config["Certificate Path"])
                if "Key Path" in config:
                    self.entry_key.insert(0, config["Key Path"])
        
        # Set URL randomization
        if "Custom URLs" in config:
            use_custom_urls = config["Custom URLs"].lower() == "true"
            self.url_random_var.set(use_custom_urls)
        
        # Set pattern based on loaded paths
        if "URL Pattern" in config:
            pattern = config.get("URL Pattern", "web_app")
            if pattern in ["web_app", "api", "cdn", "blog", "custom"]:
                self.url_pattern_var.set(pattern)
                self.url_pattern_combo.set(pattern)
        
        # Set path rotation
        if "Path Rotation Enabled" in config:
            path_rotation = config["Path Rotation Enabled"].lower() == "true"
            self.path_rotation_var.set(path_rotation)
            self.toggle_path_rotation()
            
        if "Rotation Interval" in config:
            # Extract just the number from "X seconds"
            rotation_interval = config["Rotation Interval"]
            if " seconds" in rotation_interval:
                rotation_interval = rotation_interval.split(" ")[0]
            if rotation_interval in ["1800", "3600", "7200", "14400", "28800", "86400"]:
                self.rotation_interval_var.set(rotation_interval)
                self.rotation_interval_combo.set(rotation_interval)
    
    def load_url_paths(self, url_paths_file):
        """Load URL paths from the url_paths.json file"""
        try:
            with open(url_paths_file, 'r') as f:
                url_paths = json.load(f)
            
            # Set each path in the corresponding hidden entry
            if "beacon_path" in url_paths:
                self.entry_beacon_path.delete(0, tk.END)
                self.entry_beacon_path.insert(0, url_paths["beacon_path"])
                
            if "agent_path" in url_paths:
                self.entry_agent_path.delete(0, tk.END)
                self.entry_agent_path.insert(0, url_paths["agent_path"])
                
            if "stager_path" in url_paths:
                self.entry_stager_path.delete(0, tk.END)
                self.entry_stager_path.insert(0, url_paths["stager_path"])
                
            if "cmd_result_path" in url_paths:
                self.entry_cmd_result_path.delete(0, tk.END)
                self.entry_cmd_result_path.insert(0, url_paths["cmd_result_path"])
                
            if "file_upload_path" in url_paths:
                self.entry_file_upload_path.delete(0, tk.END)
                self.entry_file_upload_path.insert(0, url_paths["file_upload_path"])
        except Exception as e:
            self.logger(f"Error loading URL paths: {e}")

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
        ip = self.ip_var.get().strip()
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
        
        # Check if this is an existing campaign being restarted or a new one
        is_existing_campaign = os.path.exists(campaign_dir)
        
        try:
            # Create the campaign directory if it doesn't exist
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
            f"URL Pattern: {self.url_pattern_var.get()}\n"
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

        # Determine message based on whether this is a new or existing campaign
        if is_existing_campaign:
            message = f"Restarting existing campaign '{campaign_name}'."
            self.logger(f"Restarting existing campaign '{campaign_name}' with C&C {ip}:{port}")
        else:
            message = f"Campaign '{campaign_name}' created with C&C {ip}:{port}."
            self.logger(f"New campaign '{campaign_name}' started with C&C {ip}:{port}")

        messagebox.showinfo("Success", f"{message}\nConfig saved to:\n{config_path}")

        # Set up the log manager with the campaign folder
        if hasattr(self, 'log_manager'):
            self.log_manager.set_campaign_folder(campaign_name)

        # Load existing clients for this campaign if it's being restarted
        if is_existing_campaign:
            self.load_existing_clients(campaign_dir)

        # Start the actual webserver in a separate thread using the new module
        try:
            self.server_thread = core.server.start_webserver(
                ip, 
                int(port), 
                self.client_manager, 
                self.logger,
                campaign_name,
                use_ssl=use_ssl,
                cert_path=cert_path if use_ssl else None,
                key_path=key_path if use_ssl else None,
                url_paths=url_paths,
                path_rotation=path_rotation,
                rotation_interval=rotation_interval
            )
            self.btn_start_campaign.config(state=tk.DISABLED)
            self.btn_stop_campaign.config(state=tk.NORMAL)
        except Exception as e:
            self.logger(f"Failed to start webserver: {e}")
            if self.server_thread:
                self.stop_campaign()
    
    def load_existing_clients(self, campaign_dir):
        """Load existing client information from the campaign directory"""
        clients_file = os.path.join(campaign_dir, "clients.json")
        
        if os.path.exists(clients_file):
            try:
                with open(clients_file, 'r') as f:
                    client_data = json.load(f)
                
                # Add clients to client manager
                for client_id, client_info in client_data.items():
                    # Extract basic client properties
                    ip = client_info.get("ip", "Unknown")
                    hostname = client_info.get("hostname", "Unknown")
                    username = client_info.get("username", "Unknown")
                    system_info = client_info.get("system_info", {})
                    
                    # Try to extract machine_guid and os_version from system_info
                    machine_guid = "Unknown"
                    os_version = "Unknown"
                    mac_address = "Unknown"
                    
                    if system_info:
                        machine_guid = system_info.get("MachineGuid", "Unknown")
                        os_version = system_info.get("OsVersion", "Unknown")
                        mac_address = system_info.get("MacAddress", "Unknown")
                    
                    # Add client to the client manager
                    self.client_manager.add_client(
                        ip=ip,
                        hostname=hostname,
                        username=username,
                        machine_guid=machine_guid,
                        os_version=os_version,
                        mac_address=mac_address,
                        system_info=system_info
                    )
                    
                    # Set the verification status if available
                    if "verification_status" in client_info:
                        verification = client_info["verification_status"]
                        self.client_manager.set_verification_status(
                            client_id, 
                            verification.get("verified", False),
                            verification.get("confidence", 0),
                            verification.get("warnings", ["Unknown client"])
                        )
                
                self.logger(f"Loaded {len(client_data)} clients from existing campaign")
            except Exception as e:
                self.logger(f"Error loading existing clients: {e}")
                
        # Check for client key information
        client_keys_file = os.path.join(campaign_dir, "client_keys.json")
        if hasattr(self.client_manager, 'client_keys') and os.path.exists(client_keys_file):
            try:
                with open(client_keys_file, 'r') as f:
                    key_status = json.load(f)
                
                # We can't restore the actual keys, but we can mark which clients had unique keys
                # The C2 handler will re-issue keys to these clients when they reconnect
                self.logger(f"Found key status for {len(key_status)} clients")
                
                # Note: We don't add the actual keys here since they're not saved in the file
                # The system will regenerate keys when verified clients reconnect
            except Exception as e:
                self.logger(f"Error loading client key information: {e}")
    
    def stop_campaign(self):
        if self.server_thread and self.server_thread.is_alive():
            try:
                core.server.stop_webserver()
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